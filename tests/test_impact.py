"""Tests for POST /policies/{name}/impact (policy change impact preview)."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.redaction import compile_rule, diff_audits, redact

client = TestClient(app)


def _create_policy(name: str, rules) -> dict:
    resp = client.put(f"/policies/{name}", json={"rules": rules})
    assert resp.status_code == 201, resp.text
    return resp.json()


# --------------------------------------------------------------------------- #
# Pure diff_audits behaviour
# --------------------------------------------------------------------------- #


def _run(sample, rules, salt=""):
    compiled = [compile_rule(i, r["pointer"], r["action"]) for i, r in enumerate(rules)]
    _, audit = redact(sample, compiled, salt=salt)
    return audit


def test_diff_added_removed_changed_basic():
    sample = {"users": [{"email": "a@x", "password": "p"}], "ssn": "1"}
    current = _run(sample, [{"pointer": "/users/*/email", "action": "mask"}])
    candidate = _run(
        sample,
        [
            {"pointer": "/users/*/email", "action": "mask"},
            {"pointer": "/users/*/password", "action": "remove"},
            {"pointer": "/**/ssn", "action": "sha256"},
        ],
    )
    diff = diff_audits(current, candidate)

    assert {e["pointer"] for e in diff["added"]} == {
        "/users/0/password",
        "/ssn",
    }
    assert diff["removed"] == []
    assert diff["changed"] == []


def test_diff_same_action_different_rule_index_is_not_a_change():
    sample = {"k": "v"}
    current = _run(sample, [{"pointer": "/k", "action": "mask"}])
    # Same effective action; only the winning declaration index differs.
    candidate = _run(
        sample,
        [
            {"pointer": "/other", "action": "remove"},
            {"pointer": "/k", "action": "mask"},
        ],
    )
    diff = diff_audits(current, candidate)
    assert diff == {"added": [], "removed": [], "changed": []}


def test_diff_parent_subtree_short_circuit_shows_one_action():
    # Current policy removes the whole /card subtree, so only /card is audited
    # (its descendants are short-circuited). Switching to leaf-level masking
    # must surface exactly one removed parent action plus added leaves -- never
    # phantom descendant removals.
    sample = {"card": {"number": "x", "cvv": "y"}, "ok": 1}
    current = _run(sample, [{"pointer": "/card", "action": "remove"}])
    candidate = _run(
        sample,
        [
            {"pointer": "/card/number", "action": "mask"},
            {"pointer": "/card/cvv", "action": "mask"},
        ],
    )
    diff = diff_audits(current, candidate)
    assert [e["pointer"] for e in diff["removed"]] == ["/card"]
    assert {e["pointer"] for e in diff["added"]} == {"/card/number", "/card/cvv"}
    assert diff["changed"] == []


def test_diff_parent_mask_then_remove_is_a_change_not_descendant_noise():
    sample = {"card": {"number": "x", "cvv": "y"}}
    current = _run(sample, [{"pointer": "/card", "action": "mask"}])
    candidate = _run(sample, [{"pointer": "/card", "action": "remove"}])
    diff = diff_audits(current, candidate)
    assert len(diff["changed"]) == 1
    change = diff["changed"][0]
    assert change["pointer"] == "/card"
    assert change["before"]["action"] == "mask"
    assert change["after"]["action"] == "remove"
    assert diff["added"] == [] and diff["removed"] == []


def test_diff_array_deletion_keeps_original_indices_stable():
    # Both rule sets remove original index 0; candidate additionally masks the
    # surviving ORIGINAL elements. Pointers /items/1 and /items/2 must compare
    # by their original positions even though index 0 disappears from output.
    sample = {"items": [{"v": "a"}, {"v": "b"}, {"v": "c"}]}
    current = _run(sample, [{"pointer": "/items/0", "action": "remove"}])
    candidate = _run(
        sample,
        [
            {"pointer": "/items/0", "action": "remove"},
            {"pointer": "/items/*/v", "action": "mask"},
        ],
    )
    diff = diff_audits(current, candidate)
    assert {e["pointer"] for e in diff["added"]} == {"/items/1/v", "/items/2/v"}
    # /items/0 is a removal action in both runs -> not reported.
    assert diff["removed"] == []
    assert diff["changed"] == []


def test_diff_root_rule_change():
    sample = {"a": 1}
    current = _run(sample, [{"pointer": "", "action": "mask"}])
    candidate = _run(sample, [{"pointer": "", "action": "sha256"}])
    diff = diff_audits(current, candidate)
    assert diff["changed"][0]["pointer"] == ""
    assert diff["changed"][0]["after"]["action"] == "sha256"


# --------------------------------------------------------------------------- #
# Endpoint
# --------------------------------------------------------------------------- #


def test_impact_endpoint_full_flow():
    snapshot = _create_policy(
        "pii", [{"pointer": "/users/*/email", "action": "mask"}]
    )

    resp = client.post(
        "/policies/pii/impact",
        json={
            "rules": [
                {"pointer": "/users/*/email", "action": "mask"},
                {"pointer": "/users/*/password", "action": "remove"},
                {"pointer": "/users/*/email", "action": "sha256", "name": "h"},
            ],
            "samples": [
                {"users": [{"email": "a@x", "password": "p"}]},
                {"users": [], "other": 1},
            ],
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # Baseline is the atomic read of the currently committed version.
    assert body["baseline"] == {
        "name": "pii",
        "version": 1,
        "etag": snapshot["etag"],
    }

    s0, s1 = body["samples"]
    assert s0["index"] == 0
    assert [e["pointer"] for e in s0["added"]] == ["/users/0/password"]
    assert s0["added"][0]["action"] == "remove"
    # email flips mask -> sha256
    assert len(s0["changed"]) == 1
    change = s0["changed"][0]
    assert change["pointer"] == "/users/0/email"
    assert change["before"]["action"] == "mask"
    assert change["after"]["action"] == "sha256"
    assert change["after"]["rule"]["name"] == "h"
    assert s0["removed"] == []

    # Second sample matches nothing under either rule set.
    assert s1 == {"index": 1, "added": [], "removed": [], "changed": []}

    assert body["summary"] == {
        "samples": 2,
        "added": 1,
        "removed": 0,
        "changed": 1,
    }


def test_impact_does_not_create_a_version():
    _create_policy("pii", [{"pointer": "/a", "action": "mask"}])
    resp = client.post(
        "/policies/pii/impact",
        json={
            "rules": [{"pointer": "/a", "action": "remove"}],
            "samples": [{"a": 1}],
        },
    )
    assert resp.status_code == 200
    # The stored policy is untouched: still version 1 with the original body.
    current = client.get("/policies/pii").json()
    assert current["version"] == 1
    assert current["rules"] == [{"pointer": "/a", "action": "mask"}]
    assert client.get("/policies/pii/versions/2").status_code == 404


def test_impact_against_latest_after_update_reports_new_baseline():
    snapshot = _create_policy("pii", [{"pointer": "/a", "action": "mask"}])
    client.put(
        "/policies/pii",
        json={"rules": [{"pointer": "/a", "action": "remove"}]},
        headers={"If-Match": snapshot["etag"]},
    )
    resp = client.post(
        "/policies/pii/impact",
        json={"rules": [], "samples": [{"a": 1}]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["baseline"]["version"] == 2
    # Candidate removes every rule -> the current remove becomes "removed".
    assert body["samples"][0]["removed"][0] == {
        "pointer": "/a",
        "action": "remove",
        "rule": {"index": 0, "pointer": "/a", "action": "remove"},
    }


def test_impact_empty_candidate_rules_is_valid():
    _create_policy("pii", [{"pointer": "/a", "action": "mask"}])
    resp = client.post(
        "/policies/pii/impact",
        json={"rules": [], "samples": [{"a": 1}, {"b": 2}]},
    )
    assert resp.status_code == 200
    body = resp.json()
    # /a only acts on the first sample; the second is untouched by both runs.
    assert body["summary"] == {"samples": 2, "added": 0, "removed": 1, "changed": 0}
    assert body["samples"][0]["removed"][0]["pointer"] == "/a"
    assert body["samples"][1] == {"index": 1, "added": [], "removed": [], "changed": []}


def test_impact_policy_not_found_is_404():
    resp = client.post(
        "/policies/ghost/impact",
        json={"rules": [], "samples": [{"a": 1}]},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["name"] == "ghost"


def test_impact_too_many_samples_is_422():
    _create_policy("pii", [{"pointer": "/a", "action": "mask"}])
    resp = client.post(
        "/policies/pii/impact",
        json={"rules": [], "samples": [{} for _ in range(21)]},
    )
    assert resp.status_code == 422


def test_impact_zero_samples_is_422():
    _create_policy("pii", [{"pointer": "/a", "action": "mask"}])
    resp = client.post(
        "/policies/pii/impact", json={"rules": [], "samples": []}
    )
    assert resp.status_code == 422


def test_impact_missing_samples_or_rules_is_422():
    _create_policy("pii", [{"pointer": "/a", "action": "mask"}])
    assert client.post(
        "/policies/pii/impact", json={"rules": []}
    ).status_code == 422
    assert client.post(
        "/policies/pii/impact", json={"samples": [{}]}
    ).status_code == 422


def test_impact_invalid_candidate_rules_is_422():
    _create_policy("pii", [{"pointer": "/a", "action": "mask"}])
    # Bad pointer syntax.
    resp = client.post(
        "/policies/pii/impact",
        json={"rules": [{"pointer": "no-slash", "action": "mask"}], "samples": [{}]},
    )
    assert resp.status_code == 422
    # Unknown action.
    resp = client.post(
        "/policies/pii/impact",
        json={"rules": [{"pointer": "/a", "action": "explode"}], "samples": [{}]},
    )
    assert resp.status_code == 422


def test_impact_accepts_scalar_samples():
    _create_policy("pii", [{"pointer": "", "action": "mask"}])
    resp = client.post(
        "/policies/pii/impact",
        json={"rules": [], "samples": [42, "hi", None, [1, 2]]},
    )
    assert resp.status_code == 200
    body = resp.json()
    # Root mask acts on every sample; dropping all rules removes each action.
    assert body["summary"]["removed"] == 4
    assert {s["index"] for s in body["samples"]} == {0, 1, 2, 3}


def test_impact_extra_field_is_422():
    _create_policy("pii", [])
    resp = client.post(
        "/policies/pii/impact",
        json={"rules": [], "samples": [{}], "bogus": 1},
    )
    assert resp.status_code == 422


def test_impact_subtree_short_circuit_end_to_end():
    _create_policy(
        "pii",
        [
            {"pointer": "/card/number", "action": "mask"},
            {"pointer": "/card/cvv", "action": "mask"},
        ],
    )
    resp = client.post(
        "/policies/pii/impact",
        json={"rules": [{"pointer": "/card", "action": "remove"}], "samples": [
            {"card": {"number": "x", "cvv": "y"}}
        ]},
    )
    assert resp.status_code == 200
    s0 = resp.json()["samples"][0]
    assert {e["pointer"] for e in s0["removed"]} == {"/card/number", "/card/cvv"}
    assert [e["pointer"] for e in s0["added"]] == ["/card"]
    assert s0["changed"] == []
