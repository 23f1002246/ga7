"""Tests the /release-gate policy endpoint (run by the TDS GA7 Release Gate workflow)."""
import copy
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

CLEAN_PREVIEW = {
    "target": "preview",
    "event": "pull_request",
    "ref": "refs/heads/feature/x",
    "workflow": {
        "trigger": "pull_request",
        "permissions": {"contents": "read", "packages": "write", "id-token": "none"},
        "testsPassed": True,
        "matrixComplete": True,
        "failFast": False,
        "actions": [{"owner": "actions", "name": "checkout", "ref": "v4"}],
    },
    "image": {
        "multiStage": True,
        "runsAsRoot": False,
        "secretMode": "none",
        "criticalVulnerabilities": 0,
        "digestPinned": True,
    },
}

CLEAN_PRODUCTION = copy.deepcopy(CLEAN_PREVIEW)
CLEAN_PRODUCTION.update({"target": "production", "event": "push", "ref": "refs/heads/main"})
CLEAN_PRODUCTION["workflow"]["trigger"] = "push"
CLEAN_PRODUCTION["workflow"]["environmentApproval"] = True


def gate(payload):
    r = client.post("/release-gate", json=payload)
    assert r.status_code == 200
    return r.json()


def mutate(base, path, value):
    p = copy.deepcopy(base)
    node = p
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return p


def test_clean_preview_promotes():
    assert gate(CLEAN_PREVIEW) == {"decision": "promote", "violations": []}


def test_clean_production_promotes():
    assert gate(CLEAN_PRODUCTION) == {"decision": "promote", "violations": []}


@pytest.mark.parametrize("path,value,code", [
    (["workflow", "permissions"],
     {"contents": "read", "packages": "write", "id-token": "none", "actions": "read"},
     "EXCESS_PERMISSION"),
    (["workflow", "permissions"],
     {"contents": "write", "packages": "write", "id-token": "none"},
     "EXCESS_PERMISSION"),
    (["workflow", "trigger"], "pull_request_target", "UNSAFE_PR_TRIGGER"),
    (["workflow", "testsPassed"], False, "TESTS_INCOMPLETE"),
    (["workflow", "matrixComplete"], False, "TESTS_INCOMPLETE"),
    (["workflow", "failFast"], True, "TESTS_INCOMPLETE"),
    (["workflow", "actions"], [{"owner": "docker", "name": "build-push-action", "ref": "v5"}],
     "MUTABLE_ACTION"),
    (["workflow", "actions"], [{"owner": "docker", "name": "b", "ref": "A" * 40}],
     "MUTABLE_ACTION"),
    (["image", "multiStage"], False, "SINGLE_STAGE_IMAGE"),
    (["image", "runsAsRoot"], True, "ROOT_RUNTIME"),
    (["image", "secretMode"], "arg", "SECRET_IN_LAYER"),
    (["image", "secretMode"], "copy", "SECRET_IN_LAYER"),
    (["image", "criticalVulnerabilities"], 2, "CRITICAL_CVE"),
    (["image", "digestPinned"], False, "UNPINNED_IMAGE"),
])
def test_single_violation(path, value, code):
    result = gate(mutate(CLEAN_PREVIEW, path, value))
    assert result["decision"] == "block"
    assert result["violations"] == [code]


def test_third_party_sha_pin_is_accepted():
    payload = mutate(CLEAN_PREVIEW, ["workflow", "actions"],
                     [{"owner": "actions", "name": "checkout", "ref": "v4"},
                      {"owner": "docker", "name": "build-push-action", "ref": "a1b2c3d4" * 5}])
    assert gate(payload) == {"decision": "promote", "violations": []}


def test_buildkit_secret_is_accepted():
    assert gate(mutate(CLEAN_PREVIEW, ["image", "secretMode"], "buildkit"))["decision"] == "promote"


def test_production_requires_main_push():
    result = gate(mutate(CLEAN_PRODUCTION, ["ref"], "refs/heads/release"))
    assert result["decision"] == "block"
    assert result["violations"] == ["INVALID_PRODUCTION_REF"]


def test_production_requires_environment_approval():
    result = gate(mutate(CLEAN_PRODUCTION, ["workflow", "environmentApproval"], False))
    assert result["decision"] == "block"
    assert result["violations"] == ["APPROVAL_REQUIRED"]


def test_multiple_failures_are_all_reported():
    payload = copy.deepcopy(CLEAN_PRODUCTION)
    payload["workflow"]["trigger"] = "pull_request_target"
    payload["workflow"]["failFast"] = True
    payload["image"]["runsAsRoot"] = True
    payload["image"]["criticalVulnerabilities"] = 4
    payload["workflow"]["environmentApproval"] = False
    result = gate(payload)
    assert result["decision"] == "block"
    assert set(result["violations"]) == {
        "UNSAFE_PR_TRIGGER", "TESTS_INCOMPLETE", "ROOT_RUNTIME",
        "CRITICAL_CVE", "APPROVAL_REQUIRED",
    }


def test_promote_only_when_no_violations():
    assert gate(CLEAN_PREVIEW)["violations"] == []
    blocked = gate(mutate(CLEAN_PREVIEW, ["image", "digestPinned"], False))
    assert blocked["decision"] == "block" and blocked["violations"]
