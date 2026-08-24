from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "terraform/scripts/project-qurl-sharing-customer-tier.py"
SPEC = importlib.util.spec_from_file_location("owner_projector", SCRIPT)
assert SPEC and SPEC.loader
MOD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MOD
SPEC.loader.exec_module(MOD)

CLIENT = "oScYkXhLitBPO6gBjxo4Rwyw37AdoNPy"
SUBJECT = f"{CLIENT}@clients"
EMAIL = "oscykxhlitbpo6gbjxo4rwyw37adonpy-clients@machine.notify.layerv.xyz"
SOURCE = "4" * 40
STAMP = "2026-08-23T21:00:00Z"


def row(*, tier: str = "free", usage: str = "0", updated: str = STAMP, assigned: str = ""):
    value = {
        "auth0_subject": {"S": SUBJECT},
        "email": {"S": EMAIL},
        "tier": {"S": tier},
        "frozen": {"BOOL": False},
        "frozen_reason": {"S": ""},
        "created_at": {"S": "2026-08-23T20:00:00Z"},
        "updated_at": {"S": updated},
        "current_period_usage": {"N": usage},
        "spending_cap_cents": {"N": "0"},
        "unit_price_cents": {"N": "0"},
    }
    if assigned:
        value["assigned_cell_id"] = {"S": assigned}
    return value


class FakeRunner:
    def __init__(self, reads, *, transaction_rc: int = 0):
        self.reads = list(reads)
        self.transaction_rc = transaction_rc
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if "get-item" in argv:
            value = self.reads.pop(0)
            body = {} if value is None else {"Item": value}
            return subprocess.CompletedProcess(argv, 0, json.dumps(body), "")
        if "transact-write-items" in argv:
            return subprocess.CompletedProcess(argv, self.transaction_rc, "{}", "failed")
        raise AssertionError(argv)


def make_plan(current=None):
    runner = FakeRunner([current])
    return MOD.plan(MOD.TABLE, CLIENT, MOD.REGION, STAMP, SOURCE, runner=runner)


def test_absent_plan_precommits_exact_complete_system_row():
    intent = make_plan()
    assert intent["action"] == "create"
    assert intent["before_row_sha256"] == "absent"
    assert intent["source_sha"] == SOURCE
    assert intent["subject"] == SUBJECT
    assert intent["email"] == EMAIL
    assert intent["expected_created_at"] == STAMP
    assert intent["expected_updated_at"] == STAMP
    assert intent["expected_usage"] == "0"
    assert intent["expected_assigned_cell_id"] == ""
    expected = MOD.expected_row_from_intent(intent)
    assert set(expected) == MOD.REQUIRED_FIELDS
    assert "ttl" not in expected
    assert MOD.row_digest(expected) == intent["expected_row_sha256"]


def test_real_aws_empty_get_item_stdout_is_exact_absence():
    class EmptyAWSRunner(FakeRunner):
        def __call__(self, argv, **kwargs):
            assert "get-item" in argv
            return subprocess.CompletedProcess(argv, 0, "", "")

    intent = MOD.plan(
        MOD.TABLE,
        CLIENT,
        MOD.REGION,
        STAMP,
        SOURCE,
        runner=EmptyAWSRunner([]),
    )
    assert intent["action"] == "create"
    assert intent["before_row_sha256"] == "absent"


def test_create_uses_one_deterministic_transaction_and_classifies_lost_response():
    intent = make_plan()
    expected = MOD.expected_row_from_intent(intent)
    runner = FakeRunner([None, expected], transaction_rc=75)
    assert MOD.apply_intent(intent, runner=runner) == intent["expected_row_sha256"]
    transact = [call for call in runner.calls if "transact-write-items" in call[0]]
    assert len(transact) == 1
    argv = transact[0][0]
    token = argv[argv.index("--client-request-token") + 1]
    assert len(token) == 36 and token.startswith("qshare-")
    items = json.loads(argv[argv.index("--transact-items") + 1])
    assert len(items) == 1
    assert items[0]["Put"]["Item"] == expected


def test_create_ambiguity_cannot_self_pin_a_different_system_row():
    intent = make_plan()
    different = MOD.expected_row_from_intent(intent)
    different["updated_at"] = {"S": "2026-08-23T21:00:01Z"}
    with pytest.raises(MOD.ProjectionError):
        MOD.apply_intent(intent, runner=FakeRunner([None, different], transaction_rc=75))


def test_free_plan_apply_verify_exact_cas_preserves_authority():
    free = row(usage="3", updated="2026-08-23T20:30:00Z", assigned="cell0")
    intent = make_plan(free)
    assert intent["action"] == "promote"
    assert intent["before_row_sha256"] == MOD.row_digest(free)
    assert intent["expected_created_at"] == "2026-08-23T20:00:00Z"
    assert intent["expected_updated_at"] == "2026-08-23T20:30:00Z"
    assert intent["expected_usage"] == "3"
    assert intent["expected_assigned_cell_id"] == "cell0"
    expected = MOD.expected_row_from_intent(intent)
    runner = FakeRunner([free, expected])
    assert MOD.apply_intent(intent, runner=runner) == intent["expected_row_sha256"]
    assert MOD.verify_intent(intent, runner=FakeRunner([expected])) == intent["expected_row_sha256"]
    transaction = json.loads(
        next(call[0] for call in runner.calls if "transact-write-items" in call[0])[
            next(call[0] for call in runner.calls if "transact-write-items" in call[0]).index("--transact-items") + 1
        ]
    )
    update = transaction[0]["Update"]
    assert update["UpdateExpression"] == "SET #tier = :system"
    assert "#assigned = :assigned" in update["ConditionExpression"]


def test_replay_plan_is_exact_and_apply_performs_no_write():
    system = row(tier="system", usage="4", updated="2026-08-23T20:45:00Z")
    intent = make_plan(system)
    assert intent["action"] == "replay"
    assert intent["provisioned_at"] == "2026-08-23T20:45:00Z"
    runner = FakeRunner([system])
    assert MOD.apply_intent(intent, runner=runner) == MOD.row_digest(system)
    assert all("transact-write-items" not in call[0] for call in runner.calls)


def test_verify_exact_then_current_allows_only_monotonic_cell0_descendant():
    intent = make_plan()
    exact = MOD.expected_row_from_intent(intent)
    assert MOD.verify_intent(intent, runner=FakeRunner([exact])) == MOD.row_digest(exact)
    descendant = copy.deepcopy(exact)
    descendant["updated_at"] = {"S": "2026-08-23T21:01:00Z"}
    descendant["current_period_usage"] = {"N": "2"}
    descendant["assigned_cell_id"] = {"S": "cell0"}
    assert MOD.verify_current_owner(intent, runner=FakeRunner([descendant])) == MOD.row_digest(descendant)
    mutations = []
    for field, value in (
        ("auth0_subject", {"S": "x"}),
        ("email", {"S": "other@machine.notify.layerv.xyz"}),
        ("tier", {"S": "free"}),
        ("frozen", {"BOOL": True}),
        ("created_at", {"S": "2026-08-23T19:00:00Z"}),
        ("updated_at", {"S": "2026-08-23T20:59:59Z"}),
        ("current_period_usage", {"N": "-1"}),
        ("spending_cap_cents", {"N": "1"}),
        ("assigned_cell_id", {"S": "cell1"}),
    ):
        bad = copy.deepcopy(descendant)
        bad[field] = value
        mutations.append(bad)
    for bad in mutations:
        with pytest.raises(MOD.ProjectionError):
            MOD.verify_current_owner(intent, runner=FakeRunner([bad]))

    promoted_intent = make_plan(row(usage="3", assigned="cell0"))
    rollback = MOD.expected_row_from_intent(promoted_intent)
    rollback["current_period_usage"] = {"N": "2"}
    with pytest.raises(MOD.ProjectionError):
        MOD.verify_current_owner(promoted_intent, runner=FakeRunner([rollback]))


def test_intent_strict_types_digest_and_strong_read_shape():
    intent = make_plan()
    for field, value in (
        ("client_id", 1),
        ("source_sha", 1),
        ("expected_row_sha256", 1),
        ("before_row_sha256", 1),
        ("expected_usage", 1),
        ("provisioned_at", 1),
    ):
        bad = dict(intent)
        bad[field] = value
        with pytest.raises(MOD.ProjectionError):
            MOD.validate_intent(bad)
    bad = dict(intent)
    bad["expected_usage"] = "1"
    with pytest.raises(MOD.ProjectionError):
        MOD.validate_intent(bad)

    class BadRead(FakeRunner):
        def __call__(self, argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, '{"ConsumedCapacity":{}}', "")

    with pytest.raises(MOD.ProjectionError):
        MOD.strong_read(MOD.TABLE, SUBJECT, MOD.REGION, BadRead([]))

    class RawRead(FakeRunner):
        def __init__(self, stdout: str, returncode: int = 0):
            super().__init__([])
            self.stdout = stdout
            self.returncode = returncode

        def __call__(self, argv, **kwargs):
            return subprocess.CompletedProcess(argv, self.returncode, self.stdout, "")

    for raw in (
        " ",
        "\n",
        "null",
        "[]",
        "{",
        '{"Item":null}',
        '{"Item":{},"extra":true}',
        '{"ConsumedCapacity":{}}',
    ):
        with pytest.raises(MOD.ProjectionError):
            MOD.strong_read(MOD.TABLE, SUBJECT, MOD.REGION, RawRead(raw))

    assert MOD.strong_read(MOD.TABLE, SUBJECT, MOD.REGION, RawRead("{}")) is None
    with pytest.raises(MOD.ProjectionError):
        MOD.strong_read(MOD.TABLE, SUBJECT, MOD.REGION, RawRead("", returncode=75))


def test_malformed_or_paid_existing_rows_never_plan():
    for bad in (
        {**row(), "ttl": {"N": "1"}},
        {**row(), "email": {"S": "other@example.com"}},
        {**row(), "tier": {"S": "growth"}},
        {**row(), "frozen": {"BOOL": True}},
        {**row(), "spending_cap_cents": {"N": "1"}},
    ):
        with pytest.raises(MOD.ProjectionError):
            make_plan(bad)
