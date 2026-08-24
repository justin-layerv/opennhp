import fnmatch
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / ".github/scripts/apply-durable-aop-session-control-delete-iam.py"
BEFORE_DOCUMENT = ROOT / "tests/fixtures/sandbox-dynamodb-read-v8.json"


def load_helper():
    spec = importlib.util.spec_from_file_location("session_control_delete_iam", HELPER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


FAKE_AWS = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

state_path = Path(os.environ["FAKE_IAM_STATE"])
log_path = Path(os.environ["FAKE_IAM_LOG"])
before_path = Path(os.environ["FAKE_IAM_BEFORE_DOCUMENT"])
state = json.loads(state_path.read_text())
args = sys.argv[1:]
with log_path.open("a") as handle:
    handle.write(json.dumps(args, separators=(",", ":")) + "\n")

expected_suffix = ["--region", "us-east-2", "--no-cli-pager", "--output", "json"]
if len(args) < 7 or args[0] != "iam" or args[-5:] != expected_suffix:
    print("unexpected global arguments", file=sys.stderr)
    raise SystemExit(91)
operation = args[1]
body = args[2:-5]
arn = "arn:aws:iam::767397897469:policy/layerv-nhp-sandbox-dynamodb-read"
before = json.loads(before_path.read_text())
desired_statement = {
    "Sid":"DynamoDBSessionControlTerminalCloseDelete","Effect":"Allow",
    "Action":["dynamodb:DeleteItem"],
    "Resource":["arn:aws:dynamodb:us-east-2:767397897469:table/layerv-nhp-sandbox-cell0-nhp-session-control"],
    "Condition":{"ForAllValues:StringLike":{"dynamodb:LeadingKeys":[
        "ACTIVE#ba9c4949557b0a0b68c6354dbdec84ab68d0e9af183243ac4ac1b89cf0b0c153","EVENT#*"
    ]},"ForAnyValue:StringEquals":{"dynamodb:EnclosingOperation":["TransactWriteItems"]},
    "Null":{"dynamodb:LeadingKeys":"false"}},
}
index = [item["Sid"] for item in before["Statement"]].index("DynamoDBSessionControlDueIndex") + 1
desired = {"Version":before["Version"],"Statement":[*before["Statement"][:index],desired_statement,*before["Statement"][index:]]}
stage = state.get("stage", "before")
default = "v9" if stage == "ready" else "v8"
versions = {
    "before":["v8","v7","v6","v5","v4"],
    "pruned":["v8","v7","v6","v5"],
    "ready":["v9","v8","v7","v6","v5"],
}[stage]
date = "2026-08-24T09:00:00+00:00"

if state.get("raw_operation") == operation:
    sys.stdout.write(state.get("raw_stdout", ""))
    raise SystemExit(int(state.get("raw_returncode", 0)))

if operation == "get-policy":
    assert body == ["--policy-arn", arn]
    tags = [{"Key":key,"Value":value} for key,value in {
        "Project":"NHP","Owner":"platform-team","Repository":"layervai/nhp","ManagedBy":"terraform",
        "Organization":"LayerV","CostCenter":"infrastructure","Environment":"sandbox","Service":"shared",
        "Application":"nhp",
    }.items()]
    value = {"Policy":{"PolicyName":"layerv-nhp-sandbox-dynamodb-read","PolicyId":"ANPA3FLD2UT65P2XBQDPY",
        "Arn":arn,"Path":"/","DefaultVersionId":default,"AttachmentCount":1,
        "PermissionsBoundaryUsageCount":0,"IsAttachable":True,
        "Description":"Read access to NHP DynamoDB tables, plus write access to ac-assignments for server auto-assignment",
        "CreateDate":date,"UpdateDate":date,"Tags":tags}}
    for key,value_override in state.get("policy_overrides", {}).items():
        value["Policy"][key] = value_override
    print(json.dumps(value))
elif operation == "list-entities-for-policy":
    assert body == ["--policy-arn", arn]
    roles = state.get("roles", [{"RoleName":"layerv-nhp-sandbox-server","RoleId":"AROA3FLD2UT64E3ZXY7UH"}])
    print(json.dumps({"PolicyGroups":[],"PolicyRoles":roles,"PolicyUsers":[]}))
elif operation == "list-policy-versions":
    assert body == ["--policy-arn", arn]
    if state.get("extra_version"):
        versions.append(state["extra_version"])
    print(json.dumps({"Versions":[{"VersionId":item,"IsDefaultVersion":item==default,"CreateDate":date} for item in versions]}))
elif operation == "get-policy-version":
    assert body[:2] == ["--policy-arn", arn] and body[2] == "--version-id"
    version = body[3]
    assert version == default
    document = desired if stage == "ready" else before
    if state.get("document_drift"):
        document = json.loads(json.dumps(document))
        document["Statement"][0]["Effect"] = "Deny"
    print(json.dumps({"PolicyVersion":{"Document":document,"VersionId":version,"IsDefaultVersion":True,"CreateDate":date}}))
elif operation == "delete-policy-version":
    assert body == ["--policy-arn",arn,"--version-id","v4"]
    if state.get("fail_delete_before"):
        print("delete failed before commit", file=sys.stderr)
        raise SystemExit(42)
    state["stage"] = "pruned"
    state_path.write_text(json.dumps(state))
    if state.get("fail_delete_after"):
        print("lost delete response", file=sys.stderr)
        raise SystemExit(42)
    print("{}")
elif operation == "create-policy-version":
    assert body[0:2] == ["--policy-arn",arn]
    assert body[2] == "--policy-document" and json.loads(body[3]) == desired
    assert body[4:] == ["--set-as-default"]
    if state.get("fail_create_before"):
        print("create failed before commit", file=sys.stderr)
        raise SystemExit(42)
    state["stage"] = "ready"
    state_path.write_text(json.dumps(state))
    if state.get("fail_create_after"):
        print("lost create response", file=sys.stderr)
        raise SystemExit(42)
    print(json.dumps({"PolicyVersion":{"VersionId":"v9","IsDefaultVersion":True,"CreateDate":date,"Document":desired}}))
else:
    print("unexpected operation", operation, file=sys.stderr)
    raise SystemExit(92)
"""


class SessionControlDeleteIAMTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.work = Path(self.temp.name)
        self.bin = self.work / "bin"
        self.bin.mkdir()
        fake = self.bin / "aws"
        fake.write_text(FAKE_AWS)
        fake.chmod(0o755)
        self.state = self.work / "state.json"
        self.log = self.work / "aws.log"
        self.env = os.environ.copy()
        self.env.update(
            {
                "PATH": f"{self.bin}:{self.env['PATH']}",
                "FAKE_IAM_STATE": str(self.state),
                "FAKE_IAM_LOG": str(self.log),
                "FAKE_IAM_BEFORE_DOCUMENT": str(BEFORE_DOCUMENT),
            }
        )
        self.reset()

    def tearDown(self):
        self.temp.cleanup()

    def reset(self, **state):
        self.state.write_text(json.dumps({"stage": "before", **state}))
        self.log.write_text("")

    def invoke(self, *args, expect=0):
        result = subprocess.run(
            [str(HELPER), *args], env=self.env, text=True, capture_output=True
        )
        self.assertEqual(result.returncode, expect, result.stderr)
        return result

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def plan(self):
        return self.invoke("plan").stdout.strip()

    def test_plan_apply_verify_and_replay_are_exact(self):
        intent = self.plan()
        self.assertEqual(
            json.loads(intent)["before_versions"], ["v4", "v5", "v6", "v7", "v8"]
        )
        result = self.invoke("apply", "--intent-json", intent)
        receipt = json.loads(result.stdout)
        self.assertEqual(receipt["versions"], ["v5", "v6", "v7", "v8", "v9"])
        self.assertEqual(json.loads(self.state.read_text())["stage"], "ready")
        mutations = [
            call[1]
            for call in self.calls()
            if call[1] in {"delete-policy-version", "create-policy-version"}
        ]
        self.assertEqual(mutations, ["delete-policy-version", "create-policy-version"])
        before = len(self.calls())
        self.assertEqual(
            json.loads(self.invoke("apply", "--intent-json", intent).stdout), receipt
        )
        self.assertEqual(
            json.loads(self.invoke("verify", "--intent-json", intent).stdout), receipt
        )
        self.assertNotIn(
            "delete-policy-version",
            [call[1] for call in self.calls()[before:]],
        )
        self.assertNotIn(
            "create-policy-version",
            [call[1] for call in self.calls()[before:]],
        )

    def test_delete_and_create_lost_responses_classify_exact_state(self):
        for flag in ("fail_delete_after", "fail_create_after"):
            with self.subTest(flag=flag):
                self.reset(**{flag: True})
                intent = self.plan()
                result = self.invoke("apply", "--intent-json", intent)
                self.assertEqual(json.loads(result.stdout)["default_version"], "v9")
                self.assertEqual(json.loads(self.state.read_text())["stage"], "ready")

    def test_partial_mutation_replays_without_replan(self):
        intent = self.plan()
        self.reset(stage="before", fail_create_before=True)
        # The delete commits, then the create fails before commit.
        self.invoke("apply", "--intent-json", intent, expect=1)
        state = json.loads(self.state.read_text())
        self.assertEqual(state["stage"], "pruned")
        state.pop("fail_create_before")
        self.state.write_text(json.dumps(state))
        self.log.write_text("")
        self.invoke("apply", "--intent-json", intent)
        self.assertNotIn("delete-policy-version", [call[1] for call in self.calls()])
        self.assertEqual(
            [call[1] for call in self.calls()].count("create-policy-version"), 1
        )

    def test_invalid_intent_fails_before_every_aws_action(self):
        baseline = json.loads(self.plan())
        mutations = {
            "action": "dynamodb:*",
            "enclosing_operation": "DeleteItem",
            "table_arn": baseline["table_arn"] + "-other",
            "leading_keys": ["EVENT#*", "SESSION#*"],
            "attached_role": "layerv-nhp-sandbox-ac",
            "policy_arn": baseline["policy_arn"] + "-other",
            "policy_path": "/other/",
            "prune_version": "v5",
        }
        for key, value in mutations.items():
            with self.subTest(key=key):
                candidate = dict(baseline)
                candidate[key] = value
                self.log.write_text("")
                self.invoke(
                    "apply",
                    "--intent-json",
                    json.dumps(candidate, sort_keys=True, separators=(",", ":")),
                    expect=1,
                )
                self.assertEqual(self.calls(), [])

    def test_live_authority_drift_fails_without_mutation(self):
        cases = (
            {"roles": [{"RoleName": "layerv-nhp-sandbox-ac", "RoleId": "AROAOTHER"}]},
            {"extra_version": "v10"},
            {"document_drift": True},
            {"policy_overrides": {"Path": "/other/"}},
            {"policy_overrides": {"Arn": "arn:aws:iam::767397897469:policy/other"}},
        )
        for state in cases:
            with self.subTest(state=state):
                self.reset(**state)
                self.invoke("plan", expect=1)
                self.assertFalse(
                    any(
                        call[1] in {"delete-policy-version", "create-policy-version"}
                        for call in self.calls()
                    )
                )

    def test_aws_output_is_bounded_closed_and_successful(self):
        for raw_stdout, returncode in (
            ("", 0),
            ("null\n", 0),
            ("{} {}\n", 0),
            ("{}\n", 42),
        ):
            with self.subTest(raw_stdout=raw_stdout, returncode=returncode):
                self.reset(
                    raw_operation="get-policy",
                    raw_stdout=raw_stdout,
                    raw_returncode=returncode,
                )
                self.invoke("plan", expect=1)

    def test_reviewed_statement_is_the_exact_terraform_document_delta(self):
        helper = load_helper()
        before = json.loads(BEFORE_DOCUMENT.read_text())
        desired = helper.desired_document(before)
        self.assertEqual(helper.digest(before), helper.BEFORE_POLICY_SHA256)
        self.assertEqual(helper.digest(desired), helper.DESIRED_POLICY_SHA256)
        delta = [
            statement
            for statement in desired["Statement"]
            if statement["Sid"] == helper.STATEMENT_SID
        ]
        self.assertEqual(delta, [helper.terminal_delete_statement()])

    def test_leading_key_union_denies_every_other_partition_namespace(self):
        helper = load_helper()

        def allowed(keys, enclosing_operation):
            return (
                enclosing_operation == helper.ENCLOSING_OPERATION
                and bool(keys)
                and all(
                    any(
                        fnmatch.fnmatchcase(key, pattern)
                        for pattern in helper.LEADING_KEYS
                    )
                    for key in keys
                )
            )

        active = helper.LEADING_KEYS[0]
        # AWS evaluates each transactional member as its underlying action.
        # Model the production terminal-close transaction and select only the
        # two DeleteItem members that enter this statement's LeadingKeys.
        mixed_transaction = [
            ("DeleteItem", active),
            ("DeleteItem", "EVENT#" + "a" * 64),
            ("UpdateItem", "CONTROL#cell0"),
            ("UpdateItem", "META#cell0"),
            ("UpdateItem", "SESSION#resource"),
            ("PutItem", "CLOSED#event"),
            ("ConditionCheckItem", "COMPLETE#event"),
            ("ConditionCheckItem", "TASKSET#event"),
        ]
        delete_member_keys = [
            key for action, key in mixed_transaction if action == "DeleteItem"
        ]
        non_delete_member_keys = [
            key for action, key in mixed_transaction if action != "DeleteItem"
        ]
        self.assertEqual(delete_member_keys, [active, "EVENT#" + "a" * 64])
        self.assertTrue(allowed(delete_member_keys, "TransactWriteItems"))
        self.assertNotIn("CONTROL#cell0", delete_member_keys)
        self.assertNotIn("SESSION#resource", delete_member_keys)
        self.assertTrue(non_delete_member_keys)
        # IAM cannot require both keys, so each allowed subset is documented.
        self.assertTrue(allowed([active], "TransactWriteItems"))
        self.assertTrue(allowed(["EVENT#" + "b" * 64], "TransactWriteItems"))
        self.assertFalse(allowed([active], "DeleteItem"))
        self.assertFalse(allowed([active], ""))
        for denied in (
            "ACTIVE#" + "0" * 64,
            "SESSION#abc",
            "CONTROL#abc",
            "OVERFLOW#abc",
            "TASK#abc",
            "DIRECTORY#abc",
            "OWNER#abc",
        ):
            with self.subTest(denied=denied):
                self.assertFalse(allowed([active, denied], "TransactWriteItems"))
        self.assertFalse(allowed([], "TransactWriteItems"))


if __name__ == "__main__":
    unittest.main()
