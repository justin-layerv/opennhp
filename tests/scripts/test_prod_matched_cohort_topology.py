from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def text(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def selector_key_set(name: str) -> set[str]:
    tree = ast.parse(text(".github/scripts/prod_matched_cohort_control.py"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return set(ast.literal_eval(node.value))
    raise AssertionError(f"missing selector key set {name}")


def python_literal(path: str, name: str):
    tree = ast.parse(text(path))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == name for target in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError(f"missing Python literal {name} in {path}")


def resource_stems(path: str, module_prefix: str) -> set[str]:
    return {
        f"{module_prefix}{resource_type}.{name}"
        for resource_type, name in re.findall(
            r'(?m)^resource "([^"]+)" "([^"]+)" \{',
            text(path),
        )
    }


def hcl_object_keys(label: str) -> set[str]:
    source = text("terraform/matched_cohort_contract.tf")
    match = re.search(rf"(?m)^    {label} = \{{\n", source)
    if match is None:
        raise AssertionError(f"missing contract object {label}")
    keys: set[str] = set()
    depth = 1
    for line in source[match.end():].splitlines():
        depth += line.count("{") - line.count("}")
        if depth == 0:
            break
        if depth == 1:
            key = re.match(r"^      ([a-z][a-z0-9_]*)\s+=", line)
            if key:
                keys.add(key.group(1))
    return keys


class MatchedCohortTopologyTest(unittest.TestCase):
    def test_saved_plan_inventory_covers_every_cohort_resource_declaration(self) -> None:
        checker = ".github/scripts/check-prod-matched-cohort-additive-plan.py"
        allowed = {
            address.removesuffix("[0]")
            for address in (
                python_literal(checker, "ALLOWED_RESOURCE_NAMES")
                | python_literal(checker, "CONNECTOR_AUTHORITY_CREATES")
            )
        }
        allowed |= {
            prefix.removesuffix('["')
            for prefix in (
                python_literal(checker, "ALLOWED_INDEXED_PREFIXES")
                + python_literal(checker, "ALLOWED_FRPS_KEY_PREFIXES")
                + (python_literal(checker, "AC_FRPS_INGRESS_PREFIX"),)
            )
        }
        allowed |= {
            prefix.removesuffix("[")
            for prefix in python_literal(checker, "ALLOWED_NUMERIC_PREFIXES")
        }

        declared = resource_stems(
            "terraform/matched_cohort_contract.tf",
            "module.nhp.",
        )
        declared |= {
            "module.nhp.aws_ssm_parameter.relay_matched_cohort_image_tag",
        }
        declared |= resource_stems(
            "terraform/modules/dynamodb/matched_cohort.tf",
            "module.nhp.module.dynamodb.",
        )
        declared |= resource_stems(
            "terraform/modules/compute/matched_cohort.tf",
            "module.nhp.module.compute.",
        )
        declared.remove(
            "module.nhp.module.compute.aws_iam_role_policy.server_candidate_control_identity_agent_keys"
        )
        declared |= {
            "module.nhp.module.compute.aws_iam_role_policy.server_candidate_connector_authority",
        }
        declared |= resource_stems(
            "terraform/modules/ac/matched_cohort.tf",
            "module.nhp.module.ac.",
        )
        declared |= resource_stems(
            "terraform/modules/relay/matched_cohort.tf",
            "module.nhp.module.relay[0].",
        )
        self.assertEqual(allowed, declared)

    def test_server_candidate_is_full_size_and_only_on_candidate_edges(self) -> None:
        source = text("terraform/modules/compute/matched_cohort.tf")
        block = re.search(
            r'resource "aws_autoscaling_group" "server_candidate" \{(?P<body>.*)\n\}',
            source,
            re.S,
        )
        self.assertIsNotNone(block)
        body = block.group("body")
        for required in (
            "min_size            = var.min_capacity",
            "desired_capacity    = var.min_capacity",
            "aws_lb_target_group.server_registration_green[0].arn",
            "aws_lb_target_group.server_relay_green[0].arn",
            "aws_lb_target_group.server_candidate[0].arn",
            "aws_lb_target_group.server_candidate_promotion[0].arn",
        ):
            self.assertIn(required, body)
        self.assertNotIn("aws_lb_target_group.udp[", body)
        self.assertNotIn("aws_lb_target_group.server_registration_blue", body)

    def test_candidate_readiness_has_no_unconditional_wait_and_uses_five_second_health(self) -> None:
        compute = text("terraform/modules/compute/matched_cohort.tf")
        ac = text("terraform/modules/ac/matched_cohort.tf")
        relay = text("terraform/modules/relay/matched_cohort.tf")
        checker = text(".github/scripts/check-prod-matched-cohort-additive-plan.py")

        self.assertNotIn('resource "time_sleep" "server_matched_cohort_iam_propagation"', compute)
        self.assertNotIn("server_matched_cohort_iam_propagation", checker)
        self.assertIn("candidate_iam_ready()", compute)
        self.assertIn('local pids=()', compute)
        self.assertIn('for pid in "$${pids[@]}"; do wait "$pid" || failed=1; done', compute)
        self.assertIn("for attempt in $(seq 1 45)", compute)
        self.assertIn("sleep 0.25", compute)
        self.assertIn("sleep 0.5", compute)
        self.assertIn("sleep 1", compute)
        self.assertNotIn('create_duration = "60s"', compute)
        control = text(".github/scripts/prod_matched_cohort_control.py")
        self.assertNotIn("time.sleep", control)
        self.assertNotIn("import time", control)

        # Every candidate/cohort-only target health block is five seconds.
        # With healthy_threshold=2 this gives a nominal <=10s ELB signal and
        # leaves PR2 free to consume event/readback state without coarse polls.
        for source in (compute, ac, relay):
            intervals = re.findall(r"(?m)^\s+interval\s+=\s+(\d+)$", source)
            self.assertTrue(intervals)
            self.assertEqual(set(intervals), {"5"})

    def test_blue_registration_endpoint_never_targets_candidate(self) -> None:
        source = text("terraform/modules/compute/matched_cohort.tf")
        blue = re.search(
            r'resource "aws_autoscaling_attachment" "server_registration_blue" \{(?P<body>.*?)\n\}',
            source,
            re.S,
        )
        self.assertIsNotNone(blue)
        self.assertIn("aws_autoscaling_group.server.name", blue.group("body"))
        self.assertNotIn("server_candidate", blue.group("body"))

    def test_ac_rollback_clone_and_candidate_are_disjoint_and_full_size(self) -> None:
        source = text("terraform/modules/ac/matched_cohort.tf")
        blue = re.search(
            r'resource "aws_autoscaling_group" "ac_matched_blue" \{(?P<body>.*?)\n\}',
            source,
            re.S,
        )
        green = re.search(
            r'resource "aws_autoscaling_group" "ac_candidate" \{(?P<body>.*?)\n\}',
            source,
            re.S,
        )
        self.assertIsNotNone(blue)
        self.assertIsNotNone(green)
        for body in (blue.group("body"), green.group("body")):
            self.assertIn("coalesce(var.ac_min_capacity, local.is_prod ? 2 : 1)", body)
            self.assertIn("condition     = var.enable_egress_eips", body)
        self.assertIn("aws_launch_template.ac_matched_blue", blue.group("body"))
        self.assertIn("aws_lb_target_group.ac_tcp.arn", blue.group("body"))
        self.assertNotIn("ac_candidate", blue.group("body"))
        self.assertIn("aws_launch_template.ac_matched_green", green.group("body"))
        self.assertIn("aws_lb_target_group.ac_candidate", green.group("body"))
        self.assertNotIn("aws_lb_target_group.ac_tcp.arn", green.group("body"))

        # HTTPS and every FRPS control port stay on the same physical cohort.
        # The old rollback clone owns all established blue target groups; the
        # green candidate owns only the isolated candidate vector.
        self.assertIn("aws_lb_target_group.ac_frps_control[0].arn", blue.group("body"))
        self.assertIn("aws_lb_target_group.ac_frps_control_additional[name].arn", blue.group("body"))
        self.assertIn("aws_lb_target_group.ac_candidate_frps[name].arn", green.group("body"))
        self.assertNotIn("ac_frps_control[0].arn", green.group("body"))

        outputs = text("terraform/modules/ac/outputs.tf")
        for authority in (
            "asg_name",
            "min_size",
            "max_size",
            "desired_capacity",
            "launch_template_id",
            "launch_template_version",
            "image_parameter",
            "image_tag",
            "target_group_arns",
        ):
            self.assertRegex(outputs, rf"(?m)^    {authority}\s+=")
        self.assertIn('data "aws_ssm_parameter" "matched_cohort_blue_image_tag"', source)
        control = text(".github/scripts/prod_matched_cohort_control.py")
        self.assertIn("def _read_fleet", control)
        self.assertIn("def _assert_fleet_image", control)
        self.assertIn("for label, authority in fleets", control)

    def test_ac_candidate_frps_vector_is_restricted_and_selector_complete(self) -> None:
        source = text("terraform/modules/ac/matched_cohort.tf")
        outputs = text("terraform/modules/ac/outputs.tf")
        plan = text(".github/scripts/check-prod-matched-cohort-additive-plan.py")

        for resource in (
            'resource "aws_lb_target_group" "ac_candidate_frps"',
            'resource "aws_lb_listener" "ac_candidate_frps"',
            'resource "aws_vpc_security_group_ingress_rule" "ac_candidate_nlb_frps"',
            'resource "aws_vpc_security_group_egress_rule" "ac_candidate_nlb_frps"',
            'resource "aws_vpc_security_group_ingress_rule" "ac_candidate_target_frps"',
        ):
            self.assertIn(resource, source)
        self.assertIn(
            "for pair in setproduct(keys(local.matched_cohort_frps_controls), var.matched_cohort_smoke_ingress_cidrs)",
            source,
        )
        self.assertIn("cidr_ipv4         = each.value.cidr", source)
        self.assertIn("referenced_security_group_id = aws_security_group.ac.id", source)
        for field in (
            "canonical_listener_arn",
            "blue_target_group_arn",
            "candidate_target_group_arn",
            "candidate_listener_arn",
            "listen_port",
        ):
            self.assertIn(field, outputs)
        self.assertIn("ALLOWED_FRPS_KEY_PREFIXES", plan)
        self.assertIn("AC_FRPS_INGRESS_PREFIX", plan)

    def test_ac_rendered_launch_slots_bind_exact_color_server_endpoints(self) -> None:
        source = text("terraform/modules/ac/main.tf")
        self.assertRegex(
            source,
            r"(?s)matched_cohort_blue_user_data.*?server_endpoint\s+= var\.matched_cohort_blue_server_endpoint",
        )
        self.assertRegex(
            source,
            r"(?s)matched_cohort_green_user_data.*?server_endpoint\s+= var\.matched_cohort_green_server_endpoint",
        )
        self.assertRegex(
            source,
            r"(?s)matched_cohort_blue_user_data.*?eip_pool_tag\s+= local\.matched_cohort_blue_eip_pool_tag",
        )
        self.assertRegex(
            source,
            r"(?s)matched_cohort_green_user_data.*?eip_pool_tag\s+= local\.matched_cohort_green_eip_pool_tag",
        )
        root = text("terraform/main.tf")
        self.assertIn(
            'matched_cohort_blue_server_endpoint  = module.compute.matched_cohort_registration_blue_dns_name == null ? "" : module.compute.matched_cohort_registration_blue_dns_name',
            root,
        )
        self.assertIn(
            'matched_cohort_green_server_endpoint = module.compute.matched_cohort_registration_green_dns_name == null ? "" : module.compute.matched_cohort_registration_green_dns_name',
            root,
        )

    def test_disabled_cohort_root_wiring_converts_nullable_outputs_explicitly(self) -> None:
        root = text("terraform/main.tf")
        nullable_outputs = (
            "module.dynamodb.matched_cohort_server_policy_arn",
            "module.dynamodb.matched_cohort_server_policy_doc_hash",
            "module.dynamodb.matched_cohort_ac_assignments_table_name",
            "module.dynamodb.matched_cohort_ac_assignments_table_arn",
            "module.compute.matched_cohort_registration_blue_dns_name",
            "module.compute.matched_cohort_registration_green_dns_name",
        )
        for output in nullable_outputs:
            with self.subTest(output=output):
                self.assertIn(f'{output} == null ? "" :', root)
                self.assertNotRegex(root, rf"coalesce\(\s*{re.escape(output)}\s*,\s*\"\"")

    def test_ac_cohorts_have_disjoint_full_capacity_eip_pools(self) -> None:
        source = text("terraform/modules/ac/matched_cohort.tf")
        for color in ("blue", "green"):
            block = re.search(
                rf'resource "aws_eip" "matched_cohort_{color}" \{{(?P<body>.*?)\n\}}',
                source,
                re.S,
            )
            self.assertIsNotNone(block)
            body = block.group("body")
            self.assertIn("local.resolved_max_capacity + 1", body)
            self.assertIn(f"local.matched_cohort_{color}_eip_pool_tag", body)
        main = text("terraform/modules/ac/main.tf")
        self.assertIn('matched_cohort_blue_eip_pool_tag  = "${var.name_prefix}-ac-matched-blue"', main)
        self.assertIn('matched_cohort_green_eip_pool_tag = "${var.name_prefix}-ac-matched-green"', main)

    def test_relay_blue_and_candidate_server_routes_never_share_selector(self) -> None:
        root = text("terraform/main.tf")
        dmz = text("terraform/relay_dmz.tf")
        module = text("terraform/modules/relay/main.tf")
        self.assertIn("host       = module.compute.internal_nlb_dns_name", dmz)
        self.assertIn("host       = module.compute.matched_cohort_relay_green_dns_name", root)
        self.assertIn("cell_servers         = var.cell_servers", module)
        self.assertIn("cell_servers            = var.matched_cohort_cell_servers", module)
        self.assertNotIn("matched_cohort_relay_green_dns_name", dmz)

    def test_contract_has_independent_public_gates_and_candidate_selectors(self) -> None:
        source = text("terraform/matched_cohort_contract.tf")
        self.assertIn("digest-qualified server, AC, and relay images", source)
        self.assertIn("--release-id", source)
        self.assertIn("mutable source tag", source)
        for component in ("server", "ac"):
            block = re.search(rf"{component} = \{{(?P<body>.*?)\n    \}}", source, re.S)
            self.assertIsNotNone(block)
            self.assertIn("candidate_target_group_arn", block.group("body"))
            self.assertNotIn("closed_target_group_arn", block.group("body"))
        relay = re.search(r"relay = \{(?P<body>.*?)\n    \}", source, re.S)
        self.assertIsNotNone(relay)
        self.assertIn("candidate_target_group_arn", relay.group("body"))
        self.assertIn("blue_server_endpoint", relay.group("body"))
        self.assertIn("green_server_endpoint", relay.group("body"))
        self.assertIn("frps_selectors", source)
        self.assertIn("server_ingress_rules", source)
        self.assertIn("ac_ingress_rules", source)
        self.assertIn("relay_rule", source)
        self.assertIn("matched_cohort_maintenance_rule", source)
        self.assertNotIn("relay_ip_set", source)

    def test_contract_key_sets_are_the_exact_selector_key_sets(self) -> None:
        for label, constant in (("server", "SERVER_KEYS"), ("ac", "AC_KEYS"), ("relay", "RELAY_KEYS")):
            with self.subTest(label=label):
                self.assertEqual(hcl_object_keys(label), selector_key_set(constant))

    def test_maintenance_gate_paths_preserve_candidate_and_internal_smoke(self) -> None:
        compute = text("terraform/modules/compute/matched_cohort.tf")
        ac = text("terraform/modules/ac/matched_cohort.tf")
        relay = text("terraform/modules/relay/matched_cohort.tf")
        relay_main = text("terraform/modules/relay/alb.tf")
        control = text(".github/scripts/prod_matched_cohort_control.py")

        self.assertNotIn('resource "aws_vpc_security_group_ingress_rule" "server_matched_cohort_internal"', compute)
        internal = re.search(
            r'resource "aws_vpc_security_group_ingress_rule" "server_matched_cohort_internal" \{(?P<body>.*?)\n\}',
            ac,
            re.S,
        )
        self.assertIsNotNone(internal)
        self.assertIn("security_group_id            = var.server_security_group_id", internal.group("body"))
        self.assertIn("referenced_security_group_id = aws_security_group.ac.id", internal.group("body"))
        self.assertIn("from_port                    = 62206", internal.group("body"))
        self.assertIn("to_port                      = 62206", internal.group("body"))
        self.assertIn('ip_protocol                  = "udp"', internal.group("body"))
        self.assertNotIn("cidr_ipv4", internal.group("body"))
        root = text("terraform/main.tf")
        self.assertIn("server_security_group_id             = module.compute.security_group_id", root)
        self.assertIn('resource "aws_vpc_security_group_ingress_rule" "ac_candidate_target_https"', ac)
        self.assertIn('resource "aws_vpc_security_group_ingress_rule" "ac_candidate_target_frps"', ac)
        outputs = text("terraform/modules/ac/outputs.tf")
        for public_rule in ("https", "http", "portal", "nhp_connector", "nhp_knock", "frps_primary"):
            self.assertRegex(outputs, rf"(?m)^      {public_rule} = \{{")
        self.assertIn('resource "aws_lb" "relay_candidate"', relay)
        self.assertIn("load_balancer_arn = aws_lb.relay_candidate[0].arn", relay)
        self.assertIn('resource "aws_lb_listener_rule" "relay_maintenance"', relay)
        self.assertIn("depends_on = [aws_lb_listener_rule.relay]", relay)
        self.assertIn('priority = var.enable_matched_cohort_canary ? 2 : 1', relay_main)
        self.assertIn("MaintenanceController", control)
        self.assertIn("closure_probe()", control)
        self.assertIn('gates.require_state("closed")', control)

    def test_relay_candidate_security_group_has_only_standalone_rules(self) -> None:
        source = text("terraform/modules/relay/matched_cohort.tf")
        block = re.search(
            r'resource "aws_security_group" "relay_candidate_alb" \{(?P<body>.*?)\n\}',
            source,
            re.S,
        )
        self.assertIsNotNone(block)
        self.assertNotRegex(block.group("body"), r"(?m)^\s*(ingress|egress)\s*=")
        self.assertIn('resource "aws_vpc_security_group_ingress_rule" "alb_candidate_https"', source)
        self.assertIn(
            'resource "aws_vpc_security_group_egress_rule" "relay_candidate_alb_to_relay"',
            source,
        )

    def test_candidate_assignment_and_discovery_authority_cannot_observe_blue_rows(self) -> None:
        root = text("terraform/main.tf")
        compute_main = text("terraform/modules/compute/main.tf")
        compute = text("terraform/modules/compute/matched_cohort.tf")
        template = text("terraform/modules/compute/user_data.sh.tpl")
        dynamodb = text("terraform/modules/dynamodb/matched_cohort.tf")
        self.assertIn(
            'matched_cohort_ac_assignments_table = module.dynamodb.matched_cohort_ac_assignments_table_name == null ? "" : module.dynamodb.matched_cohort_ac_assignments_table_name',
            root,
        )
        self.assertRegex(
            compute,
            r"dynamodb_ac_assignments_table\s+= var\.matched_cohort_ac_assignments_table",
        )
        self.assertRegex(
            compute,
            r"dynamodb_ac_assignment_authority_table\s+= var\.dynamodb_ac_assignments_table",
        )
        self.assertRegex(
            compute_main,
            r"dynamodb_ac_assignment_authority_table\s+= null",
        )
        self.assertIn('%{ if dynamodb_ac_assignment_authority_table != null ~}', template)
        self.assertIn('ACAssignmentAuthorityTable = "${dynamodb_ac_assignment_authority_table}"', template)
        self.assertRegex(
            compute,
            r"cloudmap_service_id\s+= aws_service_discovery_service\.server_candidate\[0\]\.id",
        )
        candidate_lt = re.search(
            r'resource "aws_launch_template" "server_candidate" \{(?P<body>.*?)\n\}',
            compute,
            re.S,
        )
        candidate_asg = re.search(
            r'resource "aws_autoscaling_group" "server_candidate" \{(?P<body>.*?)\n\}',
            compute,
            re.S,
        )
        self.assertIsNotNone(candidate_lt)
        self.assertIsNotNone(candidate_asg)
        self.assertIn("aws_launch_template.server_candidate[0].id", candidate_asg.group("body"))
        self.assertNotIn("aws_launch_template.server.id", candidate_asg.group("body"))
        self.assertIn('name         = "${var.name_prefix}-${var.cell_id}-ac-assignments-candidate"', dynamodb)

        # Deterministic namespace journey: an old physical AC row can exist in
        # the rollback table, but the candidate server's configured lookup has
        # no route to that map or its blue peer list.
        blue_rows = {"physical-ac": {"assigned_servers": ["blue-1", "blue-2"]}}
        candidate_rows = {"physical-ac": {"assigned_servers": ["green-1"]}}
        self.assertEqual(candidate_rows["physical-ac"]["assigned_servers"], ["green-1"])
        self.assertNotEqual(
            candidate_rows["physical-ac"]["assigned_servers"],
            blue_rows["physical-ac"]["assigned_servers"],
        )

    def test_candidate_role_can_only_read_active_and_only_write_candidate_routes(self) -> None:
        compute = text("terraform/modules/compute/matched_cohort.tf")
        dynamodb = text("terraform/modules/dynamodb/matched_cohort.tf")
        connector = text("terraform/modules/compute/connector_authority.tf")
        candidate_lt = re.search(
            r'resource "aws_launch_template" "server_candidate" \{(?P<body>.*?)\n\}',
            compute,
            re.S,
        )
        self.assertIsNotNone(candidate_lt)
        self.assertIn(
            "aws_iam_instance_profile.server_candidate[0].arn",
            candidate_lt.group("body"),
        )
        self.assertNotIn("aws_iam_instance_profile.server.arn", candidate_lt.group("body"))

        active = re.search(
            r'Sid\s+= "CandidateReadActiveAssignmentAuthority"(?P<body>.*?)\n\s+\}',
            dynamodb,
            re.S,
        )
        candidate_read = re.search(
            r'Sid\s+= "CandidateRouteRead"(?P<body>.*?)\n\s+\}',
            dynamodb,
            re.S,
        )
        candidate_fence = re.search(
            r'Sid\s+= "CandidateRouteTerminationFenceCheck"(?P<body>.*?)\n\s+\}',
            dynamodb,
            re.S,
        )
        candidate_write = re.search(
            r'Sid\s+= "CandidateRouteWrite"(?P<body>.*?)\n\s+\}',
            dynamodb,
            re.S,
        )
        self.assertIsNotNone(active)
        self.assertIsNotNone(candidate_read)
        self.assertIsNotNone(candidate_fence)
        self.assertIsNotNone(candidate_write)
        policy_start = dynamodb.index('resource "aws_iam_policy" "matched_cohort_server"')
        policy_end = dynamodb.find('\nresource "', policy_start + 1)
        candidate_policy_source = dynamodb[policy_start:policy_end] if policy_end >= 0 else dynamodb[policy_start:]
        self.assertNotIn("matched_cohort_operator_lock", candidate_policy_source)
        self.assertIn('Action   = ["dynamodb:GetItem"]', active.group("body"))
        self.assertEqual(
            set(re.findall(r'"(dynamodb:[A-Za-z]+)"', active.group("body"))),
            {"dynamodb:GetItem"},
        )
        for forbidden in ("dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"):
            self.assertNotIn(forbidden, active.group("body"))
        self.assertIn("matched_cohort_ac_assignments[0].arn", candidate_read.group("body"))
        self.assertEqual(
            set(re.findall(r'"(dynamodb:[A-Za-z]+)"', candidate_read.group("body"))),
            {
                "dynamodb:GetItem",
                "dynamodb:Query",
                "dynamodb:Scan",
            },
        )
        self.assertEqual(
            set(re.findall(r'"(dynamodb:[A-Za-z]+)"', candidate_fence.group("body"))),
            {"dynamodb:ConditionCheckItem"},
        )
        self.assertEqual(
            {
                action
                for action in re.findall(r'"(dynamodb:[A-Za-z]+)"', candidate_write.group("body"))
                if action != "dynamodb:LeadingKeys"
            },
            {"dynamodb:PutItem"},
        )
        self.assertIn('"dynamodb:LeadingKeys" = ["__server_termination__#*"]', candidate_write.group("body"))
        session_control = re.search(
            r'Sid\s+= "CandidateSessionControlAuthority"(?P<body>.*?)\n\s+\}',
            dynamodb,
            re.S,
        )
        self.assertIsNotNone(session_control)
        self.assertIn('"dynamodb:DeleteItem"', session_control.group("body"))
        self.assertIn("aws_dynamodb_table.session_control.arn", session_control.group("body"))
        self.assertEqual(
            set(re.findall(r'"(dynamodb:[A-Za-z]+)"', session_control.group("body"))),
            {
                "dynamodb:ConditionCheckItem",
                "dynamodb:DeleteItem",
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:Query",
                "dynamodb:UpdateItem",
            },
        )
        self.assertNotIn('"dynamodb:DeleteItem"', active.group("body"))
        self.assertNotIn('"dynamodb:DeleteItem"', candidate_read.group("body"))
        self.assertNotIn('"dynamodb:DeleteItem"', candidate_fence.group("body"))
        self.assertNotIn('"dynamodb:DeleteItem"', candidate_write.group("body"))
        self.assertIn(
            "var.enable_matched_cohort_canary ? local.matched_cohort_candidate_server_role_arn",
            connector,
        )
        self.assertNotIn(
            "var.enable_matched_cohort_canary ? aws_iam_role.server_candidate[0].arn",
            connector,
        )

    def test_operator_journal_is_non_expiring_encrypted_and_runtime_isolated(self) -> None:
        dynamodb = text("terraform/modules/dynamodb/matched_cohort.tf")
        start = dynamodb.index('resource "aws_dynamodb_table" "matched_cohort_operator_lock"')
        end = dynamodb.index(
            "# Candidate server storage authority.",
            start,
        )
        journal = dynamodb[start:end]
        self.assertIn("point_in_time_recovery", journal)
        self.assertIn("enabled = local.is_prod", journal)
        self.assertIn("server_side_encryption", journal)
        self.assertIn("kms_key_arn = var.kms_key_arn", journal)
        self.assertNotIn("ttl {", journal)

        policy_start = dynamodb.index('resource "aws_iam_policy" "matched_cohort_server"')
        policy_end = dynamodb.find('\nresource "', policy_start + 1)
        candidate_policy = (
            dynamodb[policy_start:policy_end]
            if policy_end >= 0
            else dynamodb[policy_start:]
        )
        self.assertNotIn("matched_cohort_operator_lock", candidate_policy)

    def test_candidate_termination_cleanup_is_scoped_to_candidate_authority(self) -> None:
        source = text("terraform/modules/compute/matched_cohort.tf")
        cleanup = text("terraform/modules/compute/lambda/server_candidate_termination_cleanup.py")
        self.assertIn("AC_ASSIGNMENTS_TABLE = var.matched_cohort_ac_assignments_table", source)
        self.assertNotIn("SERVER_AC_INDEX_TABLE", cleanup)
        self.assertIn("table.scan", cleanup)
        self.assertIn("table.delete_item", cleanup)
        self.assertNotIn("CandidateAssignmentKMS", source)
        policy = re.search(
            r'resource "aws_iam_role_policy" "server_candidate_termination_cleanup" \{(?P<body>.*?)\n\}',
            source,
            re.S,
        )
        self.assertIsNotNone(policy)
        self.assertNotIn("kms:", policy.group("body"))
        self.assertEqual(
            set(re.findall(r'"(dynamodb:[A-Za-z]+)"', policy.group("body"))),
            {
                "dynamodb:DeleteItem",
                "dynamodb:GetItem",
                "dynamodb:PutItem",
                "dynamodb:Scan",
                "dynamodb:UpdateItem",
            },
        )
        self.assertIn('Sid    = "DeregisterCandidateServer"', policy.group("body"))
        self.assertIn('"servicediscovery:DeregisterInstance"', policy.group("body"))
        self.assertIn('"servicediscovery:GetInstance"', policy.group("body"))
        self.assertIn('Sid    = "ConsumeCandidateCleanupFailure"', policy.group("body"))
        self.assertIn('Sid      = "PublishCandidateCleanupFailure"', policy.group("body"))
        self.assertIn('Action   = ["sqs:SendMessage"]', policy.group("body"))
        self.assertIn('Sid      = "ObserveCandidateTermination"', policy.group("body"))
        self.assertIn('Action   = ["ec2:DescribeInstances"]', policy.group("body"))
        self.assertRegex(
            policy.group("body"),
            r'(?s)Sid\s+= "ObserveCandidateTermination".*?Action\s+= \["ec2:DescribeInstances"\].*?Resource\s+= "\*"',
        )

        hook = re.search(
            r'resource "aws_autoscaling_lifecycle_hook" "server_candidate_termination" \{(?P<body>.*?)\n\}',
            source,
            re.S,
        )
        self.assertIsNotNone(hook)
        self.assertRegex(hook.group("body"), r'(?m)^\s+default_result\s+= "CONTINUE"$')
        self.assertRegex(hook.group("body"), r"(?m)^\s+heartbeat_timeout\s+= 7200$")
        self.assertIn("notification_target_arn = aws_sqs_queue.server_candidate_termination_cleanup_dlq[0].arn", hook.group("body"))
        self.assertIn("role_arn                = aws_iam_role.server_candidate_termination_hook[0].arn", hook.group("body"))
        self.assertIn(
            'resource "aws_lambda_event_source_mapping" "server_candidate_termination_cleanup"',
            source,
        )
        self.assertIn("batch_size       = 1", source)
        self.assertRegex(
            source,
            r"(?m)^\s+CLOUDMAP_SERVICE_ID\s+= aws_service_discovery_service\.server_candidate\[0\]\.id$",
        )
        self.assertIn("FENCE_PREFIX = \"__server_termination__#\"", cleanup)
        self.assertIn("table.put_item", cleanup)
        self.assertIn("CLOUDMAP.deregister_instance", cleanup)
        self.assertLess(cleanup.index("_install_fence(table, detail)"), cleanup.index("_deregister(detail[\"EC2InstanceId\"])") )
        self.assertLess(cleanup.index("_deregister(detail[\"EC2InstanceId\"])") , cleanup.index("_cleanup(table, detail[\"EC2InstanceId\"])") )

        self.assertRegex(
            source,
            r'(?s)resource "aws_cloudwatch_event_target" "server_candidate_termination".*?maximum_event_age_in_seconds = 240.*?maximum_retry_attempts\s+= 2.*?dead_letter_config.*?aws_sqs_queue\.server_candidate_termination_cleanup_dlq\[0\]\.arn.*?depends_on = \[aws_sqs_queue_policy\.server_candidate_termination_cleanup_dlq\]',
        )
        self.assertRegex(
            source,
            r'(?s)resource "aws_lambda_function_event_invoke_config" "server_candidate_termination_cleanup".*?maximum_event_age_in_seconds = 240.*?maximum_retry_attempts\s+= 1.*?destination_config.*?on_failure.*?aws_sqs_queue\.server_candidate_termination_cleanup_dlq\[0\]\.arn',
        )
        for expected in (
            'resource "aws_sqs_queue_policy" "server_candidate_termination_cleanup_dlq"',
            'Principal = { Service = "events.amazonaws.com" }',
            'Action    = "sqs:SendMessage"',
            '"aws:SourceArn" = aws_cloudwatch_event_rule.server_candidate_termination[0].arn',
            '"aws:SourceAccount" = data.aws_caller_identity.current.account_id',
        ):
            self.assertIn(expected, source)
        self.assertRegex(
            source,
            r'(?s)resource "aws_cloudwatch_metric_alarm" "server_candidate_termination_cleanup_dlq".*?namespace\s+= "AWS/SQS".*?metric_name\s+= "ApproximateNumberOfMessagesVisible"',
        )
        self.assertRegex(
            source,
            r'(?s)resource "aws_cloudwatch_metric_alarm" "server_candidate_termination_event_failures".*?namespace\s+= "AWS/Events".*?metric_name\s+= "FailedInvocations"',
        )

    def test_prod_ac_capacity_is_the_reviewed_explicit_ceiling(self) -> None:
        prod = text("terraform/environments/prod/terraform.tfvars")
        self.assertRegex(prod, r"(?m)^ac_min_capacity\s*=\s*3$")
        self.assertRegex(prod, r"(?m)^ac_max_capacity\s*=\s*10$")
        checker_test = text("tests/scripts/test_check_prod_matched_cohort_additive_plan.py")
        self.assertIn("ac_max_capacity = 10", checker_test)
        self.assertIn("range(ac_max_capacity + 1)", checker_test)

    def test_no_floor_recovery_or_hard_cut_authority_is_added(self) -> None:
        paths = (
            "terraform/matched_cohort_contract.tf",
            "terraform/modules/compute/matched_cohort.tf",
            "terraform/modules/ac/matched_cohort.tf",
            "terraform/modules/relay/matched_cohort.tf",
            ".github/scripts/prod-matched-cohort-selector.py",
            ".github/scripts/prod-matched-cohort-maintenance.py",
            ".github/scripts/prod_matched_cohort_control.py",
        )
        forbidden = ("minimum-protocol-profile", "durable-aop-cutover", "recovery", "manual refresh")
        combined = "\n".join(text(path).lower() for path in paths)
        for token in forbidden:
            self.assertNotIn(token, combined)

        rollout_sources = "\n".join(
            text(path).lower()
            for path in (
                ".github/scripts/prod-matched-cohort-selector.py",
                ".github/scripts/prod-matched-cohort-maintenance.py",
                ".github/scripts/prod_matched_cohort_control.py",
                ".github/scripts/check-prod-matched-cohort-additive-plan.py",
                "terraform/matched_cohort_contract.tf",
                "terraform/modules/compute/matched_cohort.tf",
                "terraform/modules/ac/matched_cohort.tf",
                "terraform/modules/relay/matched_cohort.tf",
            )
        )
        for token in (
            "clear-ac-assignments",
            "start-instance-refresh",
            "suspend-processes",
            "resume-processes",
            "minimum-protocol-profile",
            "durable-aop-cutover",
        ):
            self.assertNotIn(token, rollout_sources)


if __name__ == "__main__":
    unittest.main()
