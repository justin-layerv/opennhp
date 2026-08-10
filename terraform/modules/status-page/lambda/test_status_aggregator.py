"""
Unit tests for the public LayerV status-page aggregator.

These tests pin the customer-facing contract: coarse component health,
history counters, sanitized incidents, and no infrastructure detail.

Resolved incident fixtures expected to publish use relative UTC dates because
fixed dates eventually age out of retention.
"""

import ipaddress
import importlib.util
import json
import os
import re
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")
os.environ.setdefault("AWS_EC2_METADATA_DISABLED", "true")
os.environ.setdefault("ENVIRONMENT", "sandbox")
os.environ.setdefault("ALARM_NAME_PREFIXES", "nhp-sandbox-cell0,nhp-sandbox-ac-")
os.environ.setdefault("SERVER_ALARM_PREFIXES", "nhp-sandbox-cell0")
os.environ.setdefault("AC_ALARM_PREFIXES", "nhp-sandbox-ac-")
os.environ.setdefault("SERVER_NLB_TG_ARNS", "arn:aws:elasticloadbalancing:us-east-1:123456789:targetgroup/server-blue/abc123")
os.environ.setdefault("AC_NLB_TG_ARNS", "arn:aws:elasticloadbalancing:us-east-1:123456789:targetgroup/ac-blue/def456")
os.environ.setdefault("DEPENDENT_SERVICE_URLS", "{}")
os.environ.setdefault("DISPLAY_ONLY_COMPONENT_IDS", "website")
os.environ.setdefault("STATUS_BUCKET", "status-test-bucket")


def _load_public_surface_guard():
    script_path = (
        Path(__file__).resolve().parents[4]
        / ".github/scripts/check-status-page-public-surface.py"
    )
    spec = importlib.util.spec_from_file_location(
        "check_status_page_public_surface",
        script_path,
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _health(healthy, unhealthy, total, configured=None, described=None, errors=0):
    if configured is None:
        configured = 1 if total > 0 else 0
    if described is None:
        described = 1 if total > 0 else 0
    return {
        "healthy": healthy,
        "unhealthy": unhealthy,
        "total": total,
        "configured": configured,
        "described": described,
        "errors": errors,
    }


def _today_key():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


class TestDeriveStatus:
    def test_operational_all_targets_up_no_alarms(self):
        from status_aggregator import OPERATIONAL, _derive_status

        assert _derive_status(_health(2, 0, 2), False) == OPERATIONAL

    def test_unknown_without_target_data(self):
        from status_aggregator import UNKNOWN, _derive_status

        assert _derive_status(_health(0, 0, 0, configured=0, described=0), False) == UNKNOWN

    def test_degraded_alarm_with_missing_target_data(self):
        from status_aggregator import DEGRADED, _derive_status

        assert _derive_status(_health(0, 0, 0, configured=1, described=0, errors=1), True) == DEGRADED

    def test_known_nlb_outage_is_not_app_debounced(self):
        from status_aggregator import MAJOR_OUTAGE, _derive_status

        # Target-group health checks already smooth this signal; only HTTP
        # hard-fail probes use the app-level two-snapshot debounce.
        assert _derive_status(_health(0, 2, 2), False) == MAJOR_OUTAGE

    def test_degraded_some_unhealthy(self):
        from status_aggregator import DEGRADED, _derive_status

        assert _derive_status(_health(1, 1, 2), False) == DEGRADED

    def test_partial_describe_error_with_no_healthy_signal_is_unknown(self):
        from status_aggregator import UNKNOWN, _derive_status

        assert _derive_status(_health(0, 1, 1, configured=2, described=1, errors=1), False) == UNKNOWN


class TestAggregateTargetHealth:
    def test_minimal_alarm_prefixes_drops_redundant_narrow_prefixes(self):
        import status_aggregator as sa

        assert sa._minimal_alarm_prefixes([
            "nhp-prod-",
            "nhp-prod-server-",
            "nhp-prod-ac-",
            "nhp-sandbox-server-",
            "nhp-sandbox-",
        ]) == ["nhp-prod-", "nhp-sandbox-"]

    @patch("status_aggregator.ssm")
    def test_target_group_selection_uses_active_color_when_configured(self, mock_ssm):
        import status_aggregator as sa

        mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "green"}}

        with patch.dict(os.environ, {
            "SERVER_NLB_TG_ARNS": "arn:blue,arn:green",
            "SERVER_NLB_TG_ARNS_BY_COLOR": '{"blue":["arn:blue"],"green":["arn:green"]}',
            "SERVER_ACTIVE_COLOR_PARAMETER": "/sandbox/nhp/server/active-color",
        }):
            assert sa._target_group_arns("SERVER") == ["arn:green"]

    @patch("status_aggregator.ssm")
    def test_target_group_selection_is_unknown_on_active_color_read_error(self, mock_ssm):
        import status_aggregator as sa

        mock_ssm.get_parameter.side_effect = RuntimeError("ssm unavailable")

        with patch.dict(os.environ, {
            "AC_NLB_TG_ARNS": "arn:blue,arn:green",
            "AC_NLB_TG_ARNS_BY_COLOR": '{"blue":["arn:blue"],"green":["arn:green"]}',
            "AC_ACTIVE_COLOR_PARAMETER": "/sandbox/nhp/ac/active-color",
        }), patch("builtins.print") as mock_print:
            assert sa._target_group_arns("AC") is None

        assert any("Active color unavailable for ac target groups" in call.args[0] for call in mock_print.call_args_list)

    def test_target_group_arns_by_color_rejects_malformed_and_wrong_shape_json(self):
        import status_aggregator as sa

        with patch.dict(os.environ, {"SERVER_NLB_TG_ARNS_BY_COLOR": "{not-json"}), \
                patch("builtins.print") as mock_print:
            assert sa._target_group_arns_by_color("SERVER") == {}
        assert any("Invalid SERVER_NLB_TG_ARNS_BY_COLOR" in call.args[0] for call in mock_print.call_args_list)

        with patch.dict(os.environ, {"SERVER_NLB_TG_ARNS_BY_COLOR": '["arn:server"]'}):
            assert sa._target_group_arns_by_color("SERVER") == {}

        with patch.dict(os.environ, {
            "SERVER_NLB_TG_ARNS_BY_COLOR": json.dumps({
                "red": ["arn:red"],
                "blue": ["", "arn:blue"],
            }),
        }):
            assert sa._target_group_arns_by_color("SERVER") == {"blue": ["arn:blue"]}

    @patch("status_aggregator.elbv2")
    def test_counts_healthy_and_unhealthy_targets(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health

        mock_elbv2.describe_target_health.return_value = {
            "TargetHealthDescriptions": [
                {"TargetHealth": {"State": "healthy"}},
                {"TargetHealth": {"State": "unhealthy"}},
                {"TargetHealth": {"State": "draining"}},
            ]
        }

        assert _aggregate_target_health(["arn:tg/test"]) == _health(1, 1, 3)

    @patch("status_aggregator.elbv2")
    def test_continues_on_describe_error(self, mock_elbv2):
        from status_aggregator import _aggregate_target_health

        mock_elbv2.describe_target_health.side_effect = [
            RuntimeError("access denied"),
            {"TargetHealthDescriptions": [{"TargetHealth": {"State": "healthy"}}]},
        ]

        assert _aggregate_target_health(["arn:tg/bad", "arn:tg/good"]) == _health(
            1,
            0,
            1,
            configured=2,
            described=1,
            errors=1,
        )


def _dorny_to_regex(pattern):
    """Compile a dorny/picomatch path glob the way dorny matches it.

    `**` crosses `/`; a single `*` does not. fnmatch cannot express that
    distinction — its `*` always crosses — which is why an earlier version of
    this fence simply refused any pattern containing a lone `*`. That also
    rejected ordinary shapes like `**/*.tf`, turning a routine filter addition
    into a matcher rewrite, so translate properly instead.

    `**/` matches zero or more directories, so `**/*.tf` matches `a.tf` as well
    as `sub/a.tf`.
    """
    # picomatch treats `**` as a globstar only when it is a WHOLE path segment;
    # `foo**bar` degrades to single-`*` semantics there. Rather than model that
    # second meaning, refuse it — the contract this translator advertises is
    # "reject what you cannot model", and silently compiling `foo**bar` to
    # `foo.*bar` would cross `/` where picomatch would not.
    for match in re.finditer(r"\*\*", pattern):
        before, after = pattern[: match.start()], pattern[match.end() :]
        if (before and not before.endswith("/")) or (after and not after.startswith("/")):
            raise AssertionError(
                f"`**` must be a whole path segment, got {pattern!r}; "
                "teach _dorny_to_regex picomatch's mid-segment semantics first"
            )

    out = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            out.append(".*")
            i += 2
        elif pattern[i] == "*":
            out.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(out) + r"\Z")


class TestGlobTranslation:
    """The translator is load-bearing for the trigger-coverage fence below."""

    def test_double_star_crosses_slash_and_single_star_does_not(self):
        cases = [
            ("terraform/modules/**/lambda/**", "terraform/modules/sp/lambda/x.py", True),
            ("terraform/modules/**/lambda/**", "terraform/modules/monitoring/main.tf", False),
            ("terraform/modules/monitoring/**", "terraform/modules/monitoring/main.tf", True),
            ("terraform/main.tf", "terraform/main.tf", True),
            ("terraform/main.tf", "terraform/modules/main.tf", False),
            # The shapes the old invariant rejected outright.
            ("**/*.tf", "a.tf", True),
            ("**/*.tf", "deep/nested/a.tf", True),
            ("**/*.tf", "a.py", False),
            ("terraform/*.tf", "terraform/main.tf", True),
            # A single `*` must NOT cross a separator; fnmatch got this wrong.
            ("terraform/*.tf", "terraform/modules/main.tf", False),
            ("terraform/*/main.tf", "terraform/modules/main.tf", True),
            ("terraform/*/main.tf", "terraform/a/b/main.tf", False),
        ]
        for pattern, path, expected in cases:
            assert bool(_dorny_to_regex(pattern).match(path)) is expected, (pattern, path)

    def test_mid_segment_double_star_is_refused_not_guessed(self):
        # picomatch would degrade these to single-`*`; compiling them as a
        # globstar would cross `/` where it must not.
        for pattern in ("foo**bar", "a/foo**", "a/**bar/c"):
            with pytest.raises(AssertionError, match="whole path segment"):
                _dorny_to_regex(pattern)
        # Legitimate whole-segment forms keep working.
        for pattern in ("**", "**/x", "a/**", "a/**/b", "a/**/b/**"):
            _dorny_to_regex(pattern)

    def test_metacharacters_in_the_literal_are_escaped(self):
        assert _dorny_to_regex("a.b/c.tf").match("a.b/c.tf")
        assert not _dorny_to_regex("a.b/c.tf").match("axb/c.tf")


class TestAlarmSummary:
    # Every repo path this suite reads from OUTSIDE its own
    # terraform/modules/*/lambda/ tree. build-and-push.yml's `lambdas` paths
    # filter decides whether "Test Lambdas" runs at all, so an input the filter
    # does not watch means the guard reading it stays silent on the PR that
    # breaks it and first fires on an unrelated Lambda PR days later — which is
    # how #3732's uncategorized alarm surfaced on dependabot PR #3780. Add to
    # this tuple whenever the suite grows a read outside lambda/.
    SUITE_INPUTS_OUTSIDE_LAMBDA_DIR = (
        ".github/scripts/check-status-page-public-surface.py",
        ".gitignore",
        "docs/runbooks/prod-rollout-ledger/2026-06-10-pr-2457-public-status-page.md",
        "terraform/main.tf",
        "terraform/modules/monitoring/main.tf",
        "terraform/modules/status-page/README.md",
        "terraform/modules/status-page/frontend/index.html",
        "terraform/modules/status-page/main.tf",
        "terraform/modules/status-page/variables.tf",
    )
    # Watching these would also need an `on.push.paths` entry in
    # build-and-push.yml — check-paths-filter-coverage.py requires every inner
    # filter pattern to have an ancestor there — and the only entry that covers
    # them is a `docs/**` or `.gitignore` glob that would start a build and
    # deploy on every prose edit. Both are assertion fixtures, not behavior the
    # published status page depends on, so the trade is not worth it.
    #
    # That cost is per-path, not a blanket exemption: #3794 accepted it for
    # `check-status-page-public-surface.py` because a single named file is a
    # cheap `on.push.paths` entry, and it is watched now. Hence equality rather
    # than subset below — this list has to shrink when that happens, and it
    # failed loudly here until it did.
    SUITE_INPUTS_KNOWINGLY_UNWATCHED = frozenset({
        ".gitignore",
        "docs/runbooks/prod-rollout-ledger/2026-06-10-pr-2457-public-status-page.md",
    })

    def test_lambdas_paths_filter_watches_this_suites_inputs(self):
        repo_root = Path(__file__).resolve().parents[4]
        workflow = (repo_root / ".github/workflows/build-and-push.yml").read_text()
        # Positional, not structural: this hardcodes the filter block's exact
        # indentation (12 spaces before `lambdas:`, 14 before each entry), so a
        # reindent, a reflow, or a YAML anchor in that group breaks the match —
        # `assert group` below turns that into a loud, explained failure rather
        # than a silent skip. Parsing the YAML properly would need PyYAML,
        # which the Test Lambdas env does not install. Two consequences worth
        # knowing if this ever fires: re.M + first-match binds to the first
        # 12-space `lambdas:` key in the file, and a differently-indented
        # rewrite needs this pattern updated, not the filter reverted.
        group = re.search(
            r"^            lambdas:\n((?:              (?:#.*|- '[^']+')\n)+)",
            workflow,
            re.M,
        )
        assert group, "could not locate the `lambdas` filter group in build-and-push.yml"
        patterns = re.findall(r"- '([^']+)'", group.group(1))
        assert patterns

        # Syntax this translator does not model. Brace expansion, negation and
        # character classes all change which paths match, so guessing would
        # produce a false green — the thing this fence exists to prevent.
        unsupported = sorted(p for p in patterns if set(p) & set("{}!()[]+@"))
        assert not unsupported, (
            "unsupported glob syntax in the `lambdas` filter; teach "
            f"_dorny_to_regex first: {unsupported}"
        )

        watched = {
            path
            for path in self.SUITE_INPUTS_OUTSIDE_LAMBDA_DIR
            for pattern in patterns
            if _dorny_to_regex(pattern).match(path)
        }
        unwatched = set(self.SUITE_INPUTS_OUTSIDE_LAMBDA_DIR) - watched

        # Equality, not subset: a path that becomes watched must leave the
        # allowlist, so the recorded exceptions can't quietly go stale.
        assert unwatched == set(self.SUITE_INPUTS_KNOWINGLY_UNWATCHED), (
            "build-and-push.yml's `lambdas` filter no longer matches this "
            f"suite's declared inputs: newly unwatched="
            f"{sorted(unwatched - self.SUITE_INPUTS_KNOWINGLY_UNWATCHED)}, "
            f"stale allowlist entries="
            f"{sorted(self.SUITE_INPUTS_KNOWINGLY_UNWATCHED - unwatched)}"
        )

    def test_declared_suite_inputs_are_read_by_this_suite(self):
        source = Path(__file__).read_text()
        # The declarations live in this file, so searching the whole source
        # would match the tuple entry itself and pass vacuously. Cut the
        # declaration block out first and look for a real read.
        # Each constant is excised on its own rather than as one span between
        # them: a single span assumes they stay adjacent, and anything inserted
        # between would shrink what gets cut and quietly restore the vacuous
        # match for whatever stayed inside.
        body = source
        for declaration in (
            r"    SUITE_INPUTS_OUTSIDE_LAMBDA_DIR = \(.*?\n    \)\n",
            r"    SUITE_INPUTS_KNOWINGLY_UNWATCHED = frozenset\(\{.*?\n    \}\)\n",
        ):
            body, count = re.subn(declaration, "", body, flags=re.S)
            assert count == 1, f"declaration not excised ({declaration!r}); guard is vacuous"

        for path in self.SUITE_INPUTS_OUTSIDE_LAMBDA_DIR:
            # Anchor on the whole read expression, for both shapes. Module-local
            # files are read through parents[1] so they appear as a tail rather
            # than the full repo-relative path — and a bare `"main.tf"` or
            # `"README.md"` also occurs in assertion text, so that substring
            # alone would prove nothing.
            #
            # Note what this therefore tracks: the read's SYNTAX, on one line
            # with this spacing — not the existence of the read. Hoisting a
            # path into a local, or reflowing the expression, fails here even
            # though the file is still read. That is the safe direction and it
            # is intended: the declaration list is a claim about what this
            # suite reads, and a refactor should re-confirm it rather than
            # quietly inherit it. Update the needle, don't delete the entry.
            tail = path.partition("terraform/modules/status-page/")[2]
            needle = f'parents[1] / "{tail}"' if tail else f'/ "{path}"'
            assert needle in body, (
                f"{path} is declared as a suite input but nothing reads it "
                f"(looked for {needle!r}); drop it from "
                "SUITE_INPUTS_OUTSIDE_LAMBDA_DIR"
            )
        assert self.SUITE_INPUTS_KNOWINGLY_UNWATCHED <= set(
            self.SUITE_INPUTS_OUTSIDE_LAMBDA_DIR
        )

    def test_monitoring_cell_alarms_are_classified_or_explicitly_ignored(self):
        import status_aggregator as sa

        repo_root = Path(__file__).resolve().parents[4]
        monitoring_main = (repo_root / "terraform/modules/monitoring/main.tf").read_text()
        # This parser intentionally matches the monitoring module's current
        # literal one-line alarm_name shape; update it if that HCL shape changes.
        cell_alarm_suffixes = set(re.findall(
            r'alarm_name\s+=\s+"\$\{var\.name_prefix\}-\$\{var\.cell_id\}(-[a-z0-9-]+)"',
            monitoring_main,
        ))
        ignored_non_status_suffixes = {
            "-art-replay-gate-drop",
            "-auth-failures",
            # A cell instance served a Connector registration while its
            # Authority handler was still dark (un-activated env, or mid
            # activation rollout). That is an internal activation-rollout
            # tripwire on a control-plane path with no public status
            # component, not evidence that the public NHP server is
            # unavailable — the knock edge keeps serving throughout.
            "-connector-registration-handler-absent",
            "-internal-auth-signer-unavailable",
            # qURL reverse-tunnel token binding is an internal rollout/security
            # tripwire, not evidence that the public NHP server is unavailable.
            "-internal-token-validate-run-id-mismatch",
            "-overload-cookie-mint-failure",
            "-overload-cookie-process-local-key",
            "-relay-forward-reject",
            "-revocation-aged-out",
            "-revocation-aged-out-page",
            "-revocation-aged-out-suppressed",
            "-revocation-delivery-latency",
            "-revocation-deploy-window",
            "-revocation-deploy-window-without-run",
            "-revocation-targeted-zero-match",
            "-revocation-untrackable",
            # This alarm means the flood-readiness telemetry collector is
            # blind; target health remains the public availability signal.
            "-udp-edge-collector-missing",
        }
        status_owned_suffixes = (
            set(sa.CELL_SERVER_ALARM_SUFFIXES)
            | set(sa.CELL_AC_ALARM_TOKENS)
            | {suffix for suffix in cell_alarm_suffixes if suffix.startswith("-server-")}
        )

        unclassified = cell_alarm_suffixes - status_owned_suffixes - ignored_non_status_suffixes

        assert cell_alarm_suffixes
        assert not unclassified, f"categorize new monitoring alarm suffixes: {sorted(unclassified)}"

        # Matching is substring-based, so these four differ only in prefix
        # text — but the monitoring module is instantiated per env and per
        # cell, so assert the real deployed shapes rather than a stand-in.
        # Deliberately NOT an enumeration of deployed env x cell. That would be
        # a list that goes stale in silence — add cell2 and this stays green
        # while covering less, the opposite of the point. Matching is
        # substring-based on the whole alarm name, so the property is
        # prefix-independence: one real deployed shape, one arbitrary future
        # cell, and a degenerate prefix together assert that no ignored suffix
        # yields a component regardless of what precedes it.
        for cell_prefix in (
            "layerv-nhp-prod-cell0",
            "layerv-nhp-sandbox-cell99",
            "x",
        ):
            for suffix in sorted(ignored_non_status_suffixes):
                name = f"{cell_prefix}{suffix}"
                assert sa._component_for_alarm_name(
                    name, cell_prefix, (cell_prefix,), ()
                ) is None, name
                assert sa._component_for_alarm_name(name) is None, name

    @patch("status_aggregator.cloudwatch")
    def test_prefix_ownership_maps_status_relevant_active_alarms(self, mock_cloudwatch):
        from status_aggregator import _get_alarm_summary

        paginator = MagicMock()
        paginator.paginate.side_effect = [
            [{
                "MetricAlarms": [
                    {"AlarmName": "nhp-prod-cell0-server-high-cpu", "StateValue": "ALARM"},
                    {"AlarmName": "nhp-prod-cell0-high-cpu", "StateValue": "ALARM"},
                    {"AlarmName": "nhp-prod-cell0-ac-peer-count-low", "StateValue": "ALARM"},
                ],
                "CompositeAlarms": [],
            }],
            [{
                "MetricAlarms": [
                    {"AlarmName": "nhp-prod-ac-registration", "StateValue": "ALARM"},
                ],
                "CompositeAlarms": [],
            }],
        ]
        mock_cloudwatch.get_paginator.return_value = paginator

        summary = _get_alarm_summary(
            ["nhp-prod-cell0", "nhp-prod-ac-"],
            ["nhp-prod-cell0"],
            ["nhp-prod-ac-"],
        )

        assert summary == {"server_active": True, "ac_active": True}

    @patch("status_aggregator.cloudwatch")
    def test_owned_prefixes_are_described_even_if_broad_prefixes_are_missing(self, mock_cloudwatch):
        from status_aggregator import _get_alarm_summary

        paginator = MagicMock()
        paginator.paginate.side_effect = [
            [{
                "MetricAlarms": [
                    {"AlarmName": "nhp-prod-cell0-high-cpu", "StateValue": "ALARM"},
                ],
                "CompositeAlarms": [],
            }],
            [{
                "MetricAlarms": [
                    {"AlarmName": "nhp-prod-ac-registration", "StateValue": "ALARM"},
                ],
                "CompositeAlarms": [],
            }],
        ]
        mock_cloudwatch.get_paginator.return_value = paginator

        summary = _get_alarm_summary(
            [],
            ["nhp-prod-cell0"],
            ["nhp-prod-ac-"],
        )

        assert summary == {"server_active": True, "ac_active": True}
        assert [call.kwargs for call in paginator.paginate.call_args_list] == [
            {"AlarmNamePrefix": "nhp-prod-cell0", "StateValue": "ALARM"},
            {"AlarmNamePrefix": "nhp-prod-ac-", "StateValue": "ALARM"},
        ]

    @patch("status_aggregator.cloudwatch")
    def test_cell_prefix_ignores_qurl_control_plane_alarms(self, mock_cloudwatch):
        from status_aggregator import _get_alarm_summary

        paginator = MagicMock()
        paginator.paginate.return_value = [{
            "MetricAlarms": [
                {"AlarmName": "nhp-prod-cell0-qurl-api-keys-throttle", "StateValue": "ALARM"},
                {"AlarmName": "nhp-prod-cell0-qurl-resource-lifecycle-dlq-messages", "StateValue": "ALARM"},
                {"AlarmName": "nhp-prod-cell0-revocation-aged-out-page", "StateValue": "ALARM"},
                {"AlarmName": "nhp-prod-cell0-qurl-api-high-latency", "StateValue": "ALARM"},
                {"AlarmName": "nhp-prod-cell0-qurl-api-unhealthy-hosts", "StateValue": "ALARM"},
            ],
            "CompositeAlarms": [],
        }]
        mock_cloudwatch.get_paginator.return_value = paginator

        summary = _get_alarm_summary(
            ["nhp-prod-cell0"],
            ["nhp-prod-cell0"],
            [],
        )

        assert summary == {"server_active": False, "ac_active": False}

    @patch("status_aggregator.cloudwatch")
    def test_overlapping_prefixes_do_not_hide_specific_alarm_classification(self, mock_cloudwatch):
        from status_aggregator import _get_alarm_summary

        alarm = {"AlarmName": "nhp-prod-ac-registration", "StateValue": "ALARM"}
        paginator = MagicMock()
        paginator.paginate.return_value = [{"MetricAlarms": [alarm], "CompositeAlarms": []}]
        mock_cloudwatch.get_paginator.return_value = paginator

        summary = _get_alarm_summary(
            ["nhp-prod", "nhp-prod-ac-"],
            ["nhp-prod"],
            ["nhp-prod-ac-"],
        )

        assert summary == {"server_active": False, "ac_active": True}
        assert [call.kwargs for call in paginator.paginate.call_args_list] == [
            {"AlarmNamePrefix": "nhp-prod", "StateValue": "ALARM"},
        ]

    def test_global_alarm_token_fallback_for_legacy_prefixes(self):
        from status_aggregator import _component_for_alarm_name

        assert _component_for_alarm_name("legacy-prod-ac-registration") == "ac"
        assert _component_for_alarm_name("legacy-prod-server-panic") == "server"

    def test_trailing_hyphen_server_prefixes_are_limited_to_known_server_surfaces(self):
        import status_aggregator as sa

        assert sa._server_alarm_matches_owned_prefix(
            "nhp-prod-green-any-server-alarm",
            "nhp-prod-green-",
        )
        assert sa._server_alarm_matches_owned_prefix(
            "nhp-prod-srv-int-any-server-alarm",
            "nhp-prod-srv-int-",
        )
        assert not sa._server_alarm_matches_owned_prefix(
            "nhp-prod-qurl-api-any-alarm",
            "nhp-prod-qurl-api-",
        )


class TestProbeDnsResolution:
    def test_getaddrinfo_timeout_fails_fast_without_waiting_for_resolver(self):
        import concurrent.futures
        import status_aggregator as sa

        executor = MagicMock()
        future = MagicMock()
        future.result.side_effect = concurrent.futures.TimeoutError()
        executor.submit.return_value = future

        with patch.object(sa, "_DNS_RESOLVER_POOL", executor), \
                patch("status_aggregator.ThreadPoolExecutor") as mock_pool:
            infos, reason = sa._getaddrinfo_with_timeout("slow.example.com", 443)

        assert infos is None
        assert reason == "hostname resolution timed out"
        mock_pool.assert_not_called()
        future.result.assert_called_once_with(timeout=sa.URL_CHECK_TIMEOUT_SECONDS)
        future.cancel.assert_called_once()
        executor.shutdown.assert_not_called()


class TestHttpChecks:
    @pytest.fixture(autouse=True)
    def _mock_probe_dns(self):
        with patch("status_aggregator._resolve_probe_host_addresses") as mock_dns:
            mock_dns.return_value = ([ipaddress.ip_address("93.184.216.34")], None)
            yield mock_dns

    def test_url_check_budget_stays_below_duration_alarm_headroom(self):
        import status_aggregator as sa

        module_main = (Path(__file__).resolve().parents[1] / "main.tf").read_text()
        duration_alarm_seconds = 35
        dns_guard_seconds = sa.URL_CHECK_TIMEOUT_SECONDS
        ordinary_head_get_seconds = (
            dns_guard_seconds
            + sa.URL_CHECK_ATTEMPTS * sa.URL_CHECK_TIMEOUT_SECONDS * 2
            + max(sa.URL_CHECK_ATTEMPTS - 1, 0) * sa.URL_CHECK_RETRY_DELAY_SECONDS
        )
        range_reject_seconds = (
            dns_guard_seconds
            + sa.URL_CHECK_TIMEOUT_SECONDS * 3
        )

        assert "threshold          = 35000" in module_main
        assert "duration exceeds 35s" in module_main
        assert "initial DNS guard (5s)" in module_main
        assert "retryable HEAD->GET attempts (~25s)" in module_main
        assert "HEAD->range-GET->plain-GET fallback (~20s)" in module_main
        assert ordinary_head_get_seconds < duration_alarm_seconds
        assert range_reject_seconds < duration_alarm_seconds

    def test_range_reject_url_check_budget_stays_below_lambda_timeout(self):
        import status_aggregator as sa

        range_reject_seconds = (
            sa.URL_CHECK_TIMEOUT_SECONDS
            + sa.URL_CHECK_TIMEOUT_SECONDS * 3
        )

        assert range_reject_seconds < 45

    def test_terraform_url_limit_matches_worker_budget(self):
        import status_aggregator as sa

        variables_tf = Path(__file__).resolve().parents[1] / "variables.tf"

        assert (
            f"length(var.dependent_service_urls) <= {sa.URL_CHECK_MAX_WORKERS}"
            in variables_tf.read_text()
        )

    def test_frontend_names_status_feed_instead_of_api_gateway(self):
        module_root = Path(__file__).resolve().parents[1]
        main_tf = (module_root / "main.tf").read_text()
        index_html = (module_root / "frontend/index.html").read_text()

        assert 'status_feed_url          = "/status.json"' in main_tf
        assert 'meta name="status-feed-url"' in index_html
        assert 'STATUS_FEED_URL' in index_html
        assert "api-url" not in index_html
        assert "API_URL" not in index_html

    def test_frontend_public_windows_match_lambda_public_windows(self):
        import status_aggregator as sa

        index_html = (Path(__file__).resolve().parents[1] / "frontend/index.html").read_text()

        assert f"var HISTORY_DAYS = {sa.HISTORY_PUBLIC_DAYS};" in index_html
        assert f"var PAST_INCIDENT_DAYS = {sa.INCIDENT_PUBLIC_DAYS};" in index_html

    def test_frontend_snapshot_stale_threshold_follows_injected_cadence(self):
        index_html = (Path(__file__).resolve().parents[1] / "frontend/index.html").read_text()

        assert "var SNAPSHOT_STALE_THRESHOLD = MINUTES_PER_SAMPLE * 2 * 60 * 1000;" in index_html
        assert "var SNAPSHOT_STALE_THRESHOLD = 10 * 60 * 1000;" not in index_html

    def test_frontend_fully_operational_percentage_is_documented(self):
        module_root = Path(__file__).resolve().parents[1]
        index_html = (module_root / "frontend/index.html").read_text()
        readme = (module_root / "README.md").read_text()

        assert "+ '% fully operational'" in index_html
        assert '"fully operational"' in readme
        assert "operational / (operational + degraded + outage)" in readme
        assert "Amber degraded samples and\nred outage samples both reduce that percentage" in readme

    def test_frontend_overall_trusts_server_incident_rollup(self):
        index_html = (Path(__file__).resolve().parents[1] / "frontend/index.html").read_text()
        match = re.search(
            r"function renderOverall\(data, activeIncidents\) \{(?P<body>.*?)\n      \}",
            index_html,
            re.S,
        )

        assert match
        body = match.group("body")
        assert "status_aggregator._derive_incident_overall owns incident severity" in body
        assert "var overall = data.overall;" in body
        assert ".impact" not in body
        assert "'critical'" not in body

    def test_readme_http_status_mapping_matches_code(self):
        from status_aggregator import DEGRADED, MAJOR_OUTAGE, _status_for_http_code

        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        variables_tf = (Path(__file__).resolve().parents[1] / "variables.tf").read_text()

        assert _status_for_http_code(403) == DEGRADED
        assert _status_for_http_code(429) == DEGRADED
        assert _status_for_http_code(503) == MAJOR_OUTAGE
        assert "4xx = degraded immediately" in readme
        assert "auth-protected 401/403 responses\n  stay degraded" in readme
        assert "repeated 429 stays degraded\n  after the retry" in readme
        assert "repeated 429 responses report degraded" in variables_tf
        assert "repeated 5xx or\n  connection-level failure starts as degraded" in readme
        assert "A URL that alternates between hard failures\n  (5xx/unreachable) and reachable degraded responses (4xx)" in readme
        assert "produces two consecutive hard-fail snapshots" in readme
        assert "anything else after the retry = **major_outage**" not in readme

    def test_root_qurl_link_probe_uses_non_empty_index_html_url(self):
        repo_root = Path(__file__).resolve().parents[4]
        root_main = (repo_root / "terraform/main.tf").read_text()

        assert (
            'var.deploy_qurl_link && var.qurl_link_domain != null && var.qurl_link_domain != "" ? {'
            in root_main
        )
        assert 'qurl_link = "https://${var.qurl_link_domain}/index.html"' in root_main
        assert 'qurl_link = "https://${var.qurl_link_domain}/"' not in root_main
        assert "/index.html is expected to answer HEAD" in root_main
        assert "leaves this tile amber until the static surface is fixed" in root_main

    def test_readme_documents_qurl_link_head_probe_expectation(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()

        assert "qURL Link `/index.html` should answer HEAD with 2xx/3xx" in readme
        assert "GET fallback is a compatibility path" in readme
        assert "clean HEAD 2xx/3xx on `/index.html`" in readme

    def test_http_component_alarm_copy_mentions_unknown_status(self):
        module_main = (Path(__file__).resolve().parents[1] / "main.tf").read_text()
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        normalized = " ".join(readme.split())

        assert "unknown/gray" in module_main
        assert "reachable 4xx/degraded" in module_main
        assert "Lambda-side egress, DNS, or reachability failures" in normalized
        assert "persistently `unknown` probe URL pages even while the public tile stays gray" in normalized
        assert "display-only components still page after the three-snapshot alarm window" in normalized

    def test_cloudfront_error_fallback_preserves_not_found_status(self):
        module_main = (Path(__file__).resolve().parents[1] / "main.tf").read_text()
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()

        assert 'dynamic "custom_error_response"' in module_main
        assert "for_each = var.enable_nhp_auth ? [] : [1]" in module_main
        assert "error_code            = 403" in module_main
        assert "error_code            = 404" in module_main
        assert module_main.count('response_page_path    = "/index.html"') >= 2
        assert module_main.count("response_code         = 404") >= 2
        assert "loop-detection responses keep their cookie-domain diagnostic\nbody" in readme

    def test_readme_status_page_template_variables_match_frontend(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()

        assert "${status_feed_url}" in readme
        assert "${snapshot_cadence_minutes}" in readme
        assert "${api_url}" not in readme

    def test_api_gateway_alarm_copy_marks_compatibility_surface(self):
        module_main = (Path(__file__).resolve().parents[1] / "main.tf").read_text()

        assert "Compatibility /status API Gateway 5xx errors" in module_main
        assert "Viewers use CloudFront/S3 status.json" in module_main

    def test_readme_documents_compatibility_api_throttle_intent(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        module_main = (Path(__file__).resolve().parents[1] / "main.tf").read_text()
        normalized = " ".join(readme.split())

        assert "2 rps with a 3-request burst" in normalized
        assert "leaves two reserved-concurrency slots" in normalized
        assert "It is not the high-fanout polling path" in normalized
        assert "one shared global API Gateway budget across all direct callers" in normalized
        assert "viewers use CloudFront/S3 and supported pollers should do the same" in normalized
        assert "429s under direct API bursts are intentional protection" in normalized
        assert "same reserved-concurrency pool rather than allowing direct callers" in normalized
        assert "Five is intentional capacity math here" in normalized
        assert "three-request API burst can drain while two async slots remain" in normalized
        assert "A slow snapshot can hold one reserved-concurrency slot" in normalized
        assert "35s duration alarm is the early warning before timeout" in normalized
        assert "intentionally trades possible direct-API throttling" in normalized
        assert "Do not market this endpoint as a high-rate integration API" in normalized
        assert "review `reserved_concurrent_executions`, the API throttle" in normalized
        assert "compatibility API becomes a supported polling path" in normalized
        assert "snapshot-invocation-gap alarm" in normalized
        assert "overlays the latest sanitized incidents" in normalized
        assert "viewer traffic still reads only CloudFront/S3 `status.json`" in normalized
        assert "one-hour async event age is deliberate headroom" in normalized
        assert "maximum_event_age_in_seconds = 3600" in module_main
        assert "Five equals the API burst of three\n  # plus two async slots" in module_main
        assert "one-hour event age is intentional\n# headroom" in module_main

    def test_readme_documents_partial_target_health_read_tradeoff(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        normalized = " ".join(readme.split())

        assert "one active target-health read fails but another active group returns a healthy target" in normalized
        assert "public component remains operational by design" in normalized
        assert "CloudWatch alarms are the backstop for the unobserved group" in normalized
        assert "zero healthy described targets with read errors fail safe to `unknown`/`degraded`" in normalized

    def test_readme_documents_http_probe_trust_boundary(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        aggregator = (Path(__file__).resolve().parents[1] / "lambda/status_aggregator.py").read_text()
        normalized = " ".join(readme.split())

        assert "operator-owned public HTTPS endpoints" in normalized
        assert "not a private health-check relay" in normalized
        assert "rejecting non-HTTPS URLs, localhost, non-global IP literals" in normalized
        assert "hostnames that resolve to non-global addresses" in normalized
        assert "redirects outside that same public HTTPS boundary" in normalized
        assert "DNS resolution is a best-effort SSRF guard" in normalized
        assert "urllib still resolves again while connecting" in normalized
        assert "redirect validation resolves each redirect target again" in normalized
        assert "duplicate DNS work is intentional" in normalized
        assert "resolver work uses a shared DNS pool" in normalized
        assert "isolated from the URL probe pool" in normalized
        assert "URL fanout remains capped at 8" in normalized
        assert "do not wire user-supplied URLs" in normalized
        assert "operator-owned Terraform URLs, not a resolver for" in aggregator
        assert "DNS\n        # rebind after this validation remains possible" in aggregator
        assert "resolver stalls isolated from the URL probe pool" in aggregator
        assert "fanout is still bounded by URL_CHECK_MAX_WORKERS" in aggregator

    def test_status_json_cache_policy_caps_incident_staleness_to_sixty_seconds(self):
        module_root = Path(__file__).resolve().parents[1]
        readme = (module_root / "README.md").read_text()
        main_tf = (module_root / "main.tf").read_text()
        aggregator = (module_root / "lambda/status_aggregator.py").read_text()
        normalized = " ".join(readme.split())

        assert "default_ttl = 60" in main_tf
        assert "max_ttl     = 60" in main_tf
        assert 'cache_control = "public, max-age=60"' in main_tf
        assert 'CacheControl="public, max-age=60"' in aggregator
        assert "`status.json` object `Cache-Control` all cap edge caching at 60 seconds" in normalized
        assert "Incident uploads update the S3 read model immediately" in normalized
        assert "previous edge copy until that TTL expires" in normalized

    def test_module_rejects_display_only_ids_without_configured_component(self):
        module_main = (Path(__file__).resolve().parents[1] / "main.tf").read_text()
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()

        assert "unknown_display_only_component_ids = setsubtract" in module_main
        assert "var.display_only_component_ids" in module_main
        assert "toset(keys(var.dependent_service_urls))" in module_main
        assert "display_only_component_ids must reference configured dependent_service_urls" in module_main
        assert "Terraform rejects display-only\nids that are not configured HTTP components" in readme

    def test_public_surface_guard_explains_single_inline_block_limit(self, capsys):
        guard = _load_public_surface_guard()

        html = "<script>one()</script><script>two()</script>"
        with pytest.raises(SystemExit):
            guard._single_inline_block(html, "script")

        assert "found 2 total <script> tags and 2 inline blocks" in capsys.readouterr().err

    def test_public_surface_guard_rejects_external_script_tags(self, capsys):
        guard = _load_public_surface_guard()

        html = '<script src="/status.js"></script><script>boot()</script>'
        with pytest.raises(SystemExit):
            guard._single_inline_block(html, "script")

        assert "found 2 total <script> tags and 1 inline blocks" in capsys.readouterr().err

    def test_status_page_alarm_describe_wildcard_is_documented(self):
        module_main = (Path(__file__).resolve().parents[1] / "main.tf").read_text()

        assert "DescribeAlarms does not support resource-level IAM scoping" in module_main
        assert "redact alarm names before publishing status" in module_main

    def test_public_surface_guard_skips_comments_and_rejects_heredocs(self, capsys):
        guard = _load_public_surface_guard()
        main_tf = '''
resource "example_resource" "status" {
  # comment braces must not close the resource: }}} " <<NOPE
  policy = jsonencode({
    Resource = "{literal}"
  })
}
'''

        block = guard._terraform_resource_block(main_tf, "example_resource", "status")

        assert "Resource" in block

        with pytest.raises(SystemExit):
            guard._terraform_resource_block(
                'resource "example_resource" "status" {\n  policy = <<EOT\n{}\nEOT\n}\n',
                "example_resource",
                "status",
            )

        assert "contains heredoc syntax" in capsys.readouterr().err

    def test_readme_documents_unknown_component_rollup_intent(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        normalized = " ".join(readme.split())

        assert "unknown` component statuses render as gray tiles" in normalized
        assert "surface the headline as unknown" in normalized
        assert "known degraded/outage signal still takes precedence" in normalized

    def test_readme_documents_range_fallback_timeout_budget(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        normalized_readme = " ".join(readme.split())
        module_main = (Path(__file__).resolve().parents[1] / "main.tf").read_text()

        assert "under the 35s Lambda duration alarm" in normalized_readme
        assert "even with the DNS guard" in normalized_readme
        assert "range-reject plain-GET fallback" in normalized_readme
        assert "range-reject plain-GET fallback is not retried" in normalized_readme
        assert "ordinary per-URL HEAD-to-GET retry budget" in normalized_readme
        assert "retryable HEAD->GET attempts (~25s)" in module_main
        assert "non-retried 416\n  # HEAD->range-GET->plain-GET fallback (~20s)" in module_main
        assert "leaves 10s before the function timeout." in module_main

    def test_readme_documents_history_recovery_and_initial_snapshot_alarm_noise(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
        normalized = " ".join(readme.split())

        assert "history.json` becomes malformed" in readme
        assert "status.json` remains current" in readme
        assert "Snapshots write `status.json` before private `history.json`" in readme
        assert "EventBridge retry cannot\ndouble-count that bucket" in readme
        assert "history.json` before `status.json`" not in readme
        assert "starts a fresh history window" in normalized
        assert "brand-new history file" in normalized
        assert "first hard HTTP outage sample is likewise counted as degraded" in normalized
        assert "intentionally slightly optimistic for one snapshot" in normalized
        assert "up to two snapshot intervals" in normalized
        assert "about 10 minutes at the default cadence" in normalized
        assert "invocation-gap\nalarm treats missing data as breaching" in readme
        assert "first three scheduled snapshots land" in readme
        assert "If `DescribeAlarms` fails" in readme
        assert "target-group health remains the primary\n  signal" in readme

    def test_rollout_ledger_documents_status_page_alarm_and_history_recovery(self):
        repo_root = Path(__file__).resolve().parents[4]
        ledger = (
            repo_root
            / "docs/runbooks/prod-rollout-ledger/2026-06-10-pr-2457-public-status-page.md"
        ).read_text()
        normalized = " ".join(ledger.split())

        assert "first three scheduled snapshots land" in ledger
        assert "initial deploy-time ALARM state\n      is expected" in ledger
        assert "confirm prod Lambda account concurrency headroom" in ledger
        assert "reserves 5 executions" in ledger
        assert "confirmed status-probe UA/WAF reachability on 2026-07-08" in ledger
        assert "LayerV-StatusPage/2.0" in ledger
        assert "ranged GET 200" in ledger
        assert "public `qurl_link` tile is green" in ledger
        assert "display-only `website` tile is green" in ledger
        assert "LayerV-StatusPage/2.0` Lambda user agent" in ledger
        assert "sustained probe failure still pages\n      the NHP on-call" in ledger
        assert "HEAD or ranged/plain GET 2xx/3xx" in normalized
        assert "malformed `history.json`" in ledger
        assert "current status publication continues" in normalized

    def test_status_aggregator_archive_file_zip_is_gitignored(self):
        repo_root = Path(__file__).resolve().parents[4]
        gitignore = (repo_root / ".gitignore").read_text()
        module_main = (Path(__file__).resolve().parents[1] / "main.tf").read_text()

        assert 'output_path = "${path.module}/lambda/status_aggregator.zip"' in module_main
        assert "terraform/**/*.zip" in gitignore

    def test_readme_documents_infra_debounce_intent(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()

        assert "target-group health\nchecks and CloudWatch alarms are already smoothed" in readme
        assert "An intervening `unknown` HTTP probe does not clear" in readme
        assert "the public status\ncan publish red for that snapshot cadence" in readme

    def test_status_bucket_lifecycle_aborts_incomplete_uploads(self):
        module_main = (Path(__file__).resolve().parents[1] / "main.tf").read_text()

        assert "abort_incomplete_multipart_upload" in module_main
        assert "days_after_initiation = 1" in module_main

    def test_service_url_map_parses_json(self):
        from status_aggregator import _service_url_map

        with patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '{"qurl_api":"https://api.example.com/health"}'}):
            assert _service_url_map() == {"qurl_api": "https://api.example.com/health"}

    def test_service_url_map_rejects_invalid_json(self):
        from status_aggregator import _service_url_map

        with patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": "not json"}):
            assert _service_url_map() == {}

    def test_service_url_map_rejects_non_dict_json(self):
        from status_aggregator import _service_url_map

        with patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '["https://api.example.com"]'}):
            assert _service_url_map() == {}

    def test_service_url_map_filters_non_string_values(self):
        from status_aggregator import _service_url_map

        with patch.dict(os.environ, {
            "DEPENDENT_SERVICE_URLS": json.dumps({
                "qurl_api": "https://api.example.com/health",
                "broken": 42,
                "missing": None,
            }),
        }), patch("builtins.print") as mock_print:
            assert _service_url_map() == {
                "qurl_api": "https://api.example.com/health",
            }

        assert mock_print.call_count == 2
        assert all(
            "Ignoring invalid DEPENDENT_SERVICE_URLS entry" in call.args[0]
            for call in mock_print.call_args_list
        )

    def test_check_url_invalid_url_returns_unknown_without_network(self):
        from status_aggregator import UNKNOWN, _check_url

        with patch("status_aggregator._urlopen") as mock_urlopen, \
                patch("builtins.print") as mock_print:
            assert _check_url("not-a-url") == UNKNOWN

        mock_urlopen.assert_not_called()
        assert any("Invalid service URL: not-a-url" in call.args[0] for call in mock_print.call_args_list)

    def test_check_url_rejects_non_https_and_link_local_without_network(self):
        from status_aggregator import UNKNOWN, _check_url

        with patch("status_aggregator._urlopen") as mock_urlopen:
            assert _check_url("http://api.example.com/health") == UNKNOWN
            assert _check_url("https://169.254.169.254/latest/meta-data/") == UNKNOWN
            assert _check_url("https://localhost/health") == UNKNOWN

        mock_urlopen.assert_not_called()

    def test_check_url_rejects_hostname_that_resolves_private_without_network(self, _mock_probe_dns):
        from status_aggregator import UNKNOWN, _check_url

        _mock_probe_dns.return_value = ([ipaddress.ip_address("10.0.0.5")], None)

        with patch("status_aggregator._urlopen") as mock_urlopen:
            assert _check_url("https://internal.example.com/health") == UNKNOWN

        mock_urlopen.assert_not_called()

    def test_safe_redirect_handler_rejects_unsafe_redirect_targets(self, _mock_probe_dns):
        import urllib.error
        import status_aggregator as sa

        handler = sa._SafeRedirectHandler()

        with pytest.raises(urllib.error.URLError, match="unsafe redirect target"):
            handler.redirect_request(None, None, 302, "Found", {}, "http://api.example.com/")

        with pytest.raises(urllib.error.URLError, match="unsafe redirect target"):
            handler.redirect_request(None, None, 302, "Found", {}, "https://127.0.0.1/")

        with pytest.raises(urllib.error.URLError, match="unsafe redirect target"):
            handler.redirect_request(None, None, 302, "Found", {}, "https://169.254.169.254/")

        _mock_probe_dns.return_value = ([ipaddress.ip_address("10.0.0.5")], None)
        with pytest.raises(urllib.error.URLError, match="unsafe redirect target"):
            handler.redirect_request(None, None, 302, "Found", {}, "https://internal.example.com/")

    def test_readme_documents_incident_impact_banner_mapping_for_runbooks(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()

        assert (
            "describe `critical` as the only incident impact that turns the\n  public banner red"
            in readme
        )
        assert "For operator UX, `impact: \"critical\"` is the only incident impact" in readme
        assert 'Do not use `major` when the intended public headline is\n  "Service disruption"' in readme
        assert "`major` remains amber by design" in readme

    @patch("status_aggregator._urlopen")
    def test_check_url_operational_on_2xx(self, mock_urlopen):
        from status_aggregator import OPERATIONAL, _check_url

        resp = MagicMock()
        resp.getcode.return_value = 204
        mock_urlopen.return_value.__enter__.return_value = resp

        assert _check_url("https://api.example.com/health") == OPERATIONAL

    @patch("status_aggregator._urlopen")
    def test_check_url_operational_on_3xx(self, mock_urlopen):
        from status_aggregator import OPERATIONAL, _check_url

        resp = MagicMock()
        resp.getcode.return_value = 302
        mock_urlopen.return_value.__enter__.return_value = resp

        assert _check_url("https://status.example.com/") == OPERATIONAL

    @patch("status_aggregator._urlopen")
    def test_check_url_falls_back_to_get_when_head_unsupported(self, mock_urlopen):
        import urllib.error
        from status_aggregator import OPERATIONAL, _check_url

        resp = MagicMock()
        resp.getcode.return_value = 204
        get_response = MagicMock()
        get_response.__enter__.return_value = resp
        mock_urlopen.side_effect = [
            urllib.error.HTTPError(
                "https://api.example.com/health",
                405,
                "Method Not Allowed",
                {},
                None,
            ),
            get_response,
        ]

        assert _check_url("https://api.example.com/health") == OPERATIONAL
        assert [call.args[0].get_method() for call in mock_urlopen.call_args_list] == ["HEAD", "GET"]
        assert mock_urlopen.call_args_list[1].args[0].headers["Range"] == "bytes=0-0"

    @patch("status_aggregator._urlopen")
    def test_check_url_falls_back_to_get_when_head_is_rejected(self, mock_urlopen):
        import urllib.error
        from status_aggregator import OPERATIONAL, _check_url

        resp = MagicMock()
        resp.getcode.return_value = 200
        get_response = MagicMock()
        get_response.__enter__.return_value = resp
        mock_urlopen.side_effect = [
            urllib.error.HTTPError(
                "https://api.example.com/health",
                403,
                "Forbidden",
                {},
                None,
            ),
            get_response,
        ]

        assert _check_url("https://api.example.com/health") == OPERATIONAL
        assert [call.args[0].get_method() for call in mock_urlopen.call_args_list] == ["HEAD", "GET"]

    @patch("status_aggregator._urlopen")
    def test_check_url_retries_plain_get_when_range_rejected(self, mock_urlopen):
        import urllib.error
        from status_aggregator import OPERATIONAL, _check_url

        resp = MagicMock()
        resp.getcode.return_value = 200
        get_response = MagicMock()
        get_response.__enter__.return_value = resp
        mock_urlopen.side_effect = [
            urllib.error.HTTPError(
                "https://static.example.com/index.html",
                405,
                "Method Not Allowed",
                {},
                None,
            ),
            urllib.error.HTTPError(
                "https://static.example.com/index.html",
                416,
                "Range Not Satisfiable",
                {},
                None,
            ),
            get_response,
        ]

        assert _check_url("https://static.example.com/index.html") == OPERATIONAL
        assert [call.args[0].get_method() for call in mock_urlopen.call_args_list] == ["HEAD", "GET", "GET"]
        assert mock_urlopen.call_args_list[1].args[0].headers["Range"] == "bytes=0-0"
        assert "Range" not in mock_urlopen.call_args_list[2].args[0].headers
        assert all(call.args[0].headers["Connection"] == "close" for call in mock_urlopen.call_args_list)

    @patch("status_aggregator.time.sleep")
    @patch("status_aggregator._urlopen")
    def test_check_url_does_not_retry_after_range_rejected_plain_get_failure(
        self, mock_urlopen, mock_sleep
    ):
        import urllib.error
        from status_aggregator import MAJOR_OUTAGE, _check_url

        mock_urlopen.side_effect = [
            urllib.error.HTTPError(
                "https://static.example.com/index.html",
                405,
                "Method Not Allowed",
                {},
                None,
            ),
            urllib.error.HTTPError(
                "https://static.example.com/index.html",
                416,
                "Range Not Satisfiable",
                {},
                None,
            ),
            urllib.error.HTTPError(
                "https://static.example.com/index.html",
                503,
                "Service Unavailable",
                {},
                None,
            ),
        ]

        assert _check_url("https://static.example.com/index.html") == MAJOR_OUTAGE
        assert [call.args[0].get_method() for call in mock_urlopen.call_args_list] == [
            "HEAD",
            "GET",
            "GET",
        ]
        assert mock_urlopen.call_args_list[1].args[0].headers["Range"] == "bytes=0-0"
        assert "Range" not in mock_urlopen.call_args_list[2].args[0].headers
        mock_sleep.assert_not_called()

    @patch("status_aggregator._urlopen")
    def test_open_health_url_reraises_server_error_without_get_fallback(self, mock_urlopen):
        import urllib.error
        from status_aggregator import _open_health_url

        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://api.example.com/health",
            503,
            "Service Unavailable",
            {},
            None,
        )

        with pytest.raises(urllib.error.HTTPError):
            _open_health_url("https://api.example.com/health")

        mock_urlopen.assert_called_once()
        assert mock_urlopen.call_args.args[0].get_method() == "HEAD"

    @patch("status_aggregator.time.sleep")
    @patch("status_aggregator._urlopen", side_effect=RuntimeError("down"))
    def test_check_url_outage_after_unreachable_retry(self, _mock_urlopen, _mock_sleep):
        from status_aggregator import MAJOR_OUTAGE, _check_url

        with patch("builtins.print") as mock_print:
            assert _check_url("https://api.example.com/health") == MAJOR_OUTAGE

        assert any(
            "Service URL check failed after 2 attempts for api.example.com/health: RuntimeError"
            in call.args[0]
            for call in mock_print.call_args_list
        )

    @patch("status_aggregator.time.sleep")
    @patch("status_aggregator._urlopen")
    def test_check_url_degraded_without_retry_for_client_error(self, mock_urlopen, mock_sleep):
        import urllib.error
        from status_aggregator import DEGRADED, _check_url

        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://api.example.com/health",
            404,
            "Not Found",
            {},
            None,
        )

        with patch("builtins.print") as mock_print:
            assert _check_url("https://api.example.com/health") == DEGRADED

        mock_sleep.assert_not_called()
        assert any(
            "Service URL check failed after 1 attempts for api.example.com/health: HTTP 404"
            in call.args[0]
            for call in mock_print.call_args_list
        )

    @patch("status_aggregator.time.sleep")
    @patch("status_aggregator._urlopen")
    def test_check_url_retries_rate_limit_response(self, mock_urlopen, mock_sleep):
        import urllib.error
        from status_aggregator import DEGRADED, _check_url

        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://api.example.com/health",
            429,
            "Too Many Requests",
            {},
            None,
        )

        assert _check_url("https://api.example.com/health") == DEGRADED
        assert mock_urlopen.call_count == 2
        mock_sleep.assert_called_once()

    @patch("status_aggregator.time.sleep")
    @patch("status_aggregator._urlopen")
    def test_check_url_outage_after_bad_http_status_retry(self, mock_urlopen, _mock_sleep):
        import urllib.error
        from status_aggregator import MAJOR_OUTAGE, _check_url

        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://api.example.com/health",
            503,
            "Service Unavailable",
            {},
            None,
        )

        assert _check_url("https://api.example.com/health") == MAJOR_OUTAGE


class TestBuildComponents:
    def test_builds_infra_and_http_components(self):
        import status_aggregator as sa

        with patch.object(sa, "_get_alarm_summary", return_value={"server_active": False, "ac_active": True}), \
                patch.object(sa, "_aggregate_target_health", side_effect=[
                    _health(2, 0, 2),
                    _health(1, 0, 1),
                ]), \
                patch.object(sa, "_check_url", return_value=sa.OPERATIONAL), \
                patch.object(sa.cloudwatch, "put_metric_data"), \
                patch.dict(os.environ, {
                    "DEPENDENT_SERVICE_URLS": '{"qurl_api":"https://api.example.com/health"}',
                    "SERVER_NLB_TG_ARNS": "arn:server",
                    "AC_NLB_TG_ARNS": "arn:ac",
                }):
            components = sa.build_components()

        assert components == [
            {"id": "nhp_server", "status": sa.OPERATIONAL},
            {"id": "nhp_ac", "status": sa.DEGRADED},
            {"id": "qurl_api", "status": sa.OPERATIONAL},
        ]

    def test_build_components_publishes_http_component_metrics(self):
        import status_aggregator as sa

        def check_url(url):
            return {
                "https://api.example.com/health": sa.DEGRADED,
                "https://qurl.example.com/index.html": sa.OPERATIONAL,
                "not-a-url": sa.UNKNOWN,
            }[url]

        with patch.object(sa, "_get_alarm_summary", return_value={"server_active": False, "ac_active": False}), \
                patch.object(sa, "_check_url", side_effect=check_url), \
                patch.object(sa.cloudwatch, "put_metric_data") as put_metric_data, \
                patch.dict(os.environ, {
                    "ENVIRONMENT": "sandbox",
                    "DEPENDENT_SERVICE_URLS": json.dumps({
                        "qurl_api": "https://api.example.com/health",
                        "qurl_link": "https://qurl.example.com/index.html",
                        "website": "not-a-url",
                    }),
                    "SERVER_NLB_TG_ARNS": "",
                    "AC_NLB_TG_ARNS": "",
                }):
            components = sa.build_components()

        assert components == [
            {"id": "nhp_server", "status": sa.UNKNOWN},
            {"id": "nhp_ac", "status": sa.UNKNOWN},
            {"id": "qurl_api", "status": sa.DEGRADED},
            {"id": "qurl_link", "status": sa.OPERATIONAL},
            {"id": "website", "status": sa.UNKNOWN},
        ]
        put_metric_data.assert_called_once()
        call = put_metric_data.call_args.kwargs
        assert call["Namespace"] == sa.STATUS_METRIC_NAMESPACE
        values = {
            next(
                dim["Value"]
                for dim in metric["Dimensions"]
                if dim["Name"] == "ComponentId"
            ): metric["Value"]
            for metric in call["MetricData"]
        }
        assert values == {"qurl_api": 1, "qurl_link": 0, "website": 1}
        assert all(
            {"Name": "Environment", "Value": "sandbox"} in metric["Dimensions"]
            for metric in call["MetricData"]
        )

    def test_active_alarm_keeps_infra_component_visible_without_target_groups(self):
        import status_aggregator as sa

        with patch.object(sa, "_get_alarm_summary", return_value={"server_active": True, "ac_active": False}), \
                patch.dict(os.environ, {
                    "SERVER_NLB_TG_ARNS": "",
                    "SERVER_NLB_TG_ARNS_BY_COLOR": "{}",
                    "SERVER_ACTIVE_COLOR_PARAMETER": "",
                    "AC_NLB_TG_ARNS": "",
                    "AC_NLB_TG_ARNS_BY_COLOR": "{}",
                    "AC_ACTIVE_COLOR_PARAMETER": "",
                    "DEPENDENT_SERVICE_URLS": "{}",
                }):
            components = sa.build_components()

        assert components == [
            {"id": "nhp_server", "status": sa.DEGRADED},
            {"id": "nhp_ac", "status": sa.UNKNOWN},
        ]

    @patch("status_aggregator.ssm")
    def test_active_color_read_error_keeps_component_unknown(self, mock_ssm):
        import status_aggregator as sa

        mock_ssm.get_parameter.side_effect = RuntimeError("ssm unavailable")

        with patch.object(sa, "_get_alarm_summary", return_value={"server_active": False, "ac_active": False}), \
                patch.dict(os.environ, {
                    "SERVER_NLB_TG_ARNS": "",
                    "SERVER_NLB_TG_ARNS_BY_COLOR": "{}",
                    "SERVER_ACTIVE_COLOR_PARAMETER": "",
                    "AC_NLB_TG_ARNS": "arn:blue,arn:green",
                    "AC_NLB_TG_ARNS_BY_COLOR": '{"blue":["arn:blue"],"green":["arn:green"]}',
                    "AC_ACTIVE_COLOR_PARAMETER": "/sandbox/nhp/ac/active-color",
                    "DEPENDENT_SERVICE_URLS": "{}",
                }), patch("builtins.print"):
            components = sa.build_components()

        assert components == [
            {"id": "nhp_server", "status": sa.UNKNOWN},
            {"id": "nhp_ac", "status": sa.UNKNOWN},
        ]

    @patch("status_aggregator.ssm")
    def test_active_color_with_no_configured_target_groups_keeps_component_unknown(self, mock_ssm):
        import status_aggregator as sa

        mock_ssm.get_parameter.return_value = {"Parameter": {"Value": "green"}}

        with patch.object(sa, "_get_alarm_summary", return_value={"server_active": False, "ac_active": False}), \
                patch.dict(os.environ, {
                    "SERVER_NLB_TG_ARNS": "",
                    "SERVER_NLB_TG_ARNS_BY_COLOR": "{}",
                    "SERVER_ACTIVE_COLOR_PARAMETER": "",
                    "AC_NLB_TG_ARNS": "arn:blue",
                    "AC_NLB_TG_ARNS_BY_COLOR": '{"blue":["arn:blue"],"green":[]}',
                    "AC_ACTIVE_COLOR_PARAMETER": "/sandbox/nhp/ac/active-color",
                    "DEPENDENT_SERVICE_URLS": "{}",
                }), patch("builtins.print") as mock_print:
            components = sa.build_components()

        assert components == [
            {"id": "nhp_server", "status": sa.UNKNOWN},
            {"id": "nhp_ac", "status": sa.UNKNOWN},
        ]
        assert any("has no configured ac target groups" in call.args[0] for call in mock_print.call_args_list)


class TestOverall:
    def test_overall_uses_worst_known_status(self):
        import status_aggregator as sa

        assert sa._derive_overall([{"status": sa.OPERATIONAL}, {"status": sa.DEGRADED}]) == sa.DEGRADED
        assert sa._derive_overall([{"status": sa.UNKNOWN}, {"status": sa.OPERATIONAL}]) == sa.UNKNOWN
        assert sa._derive_overall([{"status": sa.UNKNOWN}]) == sa.UNKNOWN
        assert sa._derive_overall([]) == sa.UNKNOWN

    def test_known_degraded_signal_takes_precedence_over_unknown(self):
        import status_aggregator as sa

        assert sa._derive_overall([{"status": sa.UNKNOWN}, {"status": sa.DEGRADED}]) == sa.DEGRADED

    def test_http_component_major_outage_escalates_overall(self):
        import status_aggregator as sa

        components = [
            {"id": "nhp_server", "status": sa.OPERATIONAL},
            {"id": "qurl_link", "status": sa.MAJOR_OUTAGE},
        ]

        assert sa._derive_overall(components) == sa.MAJOR_OUTAGE

    def test_display_only_component_does_not_escalate_overall(self):
        import status_aggregator as sa

        components = [
            {"id": "qurl_api", "status": sa.OPERATIONAL},
            {"id": "website", "status": sa.MAJOR_OUTAGE},
        ]

        assert sa._derive_overall(components) == sa.OPERATIONAL

    def test_display_only_component_ids_come_from_env(self):
        import status_aggregator as sa

        components = [
            {"id": "qurl_api", "status": sa.OPERATIONAL},
            {"id": "docs", "status": sa.MAJOR_OUTAGE},
        ]

        with patch.dict(os.environ, {"DISPLAY_ONLY_COMPONENT_IDS": "website,docs"}):
            assert sa._derive_overall(components) == sa.OPERATIONAL

    def test_empty_display_only_env_means_no_display_only_components(self):
        import status_aggregator as sa

        components = [
            {"id": "qurl_api", "status": sa.OPERATIONAL},
            {"id": "website", "status": sa.MAJOR_OUTAGE},
        ]

        with patch.dict(os.environ, {"DISPLAY_ONLY_COMPONENT_IDS": ""}):
            assert sa._derive_overall(components) == sa.MAJOR_OUTAGE

    def test_active_incidents_escalate_overall(self):
        import status_aggregator as sa

        components = [{"id": "qurl_api", "status": sa.OPERATIONAL}]

        assert sa._derive_overall(components, [{"status": "identified", "impact": "major"}]) == sa.DEGRADED
        assert sa._derive_overall(components, [{"status": "identified", "impact": "critical"}]) == sa.MAJOR_OUTAGE
        assert sa._derive_overall([{"id": "qurl_api", "status": sa.UNKNOWN}], [
            {"status": "investigating", "impact": "minor"},
        ]) == sa.DEGRADED
        assert sa._derive_overall([{"id": "qurl_api", "status": sa.DEGRADED}], [
            {"status": "identified", "impact": "critical"},
        ]) == sa.MAJOR_OUTAGE
        assert sa._derive_overall(components, [{"status": "resolved", "impact": "critical"}]) == sa.OPERATIONAL

    def test_incidents_without_allowed_impact_do_not_escalate_overall(self):
        import status_aggregator as sa

        components = [{"id": "qurl_api", "status": sa.OPERATIONAL}]

        assert sa._derive_overall(components, [{"status": "identified"}]) == sa.OPERATIONAL
        assert sa._derive_overall(components, [{"status": "identified", "impact": "catastrophic"}]) == sa.OPERATIONAL

    def test_incident_overall_reuses_sanitizer_impact_set(self):
        import inspect
        import status_aggregator as sa

        source = inspect.getsource(sa._derive_incident_overall)

        assert "impact not in _INCIDENT_IMPACTS" in source

    def test_build_public_status_overall_includes_incidents(self):
        import status_aggregator as sa

        payload = sa.build_public_status(
            components=[{"id": "qurl_api", "status": sa.OPERATIONAL}],
            history_raw={"days": {}},
            incidents_raw={"incidents": [{
                "id": "incident-1",
                "title": "Critical incident",
                "status": "identified",
                "impact": "critical",
                "started_at": "2026-07-06T20:00:00Z",
            }]},
        )

        assert payload["overall"] == sa.MAJOR_OUTAGE

    def test_build_public_status_docstring_warns_live_checks_emit_metrics(self):
        import status_aggregator as sa

        assert "components=None runs live component checks" in sa.build_public_status.__doc__
        assert "emits HTTP component metrics" in sa.build_public_status.__doc__

    def test_build_public_status_marks_display_only_components(self):
        import status_aggregator as sa

        with patch.dict(os.environ, {"DISPLAY_ONLY_COMPONENT_IDS": "website"}):
            payload = sa.build_public_status(
                components=[
                    {"id": "qurl_api", "status": sa.OPERATIONAL},
                    {"id": "website", "status": sa.MAJOR_OUTAGE},
                ],
                history_raw={"days": {}},
                incidents_raw={"incidents": []},
            )

        assert payload["overall"] == sa.OPERATIONAL
        assert payload["components"] == [
            {"id": "qurl_api", "status": sa.OPERATIONAL, "display_only": False},
            {"id": "website", "status": sa.MAJOR_OUTAGE, "display_only": True},
        ]


class TestHistorySnapshots:
    def test_record_snapshot_creates_history_and_skips_unknown(self):
        import status_aggregator as sa

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.OPERATIONAL},
            {"id": "qurl_link", "status": sa.DEGRADED},
            {"id": "nhp_server", "status": sa.UNKNOWN},
        ]), patch.object(sa, "_load_json", return_value=None), patch.object(sa.s3, "put_object") as put_object:
            history = sa.record_snapshot()

        assert history["version"] == 1
        assert history["days"][_today_key()]["qurl_api"] == [1, 0, 0]
        assert history["days"][_today_key()]["qurl_link"] == [0, 1, 0]
        assert "nhp_server" not in history["days"][_today_key()]
        assert put_object.call_count == 2

        calls = {call.kwargs["Key"]: call.kwargs for call in put_object.call_args_list}
        assert json.loads(calls[sa.HISTORY_KEY]["Body"]) == history
        status = json.loads(calls[sa.STATUS_KEY]["Body"])
        assert status["overall"] == sa.DEGRADED
        assert status["components"] == [
            {"id": "qurl_api", "status": sa.OPERATIONAL, "display_only": False},
            {"id": "qurl_link", "status": sa.DEGRADED, "display_only": False},
            {"id": "nhp_server", "status": sa.UNKNOWN, "display_only": False},
        ]
        assert status["history"] == {_today_key(): {
            "qurl_api": [1, 0, 0],
            "qurl_link": [0, 1, 0],
        }}
        assert calls[sa.STATUS_KEY]["CacheControl"] == "public, max-age=60"
        assert [call.kwargs["Key"] for call in put_object.call_args_list] == [
            sa.STATUS_KEY,
            sa.HISTORY_KEY,
        ]

    def test_record_snapshot_does_not_advance_history_when_status_write_fails(self):
        import status_aggregator as sa

        def put_object(**kwargs):
            if kwargs["Key"] == sa.STATUS_KEY:
                raise RuntimeError("status write failure")
            raise AssertionError(f"unexpected write to {kwargs['Key']}")

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.OPERATIONAL},
        ]), patch.object(sa, "_load_json", return_value=None), \
                patch.object(sa.s3, "put_object", side_effect=put_object) as mock_put:
            with pytest.raises(RuntimeError, match="status write failure"):
                sa.record_snapshot()

        assert [call.kwargs["Key"] for call in mock_put.call_args_list] == [
            sa.STATUS_KEY,
        ]

    def test_record_snapshot_debounces_first_http_outage(self):
        import status_aggregator as sa

        def load(key, missing_ok=True, **_kwargs):
            return {
                sa.HISTORY_KEY: {"version": 1, "days": {}},
                sa.INCIDENTS_KEY: {"incidents": []},
            }.get(key)

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.MAJOR_OUTAGE},
            {"id": "nhp_server", "status": sa.MAJOR_OUTAGE},
        ]), patch.object(sa, "_load_json", side_effect=load), \
                patch.object(sa.s3, "put_object") as put_object, \
                patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '{"qurl_api":"https://api.example.com/health"}'}):
            history = sa.record_snapshot()

        calls = {call.kwargs["Key"]: call.kwargs for call in put_object.call_args_list}
        status = json.loads(calls[sa.STATUS_KEY]["Body"])
        assert status["components"] == [
            {"id": "qurl_api", "status": sa.DEGRADED, "display_only": False},
            {"id": "nhp_server", "status": sa.MAJOR_OUTAGE, "display_only": False},
        ]
        assert history["days"][_today_key()]["qurl_api"] == [0, 1, 0]
        assert history["days"][_today_key()]["nhp_server"] == [0, 0, 1]
        assert history[sa.HTTP_RAW_STATUS_HISTORY_KEY] == {
            "qurl_api": sa.MAJOR_OUTAGE,
        }
        assert history[sa.HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY] == {
            "qurl_api": True,
        }
        assert sa.HTTP_RAW_STATUS_HISTORY_KEY not in status
        assert sa.HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY not in status
        assert sa.HTTP_RAW_STATUS_HISTORY_KEY not in status["history"]
        assert sa.HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY not in status["history"]
        assert sa.HTTP_RAW_STATUS_HISTORY_KEY not in calls[sa.STATUS_KEY]["Body"]
        assert sa.HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY not in calls[sa.STATUS_KEY]["Body"]

    def test_record_snapshot_escalates_repeated_http_outage(self):
        import status_aggregator as sa

        previous_history = {
            "version": 1,
            "days": {},
            sa.HTTP_RAW_STATUS_HISTORY_KEY: {"qurl_api": sa.MAJOR_OUTAGE},
        }

        def load(key, missing_ok=True, **_kwargs):
            return {
                sa.HISTORY_KEY: previous_history,
                sa.INCIDENTS_KEY: {"incidents": []},
            }.get(key)

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.MAJOR_OUTAGE},
        ]), patch.object(sa, "_load_json", side_effect=load), \
                patch.object(sa.s3, "put_object") as put_object, \
                patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '{"qurl_api":"https://api.example.com/health"}'}):
            history = sa.record_snapshot()

        calls = {call.kwargs["Key"]: call.kwargs for call in put_object.call_args_list}
        status = json.loads(calls[sa.STATUS_KEY]["Body"])
        assert status["components"] == [
            {"id": "qurl_api", "status": sa.MAJOR_OUTAGE, "display_only": False},
        ]
        assert history["days"][_today_key()]["qurl_api"] == [0, 0, 1]

    def test_record_snapshot_debounces_after_previous_raw_http_degraded(self):
        import status_aggregator as sa

        previous_history = {
            "version": 1,
            "days": {},
            sa.HTTP_RAW_STATUS_HISTORY_KEY: {"qurl_api": sa.DEGRADED},
        }

        def load(key, missing_ok=True, **_kwargs):
            return {
                sa.HISTORY_KEY: previous_history,
                sa.INCIDENTS_KEY: {"incidents": []},
            }.get(key)

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.MAJOR_OUTAGE},
        ]), patch.object(sa, "_load_json", side_effect=load), \
                patch.object(sa.s3, "put_object") as put_object, \
                patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '{"qurl_api":"https://api.example.com/health"}'}):
            history = sa.record_snapshot()

        calls = {call.kwargs["Key"]: call.kwargs for call in put_object.call_args_list}
        status = json.loads(calls[sa.STATUS_KEY]["Body"])
        assert status["components"] == [
            {"id": "qurl_api", "status": sa.DEGRADED, "display_only": False},
        ]
        assert history["days"][_today_key()]["qurl_api"] == [0, 1, 0]
        assert history[sa.HTTP_RAW_STATUS_HISTORY_KEY] == {
            "qurl_api": sa.MAJOR_OUTAGE,
        }

    def test_record_snapshot_escalates_after_two_real_http_outages(self):
        import status_aggregator as sa

        objects = {
            sa.HISTORY_KEY: {"version": 1, "days": {}},
            sa.INCIDENTS_KEY: {"incidents": []},
        }

        def load(key, missing_ok=True, **_kwargs):
            return objects.get(key)

        def put_object(**kwargs):
            objects[kwargs["Key"]] = json.loads(kwargs["Body"])

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.MAJOR_OUTAGE},
        ]), patch.object(sa, "_load_json", side_effect=load), \
                patch.object(sa.s3, "put_object", side_effect=put_object), \
                patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '{"qurl_api":"https://api.example.com/health"}'}):
            first_history = sa.record_snapshot()
            first_status = objects[sa.STATUS_KEY]
            second_history = sa.record_snapshot()
            second_status = objects[sa.STATUS_KEY]

        assert first_status["components"] == [
            {"id": "qurl_api", "status": sa.DEGRADED, "display_only": False},
        ]
        assert first_history["days"][_today_key()]["qurl_api"] == [0, 1, 0]
        assert second_status["overall"] == sa.MAJOR_OUTAGE
        assert second_status["components"] == [
            {"id": "qurl_api", "status": sa.MAJOR_OUTAGE, "display_only": False},
        ]
        assert second_history["days"][_today_key()]["qurl_api"] == [0, 1, 1]

    def test_unknown_snapshot_does_not_reset_pending_http_outage_debounce(self):
        import status_aggregator as sa

        objects = {
            sa.HISTORY_KEY: {"version": 1, "days": {}},
            sa.INCIDENTS_KEY: {"incidents": []},
        }

        def load(key, missing_ok=True, **_kwargs):
            return objects.get(key)

        def put_object(**kwargs):
            objects[kwargs["Key"]] = json.loads(kwargs["Body"])

        with patch.object(sa, "build_components", side_effect=[
            [{"id": "qurl_api", "status": sa.MAJOR_OUTAGE}],
            [{"id": "qurl_api", "status": sa.UNKNOWN}],
            [{"id": "qurl_api", "status": sa.MAJOR_OUTAGE}],
        ]), patch.object(sa, "_load_json", side_effect=load), \
                patch.object(sa.s3, "put_object", side_effect=put_object), \
                patch.dict(os.environ, {"DEPENDENT_SERVICE_URLS": '{"qurl_api":"https://api.example.com/health"}'}):
            first_history = sa.record_snapshot()
            first_status = objects[sa.STATUS_KEY]
            second_history = sa.record_snapshot()
            second_status = objects[sa.STATUS_KEY]
            third_history = sa.record_snapshot()
            third_status = objects[sa.STATUS_KEY]

        assert first_status["components"][0]["status"] == sa.DEGRADED
        assert first_history[sa.HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY] == {"qurl_api": True}
        assert second_status["components"][0]["status"] == sa.UNKNOWN
        assert second_history[sa.HTTP_HARD_OUTAGE_PENDING_HISTORY_KEY] == {"qurl_api": True}
        assert third_status["components"][0]["status"] == sa.MAJOR_OUTAGE
        assert third_history["days"][_today_key()]["qurl_api"] == [0, 1, 1]

    def test_record_snapshot_raises_before_wiping_history_on_read_error(self):
        import status_aggregator as sa

        def load(key, missing_ok=True, **_kwargs):
            if key == sa.STATUS_KEY:
                return None
            if key == sa.HISTORY_KEY:
                assert missing_ok is False
                raise RuntimeError("transient s3 read failure")
            return None

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.OPERATIONAL},
        ]), patch.object(sa, "_load_json", side_effect=load), \
                patch.object(sa.s3, "put_object") as put_object:
            with pytest.raises(RuntimeError, match="transient s3 read failure"):
                sa.record_snapshot()

        put_object.assert_not_called()

    def test_record_snapshot_continues_when_history_json_is_malformed(self):
        import status_aggregator as sa

        def get_object(Bucket, Key):
            if Key == sa.HISTORY_KEY:
                return {"Body": BytesIO(b"{not-json")}
            if Key == sa.INCIDENTS_KEY:
                return {"Body": BytesIO(b'{"incidents":[]}')}
            raise AssertionError(f"unexpected key {Key}")

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.OPERATIONAL},
        ]), patch.object(sa.s3, "get_object", side_effect=get_object), \
                patch.object(sa.s3, "put_object") as put_object, \
                patch("builtins.print") as mock_print:
            history = sa.record_snapshot()

        calls = {call.kwargs["Key"]: call.kwargs for call in put_object.call_args_list}
        status = json.loads(calls[sa.STATUS_KEY]["Body"])
        assert history["days"][_today_key()]["qurl_api"] == [1, 0, 0]
        assert status["components"] == [
            {"id": "qurl_api", "status": sa.OPERATIONAL, "display_only": False},
        ]
        assert any("Ignoring malformed history.json" in call.args[0]
                   for call in mock_print.call_args_list)

    def test_record_snapshot_raises_before_clearing_incidents_on_read_error(self):
        import status_aggregator as sa

        def load(key, missing_ok=True, **_kwargs):
            if key == sa.STATUS_KEY:
                return {"components": [], "incidents": [{"id": "incident-1"}]}
            if key == sa.INCIDENTS_KEY:
                assert missing_ok is False
                raise RuntimeError("transient incidents read failure")
            if key == sa.HISTORY_KEY:
                return {"version": 1, "days": {}}
            return None

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.OPERATIONAL},
        ]), patch.object(sa, "_load_json", side_effect=load), \
                patch.object(sa.s3, "put_object") as put_object:
            with pytest.raises(RuntimeError, match="transient incidents read failure"):
                sa.record_snapshot()

        put_object.assert_not_called()

    def test_record_snapshot_continues_when_incidents_json_is_malformed(self):
        import status_aggregator as sa

        previous_status = {
            "incidents": [{
                "id": "incident-1",
                "title": "Existing incident",
                "status": "identified",
                "impact": "major",
                "started_at": "2026-07-06T20:00:00Z",
            }],
        }

        def get_object(Bucket, Key):
            if Key == sa.INCIDENTS_KEY:
                return {"Body": BytesIO(b"{not-json")}
            if Key == sa.HISTORY_KEY:
                return {"Body": BytesIO(b'{"version":1,"days":{}}')}
            if Key == sa.STATUS_KEY:
                return {"Body": BytesIO(json.dumps(previous_status).encode("utf-8"))}
            raise AssertionError(f"unexpected key {Key}")

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.OPERATIONAL},
        ]), patch.object(sa.s3, "get_object", side_effect=get_object), \
                patch.object(sa.s3, "put_object") as put_object, \
                patch("builtins.print") as mock_print:
            history = sa.record_snapshot()

        calls = {call.kwargs["Key"]: call.kwargs for call in put_object.call_args_list}
        status = json.loads(calls[sa.STATUS_KEY]["Body"])
        assert history["days"][_today_key()]["qurl_api"] == [1, 0, 0]
        assert status["overall"] == sa.DEGRADED
        assert status["incidents"] == previous_status["incidents"]
        assert any("Ignoring malformed incidents.json" in call.args[0]
                   for call in mock_print.call_args_list)
        assert any("Reusing previous public incidents" in call.args[0]
                   for call in mock_print.call_args_list)

    def test_public_history_trims_window(self):
        import status_aggregator as sa

        old_day = (datetime.now(timezone.utc) - timedelta(days=120)).strftime("%Y-%m-%d")
        raw = {"days": {old_day: {"qurl_api": [1, 0, 0]}, _today_key(): {"qurl_api": [1, 0, 0]}}}

        assert sa._public_history(raw) == {_today_key(): {"qurl_api": [1, 0, 0]}}
        assert sa._public_history(None) == {}
        assert sa._public_history({"days": "nope"}) == {}

    @patch("status_aggregator.s3")
    def test_load_json_required_missing_key_still_starts_fresh(self, mock_s3):
        from botocore.exceptions import ClientError
        import status_aggregator as sa

        mock_s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "not found"}},
            "GetObject",
        )

        assert sa._load_json(sa.HISTORY_KEY, missing_ok=False) is None

    @patch("status_aggregator.s3")
    def test_load_json_missing_key_can_log_without_traceback(self, mock_s3):
        from botocore.exceptions import ClientError
        import status_aggregator as sa

        mock_s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "NoSuchKey", "Message": "not found"}},
            "GetObject",
        )

        with patch("builtins.print") as mock_print:
            assert sa._load_json(sa.HISTORY_KEY, missing_traceback=False) is None

        mock_print.assert_called_once_with(f"WARN: Missing {sa.HISTORY_KEY}")

    @patch("status_aggregator.s3")
    def test_load_json_required_raises_on_transient_error(self, mock_s3):
        from botocore.exceptions import ClientError
        import status_aggregator as sa

        mock_s3.get_object.side_effect = ClientError(
            {"Error": {"Code": "SlowDown", "Message": "please retry"}},
            "GetObject",
        )

        with pytest.raises(ClientError):
            sa._load_json(sa.HISTORY_KEY, missing_ok=False)

    @patch("status_aggregator.s3")
    def test_load_json_optional_oversized_object_returns_none(self, mock_s3):
        import status_aggregator as sa

        mock_s3.get_object.return_value = {
            "ContentLength": sa.JSON_OBJECT_READ_BYTES_LIMIT + 1,
            "Body": BytesIO(b"{}"),
        }

        assert sa._load_json(sa.STATUS_KEY) is None

    @patch("status_aggregator.s3")
    def test_load_json_required_oversized_object_raises(self, mock_s3):
        import status_aggregator as sa

        mock_s3.get_object.return_value = {
            "ContentLength": sa.JSON_OBJECT_READ_BYTES_LIMIT + 1,
            "Body": BytesIO(b"{}"),
        }

        with pytest.raises(sa._JsonObjectTooLarge):
            sa._load_json(sa.HISTORY_KEY, missing_ok=False)

    @patch("status_aggregator.s3")
    def test_load_json_caps_body_when_content_length_is_absent(self, mock_s3):
        import status_aggregator as sa

        mock_s3.get_object.return_value = {
            "Body": BytesIO(b" " * (sa.JSON_OBJECT_READ_BYTES_LIMIT + 1)),
        }

        assert sa._load_json(sa.INCIDENTS_KEY, parse_error_ok=True) is None

    def test_refresh_status_incidents_updates_status_without_history_write(self):
        import status_aggregator as sa

        sa._STATUS_CACHE["body"] = None
        status = {
            "environment": "sandbox",
            "timestamp": "2026-07-06T20:00:00Z",
            "overall": sa.OPERATIONAL,
            "components": [{"id": "qurl_api", "status": sa.OPERATIONAL}],
            "history": {_today_key(): {"qurl_api": [1, 0, 0]}},
            "incidents": [],
        }
        incidents = {"incidents": [{
            "id": "incident-1",
            "title": "Fresh operator update",
            "status": "identified",
            "impact": "major",
            "started_at": "2026-07-06T20:01:00Z",
        }]}

        def load(key):
            return {sa.STATUS_KEY: status, sa.INCIDENTS_KEY: incidents}.get(key)

        with patch.object(sa, "_load_json", side_effect=load), \
                patch.object(sa.s3, "put_object") as put_object:
            updated = sa.refresh_status_incidents()

        assert updated["timestamp"] == "2026-07-06T20:00:00Z"
        assert updated["overall"] == sa.DEGRADED
        assert updated["history"] == {_today_key(): {"qurl_api": [1, 0, 0]}}
        assert updated["incidents"][0]["title"] == "Fresh operator update"
        put_object.assert_called_once()
        assert put_object.call_args.kwargs["Key"] == sa.STATUS_KEY

    def test_refresh_status_incidents_starts_from_empty_when_status_is_not_a_dict(self):
        import status_aggregator as sa

        incidents = {"incidents": [{
            "id": "incident-1",
            "title": "Fresh operator update",
            "status": "identified",
            "impact": "critical",
            "started_at": "2026-07-06T20:01:00Z",
        }]}

        def load(key):
            return {sa.STATUS_KEY: [], sa.INCIDENTS_KEY: incidents}.get(key)

        with patch.object(sa, "_load_json", side_effect=load), \
                patch.object(sa.s3, "put_object") as put_object:
            updated = sa.refresh_status_incidents()

        assert updated["overall"] == sa.MAJOR_OUTAGE
        assert updated["components"] == []
        assert updated["history"] == {}
        assert updated["incidents"][0]["title"] == "Fresh operator update"
        put_object.assert_called_once()
        assert json.loads(put_object.call_args.kwargs["Body"]) == updated


class TestIncidents:
    def test_sanitizes_incident_fields(self):
        import status_aggregator as sa

        raw = {"incidents": [{
            "id": "incident-1",
            "title": "Elevated qURL errors",
            "status": "identified",
            "impact": "minor",
            "components": ["qurl_api"],
            "started_at": "2026-07-06T18:00:00Z",
            "internal_runbook": "secret",
            "updates": [{
                "at": "2026-07-06T18:05:00Z",
                "status": "identified",
                "body": "We identified the issue.",
                "operator": "internal",
            }],
        }]}

        assert sa._sanitize_incidents(raw) == [{
            "id": "incident-1",
            "title": "Elevated qURL errors",
            "status": "identified",
            "impact": "minor",
            "components": ["qurl_api"],
            "started_at": "2026-07-06T18:00:00Z",
            "updates": [{
                "at": "2026-07-06T18:05:00Z",
                "status": "identified",
                "body": "We identified the issue.",
            }],
        }]

    def test_old_active_incidents_remain_public_until_resolved(self):
        import status_aggregator as sa

        raw = {"incidents": [{
            "id": "incident-1",
            "title": "Long-running investigation",
            "status": "monitoring",
            "impact": "minor",
            "started_at": "2020-01-01T00:00:00Z",
        }]}

        assert sa._sanitize_incidents(raw) == [{
            "id": "incident-1",
            "title": "Long-running investigation",
            "status": "monitoring",
            "impact": "minor",
            "started_at": "2020-01-01T00:00:00Z",
        }]

    def test_incident_public_copy_strips_control_and_format_chars(self):
        import status_aggregator as sa

        raw = {"incidents": [{
            "id": "incident-\u202e\x001",
            "title": "ARN: arn:aws:iam::123456789012:role/test\u202e\x00",
            "status": "identified",
            "impact": "minor",
            "started_at": "2026-07-06T18:00:00Z",
            "updates": [{
                "at": "2026-07-06T18:05:00Z",
                "status": "identified",
                "body": "Operator public copy\x08\u202d",
            }],
        }]}

        incidents = sa._sanitize_incidents(raw)

        assert incidents[0]["id"] == "incident-1"
        assert incidents[0]["title"] == "ARN: arn:aws:iam::123456789012:role/test"
        assert incidents[0]["updates"][0]["body"] == "Operator public copy"

    def test_readme_documents_operator_copy_boundary(self):
        readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()

        assert "## Incident publish runbook" in readme
        assert "aws s3 cp incidents.json" in readme
        assert "Incident-level timestamps more than 1 day in the future" in readme
        assert "active incidents do not auto-expire" in readme
        assert "The leak-free guarantee means the Lambda" in readme
        assert "adds no infrastructure detail" in readme
        assert "operators are still responsible for keeping" in readme
        assert "incident copy free" in readme

    def test_skips_invalid_incident_entries(self):
        import status_aggregator as sa

        raw = {"incidents": [
            {
                "id": "incident-1",
                "title": "Missing status",
                "impact": "minor",
                "started_at": "2026-07-06T18:00:00Z",
            },
            {
                "id": "incident-2",
                "title": "Invalid impact",
                "status": "identified",
                "impact": "catastrophic",
                "started_at": "2026-07-06T18:00:00Z",
            },
        ]}

        with patch("builtins.print") as mock_print:
            assert sa._sanitize_incidents(raw) == []

        assert mock_print.call_count == 2
        messages = [call.args[0] for call in mock_print.call_args_list]
        assert any("status is not allowed" in message for message in messages)
        assert any("impact is not allowed" in message for message in messages)

    def test_skips_incidents_with_far_future_timestamps(self):
        import status_aggregator as sa

        far_future = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        raw = {"incidents": [
            {
                "id": "incident-1",
                "title": "Future active incident typo",
                "status": "identified",
                "impact": "minor",
                "started_at": far_future,
            },
            {
                "id": "incident-2",
                "title": "Future resolved incident typo",
                "status": "resolved",
                "impact": "minor",
                "started_at": "2026-07-06T18:00:00Z",
                "resolved_at": far_future,
            },
        ]}

        with patch("builtins.print") as mock_print:
            assert sa._sanitize_incidents(raw) == []

        messages = [call.args[0] for call in mock_print.call_args_list]
        assert any("started_at cannot be more than 1 day" in message for message in messages)
        assert any("resolved_at cannot be more than 1 day" in message for message in messages)

    def test_logs_resolved_incident_without_reference_timestamp(self):
        import status_aggregator as sa

        incident = {
            "id": "incident-1",
            "title": "Missing usable reference time",
            "status": "resolved",
            "impact": "minor",
            "started_at": "not a timestamp",
        }

        with patch("builtins.print") as mock_print:
            assert not sa._is_public_incident(incident)

        assert any(
            "without parseable started_at or resolved_at" in call.args[0]
            for call in mock_print.call_args_list
        )

    def test_filters_incident_updates_with_far_future_timestamps(self):
        import status_aggregator as sa

        far_future = (datetime.now(timezone.utc) + timedelta(days=2)).isoformat()
        raw = {"incidents": [{
            "id": "incident-1",
            "title": "Incident with update typo",
            "status": "monitoring",
            "impact": "minor",
            "started_at": "2026-07-06T18:00:00Z",
            "updates": [
                {
                    "at": far_future,
                    "status": "identified",
                    "body": "Future typo should not publish.",
                },
                {
                    "at": "2026-07-06T18:05:00Z",
                    "status": "monitoring",
                    "body": "Valid update should publish.",
                },
            ],
        }]}

        assert sa._sanitize_incidents(raw)[0]["updates"] == [{
            "at": "2026-07-06T18:05:00Z",
            "status": "monitoring",
            "body": "Valid update should publish.",
        }]

    def test_skips_incidents_with_invalid_value_shapes(self):
        import status_aggregator as sa

        raw = {"incidents": [
            {
                "id": "incident-1",
                "title": "Nested components should not publish",
                "status": "identified",
                "impact": "minor",
                "components": [["qurl_api"]],
                "started_at": "2026-07-06T18:00:00Z",
            },
            {
                "id": "incident-2",
                "title": "Bad timestamp should not publish",
                "status": "identified",
                "impact": "minor",
                "started_at": "not a timestamp",
            },
            {
                "id": "incident-3",
                "title": "x" * (sa._INCIDENT_STRING_LIMITS["title"] + 1),
                "status": "identified",
                "impact": "minor",
                "started_at": "2026-07-06T18:00:00Z",
            },
        ]}

        with patch("builtins.print") as mock_print:
            assert sa._sanitize_incidents(raw) == []

        assert mock_print.call_count == 3
        messages = [call.args[0] for call in mock_print.call_args_list]
        assert any("components must be known public component ids" in message for message in messages)
        assert any("started_at must be a full ISO-8601 date-time" in message for message in messages)
        assert any("title must be a non-empty string" in message for message in messages)

    def test_filters_invalid_incident_updates(self):
        import status_aggregator as sa

        raw = {"incidents": [{
            "id": "incident-1",
            "title": "Elevated qURL errors",
            "status": "identified",
            "impact": "minor",
            "components": ["qurl_api"],
            "started_at": "2026-07-06T18:00:00Z",
            "updates": [
                {
                    "at": "2026-07-06T18:05:00Z",
                    "status": "identified",
                    "body": "We identified the issue.",
                },
                {
                    "at": "not a timestamp",
                    "status": "identified",
                    "body": "This malformed update should not publish.",
                },
                {
                    "at": "2026-07-06T18:10:00Z",
                    "status": "identified",
                    "body": "x" * (sa._INCIDENT_STRING_LIMITS["body"] + 1),
                },
            ],
        }]}

        assert sa._sanitize_incidents(raw)[0]["updates"] == [{
            "at": "2026-07-06T18:05:00Z",
            "status": "identified",
            "body": "We identified the issue.",
        }]

    def test_trims_old_resolved_incidents_from_public_payload(self):
        import status_aggregator as sa

        old_started = (datetime.now(timezone.utc) - timedelta(days=sa.INCIDENT_PUBLIC_DAYS + 2)).isoformat()
        recent_started = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        recent_resolved = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        raw = {"incidents": [
            {
                "id": "old-resolved",
                "title": "Old resolved incident",
                "status": "resolved",
                "impact": "minor",
                "started_at": old_started,
            },
            {
                "id": "recent-resolved",
                "title": "Recent resolved incident",
                "status": "resolved",
                "impact": "minor",
                "started_at": recent_started,
            },
            {
                "id": "long-incident-resolved-yesterday",
                "title": "Long incident resolved yesterday",
                "status": "resolved",
                "impact": "minor",
                "started_at": old_started,
                "resolved_at": recent_resolved,
            },
            {
                "id": "old-active",
                "title": "Old active incident",
                "status": "monitoring",
                "impact": "major",
                "started_at": old_started,
            },
        ]}

        assert [incident["id"] for incident in sa._sanitize_incidents(raw)] == [
            "recent-resolved",
            "long-incident-resolved-yesterday",
            "old-active",
        ]

    def test_rejects_incidents_with_unknown_component_ids(self):
        import status_aggregator as sa

        raw = {"incidents": [{
            "id": "incident-1",
            "title": "Typoed component id",
            "status": "identified",
            "impact": "minor",
            "components": ["not_a_component"],
            "started_at": "2026-07-06T18:00:00Z",
        }]}

        with patch("builtins.print") as mock_print:
            assert sa._sanitize_incidents(raw) == []

        assert mock_print.call_count == 1
        assert "components must be known public component ids" in mock_print.call_args.args[0]

    def test_skips_duplicate_public_incident_ids(self):
        import status_aggregator as sa

        raw = {"incidents": [
            {
                "id": "incident-1",
                "title": "First copy wins",
                "status": "identified",
                "impact": "minor",
                "started_at": "2026-07-06T18:00:00Z",
            },
            {
                "id": "incident-1",
                "title": "Duplicate copy",
                "status": "identified",
                "impact": "minor",
                "started_at": "2026-07-06T18:05:00Z",
            },
        ]}

        with patch("builtins.print") as mock_print:
            assert sa._sanitize_incidents(raw) == [{
                "id": "incident-1",
                "title": "First copy wins",
                "status": "identified",
                "impact": "minor",
                "started_at": "2026-07-06T18:00:00Z",
            }]

        assert any("Skipping duplicate incident id" in call.args[0] for call in mock_print.call_args_list)

    def test_caps_raw_incident_input(self):
        import status_aggregator as sa

        base = datetime.now(timezone.utc) - timedelta(hours=sa.INCIDENT_INPUT_LIMIT + 1)
        raw = {"incidents": []}
        for offset in range(sa.INCIDENT_INPUT_LIMIT + 1):
            raw["incidents"].append({
                "id": f"resolved-{offset}",
                "title": f"Resolved incident {offset}",
                "status": "resolved",
                "impact": "minor",
                "started_at": (base + timedelta(hours=offset)).isoformat(),
            })

        with patch("builtins.print") as mock_print:
            incident_ids = [incident["id"] for incident in sa._sanitize_incidents(raw)]

        assert len(incident_ids) == sa.INCIDENT_RESOLVED_PUBLIC_LIMIT
        assert f"resolved-{sa.INCIDENT_INPUT_LIMIT}" not in incident_ids
        assert any("Ignoring incidents beyond first" in call.args[0] for call in mock_print.call_args_list)

    def test_caps_resolved_incidents_to_newest_public_limit(self):
        import status_aggregator as sa

        base = datetime.now(timezone.utc) - timedelta(hours=sa.INCIDENT_RESOLVED_PUBLIC_LIMIT + 2)
        raw = {"incidents": []}
        for offset in range(sa.INCIDENT_RESOLVED_PUBLIC_LIMIT + 2):
            raw["incidents"].append({
                "id": f"resolved-{offset}",
                "title": f"Resolved incident {offset}",
                "status": "resolved",
                "impact": "minor",
                "started_at": (base + timedelta(hours=offset)).isoformat(),
            })

        incident_ids = [incident["id"] for incident in sa._sanitize_incidents(raw)]

        assert "resolved-0" not in incident_ids
        assert "resolved-1" not in incident_ids
        assert "resolved-2" in incident_ids
        assert f"resolved-{sa.INCIDENT_RESOLVED_PUBLIC_LIMIT + 1}" in incident_ids
        assert len(incident_ids) == sa.INCIDENT_RESOLVED_PUBLIC_LIMIT

    def test_caps_active_incidents_to_newest_public_limit(self):
        import status_aggregator as sa

        raw = {"incidents": []}
        oldest_started = (
            datetime.now(timezone.utc)
            - timedelta(hours=sa.INCIDENT_PUBLIC_LIMIT + 3)
        )
        for offset in range(sa.INCIDENT_PUBLIC_LIMIT + 2):
            raw["incidents"].append({
                "id": f"active-{offset}",
                "title": f"Active incident {offset}",
                "status": "identified",
                "impact": "minor",
                "started_at": (oldest_started + timedelta(hours=offset)).isoformat(),
            })
        raw["incidents"].append({
            "id": "resolved-recent",
            "title": "Recent resolved incident",
            "status": "resolved",
            "impact": "minor",
            "started_at": datetime.now(timezone.utc).isoformat(),
        })

        incident_ids = [incident["id"] for incident in sa._sanitize_incidents(raw)]

        assert "active-0" not in incident_ids
        assert "active-1" not in incident_ids
        assert "active-2" in incident_ids
        assert "active-26" in incident_ids
        assert "resolved-recent" in incident_ids
        assert len([id_ for id_ in incident_ids if id_.startswith("active-")]) == sa.INCIDENT_PUBLIC_LIMIT

    def test_caps_public_incident_json_bytes_by_dropping_resolved_first(self):
        import status_aggregator as sa

        now = datetime.now(timezone.utc)
        resolved_started = now - timedelta(days=3)
        raw = {"incidents": [
            {
                "id": "resolved-old",
                "title": "Resolved incident",
                "status": "resolved",
                "impact": "minor",
                "started_at": resolved_started.isoformat(),
                "updates": [{
                    "at": (resolved_started + timedelta(minutes=5)).isoformat(),
                    "status": "resolved",
                    "body": "resolved " * 120,
                }],
            },
            {
                "id": "active-old",
                "title": "Older active incident",
                "status": "monitoring",
                "impact": "minor",
                "started_at": (now - timedelta(days=2)).isoformat(),
            },
            {
                "id": "active-new",
                "title": "Newer active incident",
                "status": "identified",
                "impact": "major",
                "started_at": (now - timedelta(days=1)).isoformat(),
            },
        ]}
        with patch.object(sa, "INCIDENT_PUBLIC_JSON_BYTES_LIMIT", 10**9):
            all_incidents = sa._sanitize_incidents(raw)
        active_incidents = [
            incident for incident in all_incidents
            if incident["status"] != "resolved"
        ]
        budget = sa._json_size_bytes(active_incidents) + 1

        with patch.object(sa, "INCIDENT_PUBLIC_JSON_BYTES_LIMIT", budget), \
                patch("builtins.print") as mock_print:
            trimmed = sa._sanitize_incidents(raw)

        assert [incident["id"] for incident in trimmed] == ["active-old", "active-new"]
        assert any("Trimmed 1 incident" in call.args[0] for call in mock_print.call_args_list)

    def test_caps_public_incident_json_bytes_when_only_active_incidents_remain(self):
        import status_aggregator as sa

        raw = {"incidents": [
            {
                "id": "active-old",
                "title": "Older active incident",
                "status": "monitoring",
                "impact": "minor",
                "started_at": "2026-07-02T00:00:00Z",
                "updates": [{
                    "at": "2026-07-02T00:05:00Z",
                    "status": "monitoring",
                    "body": "older " * 120,
                }],
            },
            {
                "id": "active-new",
                "title": "Newer active incident",
                "status": "identified",
                "impact": "major",
                "started_at": "2026-07-03T00:00:00Z",
            },
        ]}
        with patch.object(sa, "INCIDENT_PUBLIC_JSON_BYTES_LIMIT", 10**9):
            all_incidents = sa._sanitize_incidents(raw)
        budget = sa._json_size_bytes([
            incident for incident in all_incidents
            if incident["id"] == "active-new"
        ])

        with patch.object(sa, "INCIDENT_PUBLIC_JSON_BYTES_LIMIT", budget), \
                patch("builtins.print") as mock_print:
            trimmed = sa._sanitize_incidents(raw)

        assert [incident["id"] for incident in trimmed] == ["active-new"]
        assert any("Trimmed 1 incident" in call.args[0] for call in mock_print.call_args_list)

    def test_incident_publish_event_detects_incidents_json(self):
        import status_aggregator as sa

        event = {
            "Records": [{
                "eventSource": "aws:s3",
                "s3": {"object": {"key": "incidents.json"}},
            }]
        }

        assert sa._is_incident_publish_event(event)
        assert not sa._is_incident_publish_event({"Records": [{
            "eventSource": "aws:s3",
            "s3": {"object": {"key": "status.json"}},
        }]})
        assert not sa._is_incident_publish_event({"Records": [{
            "eventSource": "aws:s3",
            "s3": {"object": {"key": "incidents.json.bak"}},
        }]})

    def test_cached_status_merges_latest_sanitized_incidents(self):
        import status_aggregator as sa

        sa._STATUS_CACHE["body"] = None
        status = {
            "environment": "sandbox",
            "timestamp": "2026-07-06T20:00:00Z",
            "overall": sa.OPERATIONAL,
            "components": [],
            "history": {},
            "incidents": [],
        }
        incidents = {"incidents": [{
            "id": "incident-1",
            "title": "Fresh operator update",
            "status": "identified",
            "impact": "major",
            "started_at": "2026-07-06T20:00:00Z",
            "internal_notes": "do not leak",
        }]}

        def load(key):
            return {sa.STATUS_KEY: status, sa.INCIDENTS_KEY: incidents}.get(key)

        with patch.object(sa, "_load_json", side_effect=load):
            body = sa._get_cached_status()

        assert body["overall"] == sa.DEGRADED
        assert body["incidents"] == [{
            "id": "incident-1",
            "title": "Fresh operator update",
            "status": "identified",
            "impact": "major",
            "started_at": "2026-07-06T20:00:00Z",
        }]

    def test_cached_status_uses_stale_body_on_status_read_miss(self):
        import status_aggregator as sa

        stale = {
            "environment": "sandbox",
            "timestamp": "2026-07-06T20:00:00Z",
            "overall": sa.OPERATIONAL,
            "components": [{"id": "qurl_api", "status": sa.OPERATIONAL}],
            "history": {},
            "incidents": [],
        }
        sa._STATUS_CACHE["body"] = stale
        sa._STATUS_CACHE["expires_at"] = 0.0

        with patch.object(sa, "_load_json", return_value=None), \
                patch("builtins.print") as mock_print:
            body = sa._get_cached_status()

        assert body == stale
        assert any("Serving stale cached status" in call.args[0] for call in mock_print.call_args_list)

    def test_cached_status_short_negative_caches_cold_empty_fallback(self):
        import status_aggregator as sa

        sa._STATUS_CACHE["body"] = None
        sa._STATUS_CACHE["expires_at"] = 0.0

        with patch.object(sa, "_load_json", return_value=None), \
                patch.object(sa.time, "time", return_value=1234.0), \
                patch("builtins.print") as mock_print:
            body = sa._get_cached_status()

        assert body["overall"] == sa.UNKNOWN
        assert body["components"] == []
        assert sa._STATUS_CACHE["expires_at"] == 1234.0 + sa.EMPTY_STATUS_CACHE_TTL_SECONDS
        assert any("Serving empty status" in call.args[0] for call in mock_print.call_args_list)


class TestPublicPayloadIsLeakFree:
    ALLOWED_TOP_KEYS = {"environment", "timestamp", "overall", "components", "history", "incidents"}
    FORBIDDEN_SUBSTRINGS = [
        "arn:",
        "image_tag",
        "deployed_commit",
        "healthy_hosts",
        "unhealthy_hosts",
        "total_hosts",
        "asg",
        "targetgroup",
        "cloudwatch",
        "grafana",
        "235500187906",
        "state_reason",
        "threshold",
    ]

    def test_payload_shape_and_redaction(self):
        import status_aggregator as sa

        now = datetime.now(timezone.utc)
        history = {"version": 1, "days": {_today_key(): {"qurl_api": [12, 0, 0]}}}
        incidents = {"incidents": [{
            "id": "incident-1",
            "title": "Resolved qURL delay",
            "status": "resolved",
            "impact": "minor",
            "components": ["qurl_api"],
            "started_at": (now - timedelta(days=3)).isoformat(),
            "internal_notes": "do not publish",
        }]}

        def load(key):
            return {sa.HISTORY_KEY: history, sa.INCIDENTS_KEY: incidents}.get(key)

        with patch.object(sa, "build_components", return_value=[
            {"id": "qurl_api", "status": sa.OPERATIONAL},
            {"id": "nhp_server", "status": sa.OPERATIONAL},
        ]), patch.object(sa, "_load_json", side_effect=load):
            payload = sa.build_public_status()

        assert set(payload.keys()) == self.ALLOWED_TOP_KEYS
        assert payload["overall"] == sa.OPERATIONAL
        assert all(
            set(component.keys()) == {"id", "status", "display_only"}
            for component in payload["components"]
        )
        assert payload["history"] == {_today_key(): {"qurl_api": [12, 0, 0]}}
        assert "internal_notes" not in payload["incidents"][0]

        dumped = json.dumps(payload).lower()
        for forbidden in self.FORBIDDEN_SUBSTRINGS:
            assert forbidden not in dumped, f"public payload leaked: {forbidden}"

    def test_build_public_status_accepts_snapshot_inputs_without_live_checks(self):
        import status_aggregator as sa

        history = {"version": 1, "days": {_today_key(): {"qurl_api": [1, 0, 0]}}}
        components = [{"id": "qurl_api", "status": sa.OPERATIONAL}]

        with patch.object(sa, "build_components", side_effect=RuntimeError("live check")):
            payload = sa.build_public_status(
                components=components,
                history_raw=history,
                incidents_raw={"incidents": []},
            )

        assert payload["overall"] == sa.OPERATIONAL
        assert payload["components"] == [
            {"id": "qurl_api", "status": sa.OPERATIONAL, "display_only": False},
        ]


class TestHandler:
    def test_snapshot_task_routes_to_recorder(self):
        import status_aggregator as sa

        with patch.object(sa, "record_snapshot", return_value={"version": 1}) as record:
            assert sa.handler({"task": "snapshot"}, None) == {"ok": True}
        record.assert_called_once()

    def test_incident_s3_event_refreshes_status_incidents(self):
        import status_aggregator as sa

        event = {
            "Records": [{
                "eventSource": "aws:s3",
                "s3": {"object": {"key": "incidents.json"}},
            }]
        }
        with patch.object(sa, "refresh_status_incidents", return_value={"ok": True}) as refresh:
            assert sa.handler(event, None) == {"ok": True}
        refresh.assert_called_once()

    def test_non_incident_s3_event_is_ignored(self):
        import status_aggregator as sa

        event = {
            "Records": [{
                "eventSource": "aws:s3",
                "s3": {"object": {"key": "status.json"}},
            }]
        }

        with patch.object(sa, "_get_cached_status", side_effect=RuntimeError("api path")):
            assert sa.handler(event, None) == {"ok": True, "ignored": True}

    def test_options_request(self):
        import status_aggregator as sa

        result = sa.handler({"requestContext": {"http": {"method": "OPTIONS"}}}, None)
        assert result["statusCode"] == 200
        assert result["body"] == ""
        assert "Content-Type" not in result["headers"]

    def test_non_get_request_returns_method_not_allowed(self):
        import status_aggregator as sa

        result = sa.handler({"requestContext": {"http": {"method": "POST"}}}, None)

        assert result["statusCode"] == 405
        assert result["headers"]["Allow"] == "GET, OPTIONS"
        assert json.loads(result["body"]) == {"error": "Method not allowed"}

    def test_get_request_returns_public_status(self):
        import status_aggregator as sa

        sa._STATUS_CACHE["body"] = None
        fake = {"overall": sa.OPERATIONAL}
        with patch.object(sa, "_load_json",
                          side_effect=lambda key: fake if key == sa.STATUS_KEY else None), \
                patch.object(sa, "build_public_status", side_effect=RuntimeError("live check")):
            result = sa.handler({"requestContext": {"http": {"method": "GET"}}}, None)

        assert result["statusCode"] == 200
        assert json.loads(result["body"]) == fake

    def test_get_request_falls_back_before_first_snapshot(self):
        import status_aggregator as sa

        sa._STATUS_CACHE["body"] = None
        with patch.object(sa, "_load_json", return_value=None):
            result = sa.handler({"requestContext": {"http": {"method": "GET"}}}, None)

        body = json.loads(result["body"])
        assert result["statusCode"] == 200
        assert body["overall"] == sa.UNKNOWN
        assert body["components"] == []

    def test_get_request_masks_internal_errors(self):
        import status_aggregator as sa

        sa._STATUS_CACHE["body"] = None
        with patch.object(sa, "_load_json", side_effect=RuntimeError("kaboom")):
            result = sa.handler({"requestContext": {"http": {"method": "GET"}}}, None)

        assert result["statusCode"] == 500
        assert json.loads(result["body"]) == {"error": "Internal server error"}

    def test_non_dict_event_returns_internal_error(self):
        import status_aggregator as sa

        result = sa.handler(None, None)

        assert result["statusCode"] == 500
        assert json.loads(result["body"]) == {"error": "Internal server error"}


def test_no_test_accidentally_imports_pytest_only_symbols_into_runtime():
    import status_aggregator as sa

    assert not hasattr(sa, "pytest")
