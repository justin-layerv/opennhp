import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "terraform/modules/compute/udp_edge_metrics.py"
SPEC = importlib.util.spec_from_file_location("udp_edge_metrics", SCRIPT)
assert SPEC and SPEC.loader
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)

VERIFIER_SCRIPT = ROOT / "scripts/verify-udp-edge-readiness.py"
VERIFIER_SPEC = importlib.util.spec_from_file_location("verify_udp_edge_readiness", VERIFIER_SCRIPT)
assert VERIFIER_SPEC and VERIFIER_SPEC.loader
verifier = importlib.util.module_from_spec(VERIFIER_SPEC)
VERIFIER_SPEC.loader.exec_module(verifier)

OVERLAP_SCRIPT = ROOT / "scripts/verify-udp-edge-overlap.py"
OVERLAP_SPEC = importlib.util.spec_from_file_location("verify_udp_edge_overlap", OVERLAP_SCRIPT)
assert OVERLAP_SPEC and OVERLAP_SPEC.loader
overlap = importlib.util.module_from_spec(OVERLAP_SPEC)
OVERLAP_SPEC.loader.exec_module(overlap)


class UDPEdgeMetricsTest(unittest.TestCase):
    def test_overlap_verifier_requires_all_sources_and_rejects_late_start(self) -> None:
        expected_start = 1_800_000_000
        expected_end = expected_start + 300
        floods = [
            (f"source-{index}", {"started_epoch": expected_start + index, "ended_epoch": expected_end + index})
            for index in range(8)
        ]
        probe = {"started_epoch": expected_start + 2, "ended_epoch": expected_end + 2}
        report = overlap.verify_windows(floods, probe, expected_start, expected_end)
        self.assertEqual([], report["failures"])
        self.assertGreaterEqual(report["common_overlap_seconds"], 270)

        floods[-1][1]["started_epoch"] = expected_start + overlap.MAX_START_LAG_SECONDS + 1
        floods[-1][1]["ended_epoch"] = floods[-1][1]["started_epoch"] + 300
        report = overlap.verify_windows(floods, probe, expected_start, expected_end)
        self.assertTrue(any("started 31s late" in failure for failure in report["failures"]))

    def test_readiness_workflow_resolves_cell_and_fails_closed_on_probe_pipe(self) -> None:
        workflow = (ROOT / ".github/workflows/udp-edge-readiness.yml").read_text(encoding="utf-8")
        self.assertIn("/sandbox/nhp/deploy/cell-id", workflow)
        self.assertIn("cell_id: ${{ steps.target.outputs.cell_id }}", workflow)
        self.assertIn('--cell "$CELL_ID"', workflow)
        self.assertNotIn("--cell cell0", workflow)
        self.assertRegex(workflow, r"set -euo pipefail\n\s+go run ./cmd/udp-edge-probe \| tee")
        self.assertIn("actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c", workflow)
        self.assertIn("scripts/verify-udp-edge-overlap.py", workflow)

    def test_readiness_workflow_rejects_load_below_host_hashlimit(self) -> None:
        workflow = (ROOT / ".github/workflows/udp-edge-readiness.yml").read_text(encoding="utf-8")
        self.assertIn("FLOOD_PPS <= 100", workflow)
        self.assertIn("must be an integer greater than the 100 pps/source host limit", workflow)

    def test_healthy_event_only_counters_need_no_datapoints(self) -> None:
        event_only = {
            "PacketDecryptQueueDrop",
            "DecryptedMessageQueueDrop",
            "HandlerProtectedReserveExhausted",
        }
        self.assertTrue(event_only.isdisjoint(verifier.REQUIRED_SUM_METRICS))
        report = {name: {"sum": 0.0, "datapoints": 0} for name in verifier.SUM_METRICS}
        for name in verifier.REQUIRED_SUM_METRICS:
            report[name]["datapoints"] = 1
        report["UDPIngressDatagram"]["sum"] = 10_000
        report["UDPPerSourceRateLimitDrop"] = {"sum": 1.0, "datapoints": 1}
        report.update({name: {"maximum": 0.0, "datapoints": 1} for name in verifier.MAXIMUM_METRICS})
        report["ASGCPUUtilization"] = {"maximum": 1.0, "datapoints": 1}
        self.assertEqual(
            [],
            verifier.readiness_failures(
                report,
                max_cpu_percent=95,
                max_heap_bytes=1 << 30,
                max_goroutines=10_000,
            ),
        )

    def test_aws_json_retries_one_transient_cli_failure(self) -> None:
        transient = subprocess.CalledProcessError(1, ["aws"], stderr="transient")
        success = subprocess.CompletedProcess(["aws"], 0, stdout='{"Datapoints": []}', stderr="")
        with (
            mock.patch.object(verifier.subprocess, "run", side_effect=[transient, success]) as run,
            mock.patch.object(verifier.time, "sleep") as sleep,
        ):
            self.assertEqual({"Datapoints": []}, verifier.aws_json(["cloudwatch", "get-metric-statistics"]))
        self.assertEqual(2, run.call_count)
        sleep.assert_called_once_with(1)

    def test_verifier_fails_when_a_bounded_queue_reaches_capacity(self) -> None:
        self.assertFalse(verifier.reached_capacity(10239, 10240))
        self.assertTrue(verifier.reached_capacity(10240, 10240))
        self.assertTrue(verifier.reached_capacity(10241, 10240))

    def test_verifier_capacity_limits_match_go_constants(self) -> None:
        server_constants = (ROOT / "endpoints/server/constants.go").read_text(encoding="utf-8")
        core_constants = (ROOT / "nhp/core/constants.go").read_text(encoding="utf-8")
        total = int(re.search(r"MaxConcurrentHandlers\s*=\s*(\d+)", server_constants).group(1))
        reserve_divisor = int(
            re.search(r"HandlerProtectedReserve\s*=\s*MaxConcurrentHandlers\s*/\s*(\d+)", server_constants).group(1)
        )
        queue_size = int(re.search(r"RecvQueueSize\s*=\s*(\d+)", core_constants).group(1))
        self.assertEqual(
            {
                "HandlerInFlight": total,
                "HandlerProtectedInFlight": total // reserve_divisor,
                "PacketDecryptQueueDepth": queue_size,
                "DecryptedMessageQueueDepth": queue_size,
            },
            verifier.FIXED_CAPACITY_LIMITS,
        )

    def test_host_admission_sheds_noisy_sources_before_shared_cap(self) -> None:
        template = (ROOT / "terraform/modules/compute/user_data.sh.tpl").read_text(encoding="utf-8")
        guard_insert = template.find("iptables -C INPUT -p udp --dport 62206")
        per_source = template.rfind("--comment nhp-knock-per-source-drop")
        aggregate = template.rfind("--comment nhp-knock-global-drop")
        admitted = template.rfind("--comment nhp-knock-admitted")
        guard_remove = template.rfind("--comment nhp-knock-reconfigure-guard -j DROP")
        self.assertGreaterEqual(guard_insert, 0)
        self.assertGreater(per_source, guard_insert)
        self.assertGreater(aggregate, per_source)
        self.assertGreater(admitted, aggregate)
        self.assertGreater(guard_remove, admitted)

    def test_udp_edge_collector_avoids_unused_generic_metrics_and_rotates_emf(self) -> None:
        template = (ROOT / "terraform/modules/compute/user_data.sh.tpl").read_text(encoding="utf-8")
        self.assertNotIn('"net": {', template)
        self.assertNotIn('"procstat": [', template)
        self.assertIn("/etc/logrotate.d/nhp-udp-edge-metrics", template)
        self.assertIn("/opt/layerv/nhp-server/log/server-udp-edge-metrics.log {", template)
        self.assertIn("maxsize 10M", template)
        self.assertIn("copytruncate", template)

    def test_handler_shed_dashboard_label_matches_counter_semantics(self) -> None:
        monitoring = (ROOT / "terraform/modules/monitoring/main.tf").read_text(encoding="utf-8")
        self.assertIn('"HandlerBudgetExhausted", ".", ".", ".", ".", { "label" : "Total handler shed" }', monitoring)
        self.assertNotIn('"HandlerBudgetExhausted", ".", ".", ".", ".", { "label" : "General handler shed" }', monitoring)

    def test_flood_and_probe_artifacts_publish_actual_timing(self) -> None:
        flood = (ROOT / "scripts/udp-edge-flood.py").read_text(encoding="utf-8")
        probe = (ROOT / "endpoints/cmd/udp-edge-probe/main.go").read_text(encoding="utf-8")
        self.assertIn('"started_epoch": started_epoch', flood)
        self.assertIn('"ended_epoch": ended_epoch', flood)
        self.assertIn('`json:"started_epoch"`', probe)
        self.assertIn('`json:"ended_epoch"`', probe)

    def test_snmp_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "snmp"
            path.write_text(
                "Ip: Forwarding DefaultTTL\nIp: 1 64\n"
                "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors\n"
                "Udp: 101 2 3 99 4\n",
                encoding="utf-8",
            )
            self.assertEqual(
                {"InDatagrams": 101, "NoPorts": 2, "InErrors": 3, "OutDatagrams": 99, "RcvbufErrors": 4},
                collector.read_udp_snmp(path),
            )

    def test_iptables_marker_must_be_unique(self) -> None:
        line = "12 2048 DROP udp -- * * 0.0.0.0/0 0.0.0.0/0 /* nhp-knock-global-drop */"
        self.assertEqual(12, collector.read_iptables_packets(line, "nhp-knock-global-drop"))
        self.assertIsNone(collector.read_iptables_packets("", "nhp-knock-global-drop"))
        self.assertIsNone(collector.read_iptables_packets(f"{line}\n{line}", "nhp-knock-global-drop"))

    def test_udp_socket_drop_parser_sums_ipv4_and_ipv6_listeners(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            udp = Path(tmp) / "udp"
            udp6 = Path(tmp) / "udp6"
            header = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n"
            udp.write_text(
                header
                + "  1: 00000000:F2FE 00000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 123 2 0 9\n",
                encoding="utf-8",
            )
            udp6.write_text(header, encoding="utf-8")
            self.assertEqual(9, collector.read_udp_socket_drops((udp, udp6)))
            udp6.write_text(
                header
                + "  2: 00000000000000000000000000000000:F2FE 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 0 0 456 2 0 4\n",
                encoding="utf-8",
            )
            self.assertEqual(13, collector.read_udp_socket_drops((udp, udp6)))

    def test_load_state_rejects_boolean_and_non_integer_counters(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state.json"
            state.write_text(
                json.dumps({"accepted": 7, "boolean": True, "float": 2.5, "text": "3"}),
                encoding="utf-8",
            )
            self.assertEqual({"accepted": 7}, collector.load_state(state))

    def test_delta_handles_first_sample_and_reset(self) -> None:
        self.assertEqual(0, collector.delta(10, None))
        self.assertEqual(4, collector.delta(10, 6))
        self.assertEqual(2, collector.delta(2, 99))

    def test_disabled_global_cap_permits_only_its_missing_marker(self) -> None:
        self.assertEqual(0, collector.marker_error(0, 10, None, 5, False))
        self.assertEqual(1, collector.marker_error(0, 10, None, 5, True))
        self.assertEqual(1, collector.marker_error(0, 10, 1, 5, False))
        self.assertEqual(1, collector.marker_error(0, None, None, 5, False))

    def test_global_cap_environment_is_strict_boolean(self) -> None:
        old_value = os.environ.get("NHP_GLOBAL_RATE_LIMIT_ENABLED")
        try:
            os.environ["NHP_GLOBAL_RATE_LIMIT_ENABLED"] = "yes"
            with self.assertRaisesRegex(RuntimeError, "must be exactly true or false"):
                collector.global_rate_limit_enabled()
        finally:
            if old_value is None:
                os.environ.pop("NHP_GLOBAL_RATE_LIMIT_ENABLED", None)
            else:
                os.environ["NHP_GLOBAL_RATE_LIMIT_ENABLED"] = old_value

    def test_emit_is_valid_emf_with_bounded_dimensions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            old_log = collector.LOG_PATH
            collector.LOG_PATH = Path(tmp) / "metrics.log"
            old_env = os.environ.copy()
            try:
                os.environ.update(
                    NHP_ENVIRONMENT="sandbox",
                    NHP_CELL_ID="cell0",
                    INSTANCE_ID="i-test",
                    NHP_GLOBAL_RATE_LIMIT_ENABLED="true",
                )
                collector.emit({"UDPIngressDatagram": 7, "UDPEdgeCollectorHeartbeat": 1})
                doc = json.loads(collector.LOG_PATH.read_text(encoding="utf-8"))
            finally:
                collector.LOG_PATH = old_log
                os.environ.clear()
                os.environ.update(old_env)
            self.assertEqual("LayerV/NHP", doc["_aws"]["CloudWatchMetrics"][0]["Namespace"])
            self.assertEqual(
                [["Environment", "Cell"], ["Environment", "Cell", "InstanceId"]],
                doc["_aws"]["CloudWatchMetrics"][0]["Dimensions"],
            )
            self.assertEqual(7, doc["UDPIngressDatagram"])

    def test_required_environment_names_every_missing_value(self) -> None:
        old_env = os.environ.copy()
        try:
            for name in ("NHP_ENVIRONMENT", "NHP_CELL_ID", "INSTANCE_ID", "NHP_GLOBAL_RATE_LIMIT_ENABLED"):
                os.environ.pop(name, None)
            with self.assertRaisesRegex(
                RuntimeError,
                "missing required collector environment: NHP_ENVIRONMENT, NHP_CELL_ID, INSTANCE_ID, NHP_GLOBAL_RATE_LIMIT_ENABLED",
            ):
                collector.required_environment()
        finally:
            os.environ.clear()
            os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()
