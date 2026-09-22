import importlib.util
import pathlib
import subprocess
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("clash_guard", ROOT / "clash-guard.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def speed_result(status, speed=0, downloaded=0):
    return {
        "status": status,
        "http_code": 200,
        "bytes": downloaded,
        "speed_bps": speed,
        "detail": "",
    }


class ClashGuardTests(unittest.TestCase):
    def test_node_slash_and_chinese_are_percent_encoded(self):
        path = guard._delay_path("香港/01", "https://example.com/204")
        self.assertIn("%E9%A6%99%E6%B8%AF%2F01", path)
        self.assertNotIn("香港/01", path)
        self.assertIn("expected=204", path)

    def test_candidate_scan_excludes_groups_current_and_quarantine(self):
        proxies = {
            "node-a": {"type": "Shadowsocks"},
            "node-b": {"type": "VLESS"},
            "node-c": {"type": "Trojan"},
            "auto": {"type": "URLTest", "all": ["node-a"]},
            "future-group": {"type": "FutureType", "all": ["node-b"]},
        }
        selector = {"all": ["node-a", "node-b", "node-c", "auto", "future-group"]}
        with mock.patch.object(
            guard, "probe", side_effect=lambda name: {"node-b": 42, "node-c": 20}.get(name)
        ):
            self.assertEqual(
                guard.probe_candidates(proxies, selector, "node-a", excluded={"node-c"}),
                [(42, "node-b")],
            )

    def test_direct_check_accepts_second_independent_endpoint(self):
        proxies = {"DIRECT": {"type": "Direct"}}
        with mock.patch.object(
            guard,
            "api_get",
            side_effect=[guard.GuardError("first endpoint down"), {"delay": 18}],
        ) as api_get:
            self.assertTrue(guard.local_network_status(proxies))
        self.assertEqual(api_get.call_count, 2)

    def test_speed_test_classifies_pass_low_timeout_and_http_error(self):
        cases = [
            (0, "200\t1048576\t700000", "", "PASS"),
            (0, "200\t1048576\t200000", "", "LOW_THROUGHPUT"),
            (28, "200\t12345\t1000", "timed out", "TIMEOUT_PARTIAL"),
            (22, "503\t0\t0", "server error", "HTTP_ERROR"),
        ]
        for returncode, stdout, stderr, expected in cases:
            completed = subprocess.CompletedProcess([], returncode, stdout, stderr)
            with self.subTest(expected=expected), mock.patch.object(
                guard.subprocess, "run", return_value=completed
            ):
                self.assertEqual(guard.speed_test()["status"], expected)

    def test_outage_notification_is_rate_limited(self):
        state = guard._default_state()
        completed = subprocess.CompletedProcess([], 0, "", "")
        with mock.patch.object(
            guard.subprocess, "run", return_value=completed
        ) as run, mock.patch.object(guard, "save_state"):
            self.assertTrue(guard._notify_outage(state, now=2000))
            self.assertFalse(guard._notify_outage(state, now=2001))
        self.assertEqual(run.call_count, 1)
        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["/usr/bin/osascript", "-e"])

    def test_borderline_speed_is_retried_once(self):
        state = guard._default_state()
        proxies = {"candidate": {"type": "VLESS"}}
        first = speed_result(
            "LOW_THROUGHPUT", guard.BORDERLINE_SPEED_BPS, guard.SPEED_BYTES
        )
        second = speed_result("PASS", guard.MIN_SPEED_BPS, guard.SPEED_BYTES)
        with mock.patch.object(guard.time, "sleep"), mock.patch.object(
            guard, "speed_test", side_effect=[first, second]
        ) as test_speed, mock.patch.object(
            guard, "get_snapshot", return_value=(proxies, {}, "candidate")
        ), mock.patch.object(guard, "save_state"), mock.patch.object(guard, "log"):
            self.assertEqual(
                guard._validate_selected_candidate(state, "candidate", 1, 3),
                "ACCEPTED",
            )
        self.assertEqual(test_speed.call_count, 2)

    def test_quarantine_expires_doubles_and_is_eventually_forgotten(self):
        state = guard._default_state()
        result = speed_result("LOW_THROUGHPUT", 1, guard.SPEED_BYTES)
        first_ttl = guard._quarantine_node(state, "bad", result, now=1000)
        second_ttl = guard._quarantine_node(state, "bad", result, now=1100)
        self.assertEqual(first_ttl, guard.QUARANTINE_TTL)
        self.assertEqual(second_ttl, guard.QUARANTINE_TTL * 2)
        self.assertIn("bad", guard._active_quarantine(state, now=1101))
        self.assertNotIn("bad", guard._active_quarantine(state, now=1100 + second_ttl + 1))
        self.assertIn("bad", state["quarantine"])
        guard._active_quarantine(
            state, now=1100 + guard.QUARANTINE_FORGET_AFTER + 1
        )
        self.assertNotIn("bad", state["quarantine"])

    def test_local_offline_during_validation_never_quarantines(self):
        state = guard._default_state()
        proxies = {"candidate": {"type": "VLESS"}}
        failed = speed_result("TIMEOUT_PARTIAL", 0, 1234)
        with mock.patch.object(guard.time, "sleep"), mock.patch.object(
            guard, "speed_test", return_value=failed
        ), mock.patch.object(
            guard, "get_snapshot", return_value=(proxies, {}, "candidate")
        ), mock.patch.object(
            guard, "local_network_status", return_value=False
        ), mock.patch.object(guard, "save_state"), mock.patch.object(guard, "log"):
            outcome = guard._validate_selected_candidate(state, "candidate", 1, 3)
        self.assertEqual(outcome, "LOCAL_OFFLINE")
        self.assertEqual(state["quarantine"], {})
        self.assertEqual(state["phase"], "LOCAL_OFFLINE")

    def test_candidate_validation_tries_in_delay_order_until_first_pass(self):
        current = {"name": "dead"}
        selector = {
            "type": "Selector",
            "now": "dead",
            "all": ["dead", "a", "b", "c", guard.FALLBACK],
        }
        proxies = {
            guard.SELECTOR: selector,
            "dead": {"type": "VLESS"},
            "a": {"type": "VLESS"},
            "b": {"type": "VLESS"},
            "c": {"type": "VLESS"},
            guard.FALLBACK: {"type": "URLTest", "alive": True},
        }

        def snapshot():
            selector["now"] = current["name"]
            return proxies, selector, current["name"]

        switches = []

        def switch(expected, target):
            self.assertEqual(current["name"], expected)
            switches.append((expected, target))
            current["name"] = target

        state = guard._default_state()
        failed = speed_result("LOW_THROUGHPUT", 10, guard.SPEED_BYTES)
        passed = speed_result("PASS", guard.MIN_SPEED_BPS, guard.SPEED_BYTES)
        with mock.patch.object(guard, "get_snapshot", side_effect=snapshot), mock.patch.object(
            guard, "probe_candidates", return_value=[(10, "a"), (20, "b"), (30, "c")]
        ), mock.patch.object(guard, "switch_selector", side_effect=switch), mock.patch.object(
            guard, "speed_test", side_effect=[failed, passed]
        ), mock.patch.object(
            guard, "local_network_status", return_value=True
        ), mock.patch.object(guard.time, "sleep"), mock.patch.object(
            guard, "save_state"
        ), mock.patch.object(guard, "log"):
            guard._run_candidate_validation(state, "dead")

        self.assertEqual(switches, [("dead", "a"), ("a", "b")])
        self.assertIn("a", state["quarantine"])
        self.assertEqual(state["controller_selected"], "b")
        self.assertEqual(state["phase"], "HEALTHY")

    def test_manual_group_is_respected(self):
        selector = {
            "type": "Selector",
            "now": guard.FALLBACK,
            "all": [guard.FALLBACK],
        }
        proxies = {
            guard.SELECTOR: selector,
            guard.FALLBACK: {"type": "URLTest", "all": []},
        }
        state = guard._default_state()
        with mock.patch.object(
            guard, "get_snapshot", return_value=(proxies, selector, guard.FALLBACK)
        ), mock.patch.object(guard, "read_state", return_value=state), mock.patch.object(
            guard, "save_state"
        ), mock.patch.object(guard, "probe") as probe, mock.patch.object(guard, "log"):
            self.assertEqual(guard.main_once(), 0)
        probe.assert_not_called()
        self.assertEqual(state["phase"], "MANUAL_GROUP")
        self.assertFalse(state["fallback_owned"])

    def test_script_owned_fallback_continues_recovery(self):
        selector = {
            "type": "Selector",
            "now": guard.FALLBACK,
            "all": [guard.FALLBACK],
        }
        proxies = {
            guard.SELECTOR: selector,
            guard.FALLBACK: {"type": "URLTest", "all": []},
        }
        state = guard._default_state()
        state.update(
            {
                "node": guard.FALLBACK,
                "fallback_owned": True,
                "controller_selected": guard.FALLBACK,
            }
        )
        with mock.patch.object(
            guard, "get_snapshot", return_value=(proxies, selector, guard.FALLBACK)
        ), mock.patch.object(guard, "read_state", return_value=state), mock.patch.object(
            guard, "_handle_owned_fallback", return_value=0
        ) as recover, mock.patch.object(guard, "save_state"):
            self.assertEqual(guard.main_once(), 0)
        recover.assert_called_once_with(state, proxies, selector)

    def test_pending_candidate_after_crash_is_resumed_not_adopted(self):
        selector = {"type": "Selector", "now": "candidate", "all": ["candidate"]}
        proxies = {guard.SELECTOR: selector, "candidate": {"type": "VLESS"}}
        state = guard._default_state()
        state.update(
            {
                "node": "dead",
                "pending_from": "dead",
                "pending_target": "candidate",
            }
        )
        with mock.patch.object(
            guard, "get_snapshot", return_value=(proxies, selector, "candidate")
        ), mock.patch.object(guard, "read_state", return_value=state), mock.patch.object(
            guard, "local_network_status", return_value=True
        ), mock.patch.object(
            guard, "_run_candidate_validation"
        ) as validation, mock.patch.object(guard, "log"):
            self.assertEqual(guard.main_once(), 0)
        validation.assert_called_once_with(
            state, "candidate", resume_target="candidate"
        )

    def test_switching_back_to_historical_node_is_still_manual(self):
        selector = {"type": "Selector", "now": "old", "all": ["old", "managed"]}
        proxies = {
            guard.SELECTOR: selector,
            "old": {"type": "VLESS"},
            "managed": {"type": "VLESS"},
        }
        state = guard._default_state()
        state.update(
            {
                "node": "managed",
                "controller_selected": "managed",
                "manual_accepted": "old",
            }
        )
        with mock.patch.object(
            guard, "get_snapshot", return_value=(proxies, selector, "old")
        ), mock.patch.object(guard, "read_state", return_value=state), mock.patch.object(
            guard, "probe", return_value=15
        ), mock.patch.object(guard, "save_state"), mock.patch.object(guard, "log"):
            guard.main_once()
        self.assertEqual(state["manual_accepted"], "old")
        self.assertEqual(state["controller_selected"], "")
        self.assertEqual(state["last"], "MANUAL_ACCEPTED")

    def test_suspect_probe_recovery_resets_failure_count(self):
        selector = {"type": "Selector", "now": "node", "all": ["node"]}
        proxies = {guard.SELECTOR: selector, "node": {"type": "VLESS"}}
        state = guard._default_state()
        state.update({"node": "node", "fails": 1, "phase": "SUSPECT"})
        with mock.patch.object(
            guard, "get_snapshot", return_value=(proxies, selector, "node")
        ), mock.patch.object(guard, "read_state", return_value=state), mock.patch.object(
            guard, "probe", return_value=35
        ), mock.patch.object(guard, "save_state"), mock.patch.object(guard, "log"):
            guard.main_once()
        self.assertEqual(state["fails"], 0)
        self.assertEqual(state["phase"], "HEALTHY")

    def test_local_offline_waits_until_retry_without_scanning(self):
        selector = {"type": "Selector", "now": "node", "all": ["node"]}
        proxies = {guard.SELECTOR: selector, "node": {"type": "VLESS"}}
        state = guard._default_state()
        state.update(
            {
                "node": "node",
                "fails": guard.FAIL_LIMIT,
                "phase": "LOCAL_OFFLINE",
                "last": "LOCAL_OFFLINE",
                "next_retry_at": 2000,
            }
        )
        with mock.patch.object(
            guard, "get_snapshot", return_value=(proxies, selector, "node")
        ), mock.patch.object(guard, "read_state", return_value=state), mock.patch.object(
            guard, "probe", return_value=None
        ), mock.patch.object(guard.time, "time", return_value=1000), mock.patch.object(
            guard, "local_network_status"
        ) as local_check, mock.patch.object(guard, "save_state"), mock.patch.object(
            guard, "log"
        ):
            guard.main_once()
        local_check.assert_not_called()
        self.assertEqual(state["phase"], "LOCAL_OFFLINE")
        self.assertEqual(state["next_retry_at"], 2000)


if __name__ == "__main__":
    unittest.main()
