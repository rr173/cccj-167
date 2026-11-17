"""离线守卫与输入安全测试。"""

from __future__ import annotations

import unittest
from pathlib import Path

from dlq_recovery.errors import InputError
from dlq_recovery.offline import assert_offline_package, scan_source
from dlq_recovery.models import load_policy, load_records

from .helpers import write_json, write_jsonl, msg

REPO = Path(__file__).resolve().parent.parent


class OfflineGuardTests(unittest.TestCase):
    def test_package_has_no_network_imports(self):
        problems = assert_offline_package(REPO / "dlq_recovery")
        self.assertEqual(problems, [])

    def test_scanner_flags_network_import(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "evil.py"
            path.write_text("import socket\nsocket.create_connection(('x', 1))\n")
            problems = scan_source(path)
        self.assertTrue(any("socket" in p for p in problems))
        self.assertTrue(any("create_connection" in p for p in problems))

    def test_scanner_flags_from_import(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "evil2.py"
            path.write_text("from confluent_kafka import Producer\n")
            problems = scan_source(path)
        self.assertTrue(problems)


class InputSafetyTests(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        self.dir = Path(self.td.name)

    def test_duplicate_json_keys_rejected(self):
        path = self.dir / "dl.jsonl"
        path.write_text(
            '{"message":{"message_id":"a","message_id":"b"},'
            '"failure":{"delivery_count":1,"reason":"x"}}\n'
        )
        with self.assertRaises(InputError):
            load_records(path)

    def test_nan_payload_rejected(self):
        path = self.dir / "dl.jsonl"
        path.write_text(
            '{"message":{"message_id":"a","business_key":"k","partition":"p1",'
            '"offset":1,"payload":{"x":NaN},"event_type":"e","status":"s",'
            '"occurred_at":1},"failure":{"delivery_count":1,"reason":"x"}}\n'
        )
        with self.assertRaises(InputError):
            load_records(path)

    def test_unknown_field_rejected(self):
        path = self.dir / "dl.jsonl"
        row = msg(message_id="a", business_key="k", partition="p1", offset=1)
        row["message"]["typo_field"] = 1
        write_jsonl(path, [row])
        with self.assertRaises(InputError):
            load_records(path)

    def test_missing_occurred_at_rejected(self):
        path = self.dir / "dl.jsonl"
        row = msg(message_id="a", business_key="k", partition="p1", offset=1)
        del row["message"]["occurred_at"]
        write_jsonl(path, [row])
        with self.assertRaises(InputError) as ctx:
            load_records(path)
        self.assertIn("occurred_at", ctx.exception.message)

    def test_negative_offset_rejected(self):
        path = self.dir / "dl.jsonl"
        row = msg(message_id="a", business_key="k", partition="p1", offset=-1)
        write_jsonl(path, [row])
        with self.assertRaises(InputError):
            load_records(path)

    def test_empty_dead_letter_rejected(self):
        path = self.dir / "dl.jsonl"
        path.write_text("\n\n")
        with self.assertRaises(InputError):
            load_records(path)

    def test_policy_overlap_rejected(self):
        path = write_json(
            self.dir / "policy.json",
            {"problem_statuses": ["active"], "final_statuses": ["active"]},
        )
        policy = load_policy(path)
        from dlq_recovery.plan import build_plan

        # 直接构建计划应报配置冲突
        rows_path = write_jsonl(
            self.dir / "dl.jsonl",
            [msg(message_id="a", business_key="k", partition="p1", offset=1)],
        )
        with self.assertRaises(InputError):
            build_plan(load_records(rows_path), {}, policy)


if __name__ == "__main__":
    unittest.main()
