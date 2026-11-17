"""端到端测试：预览 → 批准 → 导出 → 校验，以及撤回与导出中断。"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from dlq_recovery.approvals import load_ledger, record_approval, record_withdrawal
from dlq_recovery.errors import IntegrityError, PolicyError, WorkflowError
from dlq_recovery.models import Approval
from dlq_recovery.package import export_package, verify_package
from dlq_recovery.plan import assert_exportable, build_plan

from .helpers import items_for_key, msg, plan_from_rows, write_jsonl

REPO = Path(__file__).resolve().parent.parent


def run_cli(args, cwd=REPO):
    return subprocess.run(
        [sys.executable, "-m", "dlq_recovery", *args],
        capture_output=True,
        text=True,
        cwd=cwd,
    )


class CliFlowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.dl = write_jsonl(
            self.tmp / "dl.jsonl",
            [
                msg(message_id="m-p2-10", business_key="k-p2-10", partition="p2", offset=10),
                msg(message_id="m-p1-5", business_key="k-p1-5", partition="p1", offset=5),
                msg(message_id="m-p1-2", business_key="k-p1-2", partition="p1", offset=2),
                msg(message_id="m-p2-1", business_key="k-p2-1", partition="p2", offset=1),
            ],
        )
        self.ledger = self.tmp / "approvals.jsonl"
        self.pkg = self.tmp / "pkg"
        self.common = ["--dead-letter", str(self.dl), "--approvals", str(self.ledger)]

    def _preview(self):
        p = run_cli(["preview", "--json", *self.common])
        self.assertEqual(p.returncode, 0, p.stderr)
        return json.loads(p.stdout)

    def test_full_flow_orders_partition_files(self):
        plan = self._preview()
        for item in plan["items"]:
            p = run_cli(["approve", *self.common, "--event-id", item["event_id"], "--by", "alice"])
            self.assertEqual(p.returncode, 0, p.stderr)

        p = run_cli(["export", *self.common, "--out", str(self.pkg)])
        self.assertEqual(p.returncode, 0, p.stderr)

        p1 = [
            json.loads(line)
            for line in (self.pkg / "partitions/p-p1.ndjson").read_text().splitlines()
        ]
        p2 = [
            json.loads(line)
            for line in (self.pkg / "partitions/p-p2.ndjson").read_text().splitlines()
        ]
        self.assertEqual([r["offset"] for r in p1], [2, 5])
        self.assertEqual([r["offset"] for r in p2], [1, 10])
        self.assertEqual([r["partition_sequence"] for r in p1], [1, 2])

        for record in p1 + p2:
            self.assertEqual(record["record_type"], "replay")
            self.assertIn("source_records", record)
            self.assertTrue(record["source_records"])
            self.assertEqual(record["approval"]["approved_by"], "alice")
            self.assertIn("failure_reasons", record)
            self.assertIn("failure_evidence", record)

        v = run_cli(["verify", "--package", str(self.pkg)])
        self.assertEqual(v.returncode, 0, v.stdout + v.stderr)
        self.assertTrue(json.loads(v.stdout)["ok"])

    def test_export_requires_approval(self):
        self._preview()
        p = run_cli(["export", *self.common, "--out", str(self.pkg)])
        self.assertEqual(p.returncode, 6)
        self.assertFalse(self.pkg.exists())

    def test_withdraw_removes_event_from_next_export(self):
        plan = self._preview()
        target = plan["items"][0]["event_id"]
        for item in plan["items"]:
            run_cli(["approve", *self.common, "--event-id", item["event_id"], "--by", "alice"])
        p = run_cli(["export", *self.common, "--out", str(self.pkg)])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn(target, json.loads(p.stdout)["exported_events"])

        w = run_cli(
            ["withdraw", "--approvals", str(self.ledger), "--event-id", target,
             "--by", "alice", "--reason", "误批"]
        )
        self.assertEqual(w.returncode, 0, w.stderr)
        self.assertNotIn(target, load_ledger(self.ledger).grants)

        # 重新导出到新目录，撤回的版本不应再出现
        pkg2 = self.tmp / "pkg2"
        p2 = run_cli(["export", *self.common, "--out", str(pkg2)])
        self.assertEqual(p2.returncode, 0, p2.stderr)
        self.assertNotIn(target, json.loads(p2.stdout)["exported_events"])
        for f in (pkg2 / "partitions").glob("*.ndjson"):
            for line in f.read_text().splitlines():
                self.assertNotEqual(json.loads(line)["event_id"], target)

    def test_withdraw_unknown_event_fails(self):
        p = run_cli(
            ["withdraw", "--approvals", str(self.ledger), "--event-id", "ev-nope", "--by", "a"]
        )
        self.assertEqual(p.returncode, 8)

    def test_double_approve_is_rejected(self):
        plan = self._preview()
        eid = plan["items"][0]["event_id"]
        first = run_cli(["approve", *self.common, "--event-id", eid, "--by", "alice"])
        self.assertEqual(first.returncode, 0, first.stderr)
        second = run_cli(["approve", *self.common, "--event-id", eid, "--by", "bob"])
        self.assertEqual(second.returncode, 8)

    def test_approve_unknown_event_fails(self):
        self._preview()
        p = run_cli(["approve", *self.common, "--event-id", "ev-unknown", "--by", "alice"])
        self.assertEqual(p.returncode, 5)

    def test_preview_is_read_only(self):
        plan = self._preview()
        self.assertFalse(self.ledger.exists())
        self.assertFalse(self.pkg.exists())
        self.assertEqual(len(plan["items"]), 4)

    def test_stale_approval_blocks_export(self):
        plan = self._preview()
        eid = plan["items"][0]["event_id"]
        self.ledger.write_text(
            json.dumps(
                {
                    "type": "approve",
                    "event_id": eid,
                    "action": "retry",
                    "approved_by": "alice",
                    "approved_at": "2026-01-01T00:00:00Z",
                    "plan_digest": "0" * 64,
                }
            )
            + "\n"
        )
        p = run_cli(["export", *self.common, "--out", str(self.pkg)])
        self.assertEqual(p.returncode, 6)
        self.assertFalse(self.pkg.exists())


class ExportInterruptionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.rows = [
            msg(message_id=f"m{i}", business_key=f"k{i}", partition="p1", offset=i)
            for i in range(1, 4)
        ]

    def _plan_with_all_approved(self):
        base = plan_from_rows(self.rows)
        grants = {
            it.event_id: Approval(
                event_id=it.event_id,
                action="retry",
                approved_by="alice",
                approved_at="2026-01-01T00:00:00Z",
                plan_digest=base.digest,
            )
            for it in base.items
        }
        return plan_from_rows(self.rows, grants=grants)

    def test_staging_leftover_does_not_create_partial_package(self):
        """重命名到最终目录时中断：目标目录不能出现半成品，临时目录必须清理。"""

        import dlq_recovery.package as package_mod

        plan = self._plan_with_all_approved()
        out = self.tmp / "pkg"
        real_replace = package_mod.os.replace
        calls = {"n": 0}

        def failing_replace(src, dst):
            calls["n"] += 1
            # 前几次是 staging 内部写文件用的原子替换，最后一次才是发布
            if str(dst) == str(out):
                raise OSError("模拟导出中断")
            return real_replace(src, dst)

        package_mod.os.replace = failing_replace  # type: ignore[assignment]
        try:
            with self.assertRaises(OSError):
                export_package(plan, out)
        finally:
            package_mod.os.replace = real_replace  # type: ignore[assignment]
        self.assertGreater(calls["n"], 0)
        self.assertFalse(out.exists(), "中断后不应留下半成品目录")
        leftovers = [p.name for p in self.tmp.iterdir() if p.name.startswith(".pkg.staging")]
        self.assertEqual(leftovers, [])

    def test_interrupted_staging_dir_is_not_verifiable(self):
        """模拟进程被杀后残留的 staging 目录：不能被当成有效包。"""

        plan = self._plan_with_all_approved()
        out = self.tmp / "pkg"
        export_package(plan, out)
        staging = self.tmp / ".pkg.staging-dead"
        shutil.copytree(out, staging)
        (staging / ".complete").unlink()
        with self.assertRaises(IntegrityError):
            verify_package(staging)

    def test_missing_complete_marker_is_detected(self):
        plan = self._plan_with_all_approved()
        out = self.tmp / "pkg"
        export_package(plan, out)
        (out / ".complete").unlink()
        with self.assertRaises(IntegrityError) as ctx:
            verify_package(out)
        self.assertIn("中断", ctx.exception.message)

    def test_missing_partition_file_is_detected(self):
        plan = self._plan_with_all_approved()
        out = self.tmp / "pkg"
        export_package(plan, out)
        (out / "partitions/p-p1.ndjson").unlink()
        with self.assertRaises(IntegrityError):
            verify_package(out)

    def test_tampered_partition_file_is_detected(self):
        plan = self._plan_with_all_approved()
        out = self.tmp / "pkg"
        export_package(plan, out)
        path = out / "partitions/p-p1.ndjson"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows[0]["payload"]["tampered"] = True
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        with self.assertRaises(IntegrityError) as ctx:
            verify_package(out)
        kinds = {p["kind"] for p in ctx.exception.details["report"]["problems"]}
        self.assertIn("checksum_mismatch", kinds)

    def test_step_removed_out_of_order_is_detected(self):
        plan = self._plan_with_all_approved()
        out = self.tmp / "pkg"
        export_package(plan, out)
        path = out / "partitions/p-p1.ndjson"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        path.write_text("".join(json.dumps(r) + "\n" for r in reversed(rows)))
        # 手工同步 checksums，使只剩余顺序校验能发现问题
        import hashlib

        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        manifest_path = out / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["files"]["partitions/p-p1.ndjson"]["sha256"] = digest
        manifest_path.write_text(json.dumps(manifest))
        sums = out / "checksums.sha256"
        lines = []
        for line in sums.read_text().splitlines():
            old, _, name = line.partition("  ")
            if name == "partitions/p-p1.ndjson":
                old = digest
            lines.append(f"{old}  {name}")
        sums.write_text("\n".join(lines) + "\n")
        # checksums 文件自身哈希也需同步，否则先报 checksum_mismatch
        manifest["files"]["checksums.sha256"]["sha256"] = hashlib.sha256(
            sums.read_bytes()
        ).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(IntegrityError) as ctx:
            verify_package(out)
        kinds = {p["kind"] for p in ctx.exception.details["report"]["problems"]}
        self.assertIn("partition_offset_out_of_order", kinds)

    def test_export_refuses_non_empty_output(self):
        plan = self._plan_with_all_approved()
        out = self.tmp / "pkg"
        out.mkdir()
        (out / "keep.txt").write_text("existing")
        with self.assertRaises(WorkflowError):
            export_package(plan, out)
        self.assertTrue((out / "keep.txt").exists())


class ApprovalLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.path = self.tmp / "ledger.jsonl"

    def test_approve_then_withdraw_round_trip(self):
        record_approval(
            self.path, event_id="ev-1", action="retry", approved_by="alice",
            plan_digest="d" * 64, event_version={"partition": "p1", "offset": 1},
        )
        self.assertIn("ev-1", load_ledger(self.path).grants)
        record_withdrawal(self.path, event_id="ev-1", withdrawn_by="bob")
        self.assertNotIn("ev-1", load_ledger(self.path).grants)
        history = load_ledger(self.path).records
        self.assertEqual([r["type"] for r in history], ["approve", "withdraw"])

    def test_reapprove_after_withdraw(self):
        record_approval(self.path, event_id="ev-1", action="retry", approved_by="a",
                        plan_digest="d" * 64, event_version={})
        record_withdrawal(self.path, event_id="ev-1", withdrawn_by="b")
        record_approval(self.path, event_id="ev-1", action="retry", approved_by="c",
                        plan_digest="e" * 64, event_version={})
        state = load_ledger(self.path)
        self.assertEqual(state.grants["ev-1"].approved_by, "c")

    def test_corrupt_ledger_is_rejected(self):
        self.path.write_text("{not json}\n")
        with self.assertRaises(Exception):
            load_ledger(self.path)


if __name__ == "__main__":
    unittest.main()
