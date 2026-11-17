"""对账与补投的完整行为测试。

覆盖需求清单：

- 两个分区中缺回执只阻断一个分区、阻塞点截留同分区后续事件；
- 重复/拆分/乱序回执幂等收敛且保留全部来源；
- 未知被同次尝试的确定结果消解（未知转成功/未执行）；
- 同次尝试成功与明确未执行并存构成矛盾，阻断自动补投；
- 迟到的旧尝试回执不能归入新尝试；已确认成功禁止再次补投，跨尝试矛盾展示异常；
- 未完成的补投尝试禁止重复签发；
- 发布失败（无完整包/完整包未追认）后可恢复并继续对账；
- 回执格式与身份绑定错误整文件原子拒收；
- 补投包校验拒绝替换源包、重复事件、越过阻塞位置和与登记不符。
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from dlq_recovery.errors import InputError, IntegrityError, PolicyError, ValidationError, WorkflowError
from dlq_recovery.recon import (
    EFFECTIVE_CONFLICT,
    EFFECTIVE_MISSING,
    EFFECTIVE_NOT_EXECUTED,
    EFFECTIVE_SUCCESS,
    EFFECTIVE_UNKNOWN,
    ReconciliationStore,
    compute_replay_candidates,
)
from dlq_recovery.replay import verify_replay_package

from .recon_fixtures import ReconciliationFixture, receipt, write_receipts

REPO = Path(__file__).resolve().parent.parent


def run_cli(args):
    return subprocess.run(
        [sys.executable, "-m", "dlq_recovery", *args],
        capture_output=True, text=True, cwd=REPO,
    )


class PartitionBlockingTests(ReconciliationFixture):
    def test_missing_receipt_blocks_only_one_partition(self):
        # p-a：全部拿到确定结论；p-b：第一个事件缺回执。
        rows = [
            self.r(self.eid("p-a", 1), "success"),
            self.r(self.eid("p-a", 2), "not_executed"),
            self.r(self.eid("p-a", 3), "not_executed"),
            self.r(self.eid("p-b", 2), "not_executed"),
            self.r(self.eid("p-b", 3), "not_executed"),
        ]
        self.import_rows(rows)
        view = self.view()
        preview = view["next_replay_preview"]
        included = sorted((i["partition"], i["offset"]) for i in preview["included"])
        # p-b-1 缺回执：整个 p-b 没有任何事件入选；p-a 不受牵连
        self.assertEqual(included, [("p-a", 2), ("p-a", 3)])
        blockers = {(b["partition"], b["offset"]) for b in preview["blockers"]}
        self.assertEqual(blockers, {("p-b", 1)})
        withheld = {(w["partition"], w["offset"]) for w in preview["withheld"]}
        # p-b-2/3 虽然明确未执行，但位于阻塞点之后必须截留
        self.assertEqual(withheld, {("p-b", 2), ("p-b", 3)})

    def test_success_skips_and_unknown_blocks_later_events(self):
        rows = [
            self.r(self.eid("p-a", 1), "not_executed"),
            self.r(self.eid("p-a", 2), "unknown", detail="timeout"),
            self.r(self.eid("p-a", 3), "not_executed"),
        ]
        self.import_rows(rows)
        preview = self.view()["next_replay_preview"]
        included = [i["offset"] for i in preview["included"]]
        self.assertEqual(included, [1])  # 越过未知点前只有 1
        pa_blockers = [b["offset"] for b in preview["blockers"] if b["partition"] == "p-a"]
        self.assertEqual(pa_blockers, [2])
        pa_withheld = [w["offset"] for w in preview["withheld"] if w["partition"] == "p-a"]
        self.assertEqual(pa_withheld, [3])

    def test_timeout_unknown_is_not_failure(self):
        self.import_rows([self.r(self.eid("p-a", 1), "unknown", detail="timeout")])
        self.assertEqual(self.effective(self.eid("p-a", 1)), EFFECTIVE_UNKNOWN)
        # 没有任何明确未执行事件 -> 没有可补投批次
        with self.assertRaises(PolicyError):
            self.store.issue_replay(chain_id=self.chain_id, by="alice")

    def test_no_receipt_at_all_is_missing_not_failure(self):
        self.assertEqual(self.effective(self.eid("p-a", 1)), EFFECTIVE_MISSING)
        with self.assertRaises(PolicyError):
            self.store.issue_replay(chain_id=self.chain_id, by="alice")


class ReceiptConvergenceTests(ReconciliationFixture):
    def test_duplicate_split_and_out_of_order_converge(self):
        e1, e2 = self.eid("p-a", 1), self.eid("p-a", 2)
        # 拆成两个文件、乱序，再把文件 1 重复导入一次
        f1 = self.tmp / "part1.jsonl"
        f2 = self.tmp / "part2.jsonl"
        write_receipts(f1, [self.r(e2, "success")])
        write_receipts(f2, [self.r(e1, "not_executed")])
        first = self.store.import_receipts(f1, by="alice")
        second = self.store.import_receipts(f2, by="bob")
        duplicate = self.store.import_receipts(f1, by="alice")
        self.assertEqual(first["new_evidence"], 1)
        self.assertEqual(second["new_evidence"], 1)
        self.assertEqual(duplicate["new_evidence"], 0)
        self.assertEqual(duplicate["duplicate_evidence"], 1)
        # 最终派生态与导入顺序/分块无关
        self.assertEqual(self.effective(e1), EFFECTIVE_NOT_EXECUTED)
        self.assertEqual(self.effective(e2), EFFECTIVE_SUCCESS)
        # 重复证据保留可追溯来源（同一 evidence_hash 下两条 provenance）
        state = self.store.load()
        obs = [o for (aid, e, _h), o in state.observations.items() if e == e2]
        self.assertEqual(len(obs), 1)
        sources = {p["imported_by"] for p in obs[0].provenance}
        self.assertEqual(sources, {"alice"})
        self.assertEqual(len(obs[0].provenance), 2)

    def test_unknown_resolved_by_later_definite_result_same_attempt(self):
        e1 = self.eid("p-a", 1)
        self.import_rows([self.r(e1, "unknown")], name="u.jsonl")
        self.assertEqual(self.effective(e1), EFFECTIVE_UNKNOWN)
        self.import_rows([self.r(e1, "success")], name="s.jsonl")
        self.assertEqual(self.effective(e1), EFFECTIVE_SUCCESS)
        # 反向：先未执行后未知，确定结果不被未知覆盖
        e2 = self.eid("p-a", 2)
        self.import_rows([self.r(e2, "not_executed")], name="n.jsonl")
        self.import_rows([self.r(e2, "unknown")], name="u2.jsonl")
        self.assertEqual(self.effective(e2), EFFECTIVE_NOT_EXECUTED)

    def test_conflicting_success_and_not_executed_blocks_event(self):
        e1 = self.eid("p-a", 1)
        self.import_rows([self.r(e1, "success")], name="ok.jsonl")
        self.import_rows([self.r(e1, "not_executed")], name="bad.jsonl")
        self.assertEqual(self.effective(e1), EFFECTIVE_CONFLICT)
        preview = self.view()["next_replay_preview"]
        self.assertNotIn(e1, [i["event_id"] for i in preview["included"]])
        # 矛盾是 p-a 第一个事件 -> 同分区后续全部截留
        self.assertTrue(any(b["event_id"] == e1 for b in preview["blockers"]))
        anomalies = {a["kind"] for a in self.view()["anomalies"]}
        self.assertIn("conflicting_evidence", anomalies)
        # 再补任何证据都不能消解矛盾（成功与未执行仍然并存）
        self.import_rows([self.r(e1, "success")], name="ok2.jsonl")
        self.assertEqual(self.effective(e1), EFFECTIVE_CONFLICT)


class BindingAndAtomicityTests(ReconciliationFixture):
    def _write(self, name, rows):
        path = self.tmp / name
        write_receipts(path, rows)
        return path

    def test_unknown_attempt_rejected(self):
        path = self._write("x.jsonl", [
            receipt("attempt-9999", self.package_digest, self.eid("p-a", 1),
                    self.sha(self.eid("p-a", 1)), "success"),
        ])
        with self.assertRaises(ValidationError):
            self.store.import_receipts(path, by="alice")

    def test_wrong_package_digest_rejected(self):
        path = self._write("x.jsonl", [
            receipt(self.origin_attempt, "00" * 32, self.eid("p-a", 1),
                    self.sha(self.eid("p-a", 1)), "success"),
        ])
        with self.assertRaises(ValidationError):
            self.store.import_receipts(path, by="alice")

    def test_unknown_event_rejected(self):
        path = self._write("x.jsonl", [
            receipt(self.origin_attempt, self.package_digest, "ev-does-not-exist",
                    "ab" * 32, "success"),
        ])
        with self.assertRaises(ValidationError):
            self.store.import_receipts(path, by="alice")

    def test_wrong_payload_digest_rejected(self):
        path = self._write("x.jsonl", [
            receipt(self.origin_attempt, self.package_digest, self.eid("p-a", 1),
                    "cd" * 32, "success"),
        ])
        with self.assertRaises(ValidationError):
            self.store.import_receipts(path, by="alice")

    def test_malformed_file_leaves_no_partial_state(self):
        good = self.r(self.eid("p-a", 1), "success")
        path = self.tmp / "broken.jsonl"
        path.write_text(json.dumps(good) + "\n{not valid json\n")
        before = self.store.verify_log()["entries"]
        with self.assertRaises(InputError):
            self.store.import_receipts(path, by="alice")
        after = self.store.verify_log()["entries"]
        self.assertEqual(before, after)
        # 好行也没有生效
        self.assertEqual(self.effective(self.eid("p-a", 1)), EFFECTIVE_MISSING)
        # 归档目录没有新增文件
        archived = list((self.store_path / "log/receipts").glob("*")) if (
            self.store_path / "log/receipts").exists() else []
        self.assertEqual(archived, [])

    def test_archive_write_failure_rolls_back_log_entry(self):
        import dlq_recovery.recon as recon_mod

        path = self.tmp / "ok.jsonl"
        write_receipts(path, [self.r(self.eid("p-a", 1), "success")])
        before = self.store.verify_log()["entries"]
        original_replace = recon_mod.os.replace

        def fail_on_archive(src, dst):
            if "log/receipts" in str(dst):
                raise OSError("模拟归档盘故障")
            return original_replace(src, dst)

        recon_mod.os.replace = fail_on_archive
        try:
            with self.assertRaises(OSError):
                self.store.import_receipts(path, by="alice")
        finally:
            recon_mod.os.replace = original_replace
        # 日志与派生态都回滚到导入前
        self.assertEqual(self.store.verify_log()["entries"], before)
        self.assertEqual(self.effective(self.eid("p-a", 1)), EFFECTIVE_MISSING)
        # 存储仍然可用，重新导入成功
        result = self.store.import_receipts(path, by="alice")
        self.assertEqual(result["new_evidence"], 1)
        self.assertEqual(self.effective(self.eid("p-a", 1)), EFFECTIVE_SUCCESS)

    def test_mixed_attempts_in_one_file_rejected(self):
        rows = [
            self.r(self.eid("p-a", 1), "success"),
            receipt("attempt-0002", self.package_digest, self.eid("p-a", 2),
                    self.sha(self.eid("p-a", 2)), "success"),
        ]
        path = self._write("mixed.jsonl", rows)
        with self.assertRaises(InputError):
            self.store.import_receipts(path, by="alice")

    def test_duplicate_registration_rejected(self):
        with self.assertRaises(WorkflowError):
            self.store.register_package(self.pkg, by="alice")


class ReplayIssuanceTests(ReconciliationFixture):
    def _all_not_executed(self, partition: str):
        return [self.r(self.eid(partition, off), "not_executed") for off in (1, 2, 3)]

    def test_new_attempt_only_contains_definite_failures(self):
        self.import_rows(self._all_not_executed("p-a"))
        result = self.store.issue_replay(chain_id=self.chain_id, by="alice")
        self.assertEqual(result["attempt_id"], "attempt-0002")
        self.assertEqual(result["prev_attempt_id"], self.origin_attempt)
        issued = set(result["events"])
        self.assertEqual(issued, {self.eid("p-a", o) for o in (1, 2, 3)})
        # 新尝试是独立身份
        state = self.store.load()
        new_attempt = state.attempts["attempt-0002"]
        self.assertEqual(new_attempt["kind"], "replay")
        self.assertNotEqual(new_attempt["package_digest"], self.package_digest)
        # 每条记录带前次失败依据
        pkg_dir = self.store_path / new_attempt["package_path"]
        rows = [json.loads(line) for pf in (pkg_dir / "partitions").glob("*.ndjson")
                for line in pf.read_text().splitlines()]
        for row in rows:
            self.assertEqual(row["replay"]["attempt_id"], "attempt-0002")
            self.assertEqual(row["replay"]["prev_attempt_id"], self.origin_attempt)
            self.assertEqual(row["replay"]["basis"]["basis_attempt_id"], self.origin_attempt)
            self.assertEqual(row["replay"]["basis"]["effective_result"], "not_executed")
            # 原包载荷、批准、来源证据原样保留
            origin = row["origin"]
            self.assertEqual(origin["origin_attempt_id"], self.origin_attempt)
            self.assertTrue(origin["source_records"])
            self.assertIsInstance(origin["approval"], dict)

    def test_successful_event_never_reissued(self):
        rows = [
            self.r(self.eid("p-a", 1), "success"),
            self.r(self.eid("p-a", 2), "not_executed"),
            self.r(self.eid("p-a", 3), "not_executed"),
        ]
        self.import_rows(rows)
        result = self.store.issue_replay(chain_id=self.chain_id, by="alice")
        self.assertNotIn(self.eid("p-a", 1), result["events"])
        # 补投尝试里又把 p-a-2 报成功，p-a-3 仍未执行；第二次补投只能含 p-a-3
        state = self.store.load()
        replay = state.attempts["attempt-0002"]
        dig = replay["package_digest"]
        rows2 = [
            receipt("attempt-0002", dig, self.eid("p-a", 2), self.sha(self.eid("p-a", 2)),
                    "success"),
            receipt("attempt-0002", dig, self.eid("p-a", 3), self.sha(self.eid("p-a", 3)),
                    "not_executed"),
        ]
        path = self.tmp / "r2.jsonl"
        write_receipts(path, rows2)
        self.store.import_receipts(path, by="alice")
        # 上一轮补投回执收齐后封存，才能签发下一轮（未完成对账禁止重复签发）
        self.store.seal_attempt("attempt-0002", by="alice", reason="回执收齐")
        second = self.store.issue_replay(chain_id=self.chain_id, by="alice")
        self.assertEqual(second["attempt_id"], "attempt-0003")
        self.assertEqual(second["events"], [self.eid("p-a", 3)])

    def test_double_issuance_blocked_while_replay_open(self):
        self.import_rows(self._all_not_executed("p-a"))
        self.store.issue_replay(chain_id=self.chain_id, by="alice")
        with self.assertRaises(WorkflowError):
            self.store.issue_replay(chain_id=self.chain_id, by="alice")

    def test_seal_closes_replay_and_abort_requires_missing_package(self):
        self.import_rows(self._all_not_executed("p-a"))
        issued = self.store.issue_replay(chain_id=self.chain_id, by="alice")
        # 包完整存在时不能人工中止（可能已交付下游）
        with self.assertRaises(WorkflowError):
            self.store.abort_attempt(issued["attempt_id"], by="alice", reason="x")
        # 删除包目录后可以中止并释放事件
        shutil.rmtree(Path(issued["package_dir"]))
        result = self.store.abort_attempt(issued["attempt_id"], by="alice", reason="包未发出")
        self.assertEqual(result["status"], "aborted")
        state = self.store.load()
        self.assertEqual(state.attempts[issued["attempt_id"]]["status"], "aborted")
        # 释放后可重新签发
        again = self.store.issue_replay(chain_id=self.chain_id, by="alice")
        self.assertEqual(again["attempt_id"], "attempt-0003")
        # 封存未知尝试 / 重复封存都被拒绝
        with self.assertRaises(ValidationError):
            self.store.seal_attempt("attempt-9999", by="alice", reason=None)
        self.store.seal_attempt(again["attempt_id"], by="alice", reason="done")
        with self.assertRaises(WorkflowError):
            self.store.seal_attempt(again["attempt_id"], by="alice", reason="again")

    def test_preview_does_not_occupy_events(self):
        self.import_rows(self._all_not_executed("p-a"))
        before = self.view()["next_replay_preview"]
        # 多次预览不产生尝试、不改变候选
        self.view()
        self.view()
        after = self.view()["next_replay_preview"]
        self.assertEqual(
            [i["event_id"] for i in before["included"]],
            [i["event_id"] for i in after["included"]],
        )
        state = self.store.load()
        self.assertEqual(set(state.attempts), {self.origin_attempt})

    def test_chain_of_failures_requires_each_new_attempt_definite_failure(self):
        # 第一次补投后仍是未执行 -> 可以再补；依据必须指向最近一次失败尝试
        self.import_rows(self._all_not_executed("p-a"))
        self.store.issue_replay(chain_id=self.chain_id, by="alice")
        state = self.store.load()
        a2 = state.attempts["attempt-0002"]
        rows = [
            receipt("attempt-0002", a2["package_digest"], eid, self.sha(eid), "not_executed")
            for eid in a2["events"]
        ]
        path = self.tmp / "again.jsonl"
        write_receipts(path, rows)
        self.store.import_receipts(path, by="alice")
        self.store.seal_attempt("attempt-0002", by="alice", reason="第二轮回执收齐")
        third = self.store.issue_replay(chain_id=self.chain_id, by="alice")
        self.assertEqual(third["prev_attempt_id"], "attempt-0002")
        state = self.store.load()
        a3 = state.attempts["attempt-0003"]
        pkg_dir = self.store_path / a3["package_path"]
        first_row = json.loads(
            next((pkg_dir / "partitions").glob("*.ndjson")).read_text().splitlines()[0]
        )
        self.assertEqual(first_row["replay"]["basis"]["basis_attempt_id"], "attempt-0002")


class LateReceiptAndAnomalyTests(ReconciliationFixture):
    def test_late_receipt_for_old_attempt_stays_with_old_attempt(self):
        self.import_rows([
            self.r(self.eid("p-a", 1), "not_executed"),
            self.r(self.eid("p-a", 2), "not_executed"),
            self.r(self.eid("p-a", 3), "not_executed"),
        ])
        issued = self.store.issue_replay(chain_id=self.chain_id, by="alice")
        state = self.store.load()
        a2_digest = state.attempts["attempt-0002"]["package_digest"]
        # 新尝试的回执必须用新尝试的 digest；旧 digest 不能混入
        bad = self.tmp / "bad-binding.jsonl"
        write_receipts(bad, [
            receipt("attempt-0002", self.package_digest, self.eid("p-a", 1),
                    self.sha(self.eid("p-a", 1)), "success"),
        ])
        with self.assertRaises(ValidationError):
            self.store.import_receipts(bad, by="alice")
        # 原尝试的迟到成功回执仍然挂在原尝试上（不能归入新尝试），
        # 并与早先的"明确未执行"形成同次尝试矛盾，同时产生跨尝试异常
        late = self.tmp / "late.jsonl"
        write_receipts(late, [self.r(self.eid("p-a", 1), "success")])
        self.store.import_receipts(late, by="alice")
        view = self.view()
        per = next(e for e in view["events"] if e["event_id"] == self.eid("p-a", 1))
        self.assertIn("attempt-0001", per["per_attempt"])
        self.assertEqual(per["per_attempt"]["attempt-0001"], EFFECTIVE_CONFLICT)
        # 事件已进入后续补投尝试，迟到成功必须以异常形式展示，历史不抹掉
        kinds = {a["kind"] for a in view["anomalies"] if a["event_id"] == self.eid("p-a", 1)}
        self.assertIn("late_success_after_reissue", kinds)
        self.assertIn("conflicting_evidence", kinds)
        # 存在矛盾证据的事件永远不得再自动补投
        self.assertNotIn(
            self.eid("p-a", 1),
            [i["event_id"] for i in view["next_replay_preview"]["included"]],
        )
        self.assertEqual(issued["attempt_id"], "attempt-0002")

    def test_cross_attempt_success_vs_not_executed_is_anomaly_not_erase(self):
        # 场景：原尝试先报未执行 → 事件进入补投尝试 → 原尝试迟到成功回执。
        # 矛盾与跨尝试异常都必须展示，且两个尝试的历史都不能被抹掉。
        e1 = self.eid("p-a", 1)
        self.import_rows([self.r(e1, "not_executed")])
        self.store.issue_replay(chain_id=self.chain_id, by="alice")
        state = self.store.load()
        a2 = state.attempts["attempt-0002"]
        self.assertIn(e1, a2["events"])

        late = self.tmp / "late-success.jsonl"
        write_receipts(late, [self.r(e1, "success")])
        self.store.import_receipts(late, by="alice")
        view = self.view()
        per = next(e for e in view["events"] if e["event_id"] == e1)
        # 原尝试内成功与未执行并存 -> 矛盾；补投尝试的在途事实仍保留
        self.assertEqual(per["per_attempt"]["attempt-0001"], EFFECTIVE_CONFLICT)
        self.assertIn("attempt-0002", per["per_attempt"])
        anomalies = [a for a in view["anomalies"] if a["event_id"] == e1]
        kinds = {a["kind"] for a in anomalies}
        self.assertIn("late_success_after_reissue", kinds)
        self.assertIn("conflicting_evidence", kinds)
        # 两个尝试记录都还在，attempt-0002 没有被删除或改写
        attempt_ids = {a["attempt_id"] for a in view["attempts"]}
        self.assertEqual(attempt_ids, {"attempt-0001", "attempt-0002"})
        # 矛盾事件不会出现在后续补投候选中
        self.assertNotIn(
            e1, [i["event_id"] for i in view["next_replay_preview"]["included"]]
        )


class PublishRecoveryTests(ReconciliationFixture):
    def test_failed_build_aborts_intent_and_frees_events(self):
        from dlq_recovery import replay as replay_mod

        self.import_rows([
            self.r(self.eid("p-a", 1), "not_executed"),
            self.r(self.eid("p-a", 2), "not_executed"),
        ])

        def boom(**kwargs):
            raise OSError("模拟磁盘写失败")

        original = replay_mod.build_replay_package
        replay_mod.build_replay_package = boom
        try:
            with self.assertRaises(OSError):
                self.store.issue_replay(chain_id=self.chain_id, by="alice")
        finally:
            replay_mod.build_replay_package = original

        # 意图已落盘（事件被占用），但没有完整包
        reopened = ReconciliationStore(self.store_path)
        state = reopened._load_and_recover()
        self.assertEqual(
            [r["kind"] for r in state.recovered if r["kind"] == "publish_aborted"],
            ["publish_aborted"],
        )
        attempt = state.attempts["attempt-0002"]
        self.assertEqual(attempt["status"], "aborted")
        self.assertFalse((self.store_path / attempt["package_path"]).exists())
        # 事件释放后可以重新签发
        again = reopened.issue_replay(chain_id=self.chain_id, by="alice")
        self.assertEqual(again["attempt_id"], "attempt-0003")
        report = verify_replay_package(reopened, Path(again["package_dir"]))
        self.assertTrue(report["ok"])

    def test_complete_package_without_published_is_confirmed(self):
        from dlq_recovery.recon import compute_replay_candidates
        from dlq_recovery.replay import build_replay_package, plan_replay_manifest

        self.import_rows([self.r(self.eid("p-a", 1), "not_executed")])
        state = self.store._fold()
        chain = state.chains[self.chain_id]
        candidates = compute_replay_candidates(state, self.chain_id)
        prev = state.chain_attempts(self.chain_id)[-1]
        state.attempt_seq += 1
        new_id = f"attempt-{state.attempt_seq:04d}"
        pkg_path = f"packages/{self.chain_id}/attempts/{new_id}/package"
        manifest, _ = plan_replay_manifest(
            state=state, chain=chain, attempt_id=new_id,
            prev_attempt_id=prev["attempt_id"], included=candidates["included"],
            blockers=candidates["blockers"], withheld=candidates["withheld"],
            created_by="alice",
        )
        self.store._append_entry("attempt_publishing", {
            "attempt_id": new_id, "attempt_number": state.attempt_seq,
            "chain_id": self.chain_id, "seq_in_chain": 2,
            "prev_attempt_id": prev["attempt_id"], "package_path": pkg_path,
            "package_digest": manifest["package_digest"],
            "created_at": "2026-11-17T12:00:00Z", "created_by": "alice",
            "events": candidates["included"], "blockers": candidates["blockers"],
            "withheld": candidates["withheld"],
        })
        folded = self.store._fold()
        build_replay_package(
            state=folded, chain=chain, attempt_id=new_id,
            prev_attempt_id=prev["attempt_id"], included=candidates["included"],
            blockers=candidates["blockers"], withheld=candidates["withheld"],
            out_dir=self.store_path / pkg_path, created_by="alice",
        )
        # 进程在此刻退出：只有 publishing + 完整包，没有 published 条目
        reopened = ReconciliationStore(self.store_path)
        recovered = reopened._load_and_recover()
        self.assertEqual(
            [r["kind"] for r in recovered.recovered if r["kind"] == "publish_confirmed"],
            ["publish_confirmed"],
        )
        attempt = recovered.attempts[new_id]
        self.assertEqual(attempt["status"], "delivered")
        self.assertNotIn("pending_publish", attempt)
        # 旧包可执行 -> 禁止再次签发
        with self.assertRaises(WorkflowError):
            reopened.issue_replay(chain_id=self.chain_id, by="alice")
        # 且包本身校验通过
        report = verify_replay_package(reopened, self.store_path / pkg_path)
        self.assertTrue(report["ok"])

    def test_snapshot_rebuilt_from_log_when_stale(self):
        self.import_rows([self.r(self.eid("p-a", 1), "success")])
        # 删除快照：日志是事实源，仍能完整重建
        (self.store_path / "state.json").unlink()
        view = self.store.reconcile_view(self.chain_id)
        self.assertTrue(view["chains"])
        report = self.store.verify_log()
        self.assertTrue(report["ok"])
        self.assertGreater(report["entries"], 0)

    def test_crash_in_separate_process_is_recovered_on_reopen(self):
        # 子进程在发布意图落盘后、published 前被杀；新进程打开必须恢复。
        self.import_rows([
            self.r(self.eid("p-a", 1), "not_executed"),
            self.r(self.eid("p-a", 2), "not_executed"),
        ])
        crash_code = (
            "import sys, os;"
            "sys.path.insert(0, %r);"
            "from dlq_recovery.recon import ReconciliationStore;"
            "from dlq_recovery import replay as rm;"
            "rm.build_replay_package = lambda **kw: os._exit(42);"
            "ReconciliationStore(%r).issue_replay(chain_id=%r, by='alice')"
            % (str(REPO), str(self.store_path), self.chain_id)
        )
        child = subprocess.run(
            [sys.executable, "-I", "-c", crash_code], capture_output=True, text=True
        )
        self.assertEqual(child.returncode, 42)
        reopened = ReconciliationStore(self.store_path)
        state = reopened._load_and_recover()
        self.assertIn("publish_aborted", [r["kind"] for r in state.recovered])
        self.assertEqual(state.attempts["attempt-0002"]["status"], "aborted")
        again = reopened.issue_replay(chain_id=self.chain_id, by="alice")
        self.assertEqual(again["attempt_id"], "attempt-0003")
        self.assertTrue(
            verify_replay_package(reopened, Path(again["package_dir"]))["ok"]
        )

    def test_hash_chain_tampering_is_detected(self):
        self.import_rows([self.r(self.eid("p-a", 1), "success")])
        log = self.store_path / "log/events.log"
        lines = log.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[-1])
        entry["body"]["imported_by"] = "mallory"
        lines[-1] = json.dumps(entry)
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        with self.assertRaises(IntegrityError):
            self.store.verify_log()

    def test_convergence_independent_of_order_and_chunking(self):
        import itertools

        receipts = [
            self.r(self.eid("p-a", 1), "success"),
            self.r(self.eid("p-a", 2), "not_executed"),
            self.r(self.eid("p-b", 1), "unknown"),
            self.r(self.eid("p-b", 2), "success"),
        ]

        counter = {"n": 0}

        def fold(permutation, chunk):
            counter["n"] += 1
            tag = f"{counter['n']:02d}-{''.join(map(str, permutation))}-c{chunk}"
            store_dir = self.tmp / f"store-{tag}"
            store = ReconciliationStore(store_dir)
            store.register_package(self.pkg, by="alice")
            ordered = [receipts[i] for i in permutation]
            for start in range(0, len(ordered), chunk):
                p = self.tmp / f"r-{tag}-{start}.jsonl"
                write_receipts(p, ordered[start:start + chunk])
                store.import_receipts(p, by="alice")
            state = store.load()
            return {
                eid: state.effective_for(self.origin_attempt, eid)
                for eid in self.event_meta
            }

        baseline = fold((0, 1, 2, 3), 4)
        for perm in itertools.permutations(range(4)):
            for chunk in (1, 2, 4):
                self.assertEqual(fold(perm, chunk), baseline)


class ReplayPackageVerificationTests(ReconciliationFixture):
    def setUp(self):
        super().setUp()
        self.import_rows([
            self.r(self.eid("p-a", 1), "not_executed"),
            self.r(self.eid("p-a", 2), "not_executed"),
            self.r(self.eid("p-a", 3), "not_executed"),
            self.r(self.eid("p-b", 1), "unknown"),
            self.r(self.eid("p-b", 2), "not_executed"),
            self.r(self.eid("p-b", 3), "not_executed"),
        ])
        self.issued = self.store.issue_replay(chain_id=self.chain_id, by="alice")
        self.pkg_dir = Path(self.issued["package_dir"])

    def test_valid_package_verifies(self):
        report = verify_replay_package(self.store, self.pkg_dir)
        self.assertTrue(report["ok"])
        self.assertEqual(report["verified_events"], 3)

    def test_payload_replacement_rejected(self):
        tampered = self.tmp / "tampered"
        shutil.copytree(self.pkg_dir, tampered)
        pf = next((tampered / "partitions").glob("*.ndjson"))
        rows = [json.loads(line) for line in pf.read_text().splitlines()]
        rows[0]["payload"]["injected"] = True
        pf.write_text("".join(json.dumps(r) + "\n" for r in rows))
        with self.assertRaises(IntegrityError) as ctx:
            verify_replay_package(self.store, tampered)
        kinds = {p["kind"] for p in ctx.exception.details["report"]["problems"]}
        self.assertIn("payload_content_replaced", kinds)

    def test_duplicate_event_rejected(self):
        tampered = self.tmp / "dup"
        shutil.copytree(self.pkg_dir, tampered)
        pf = next((tampered / "partitions").glob("*.ndjson"))
        rows = [json.loads(line) for line in pf.read_text().splitlines()]
        rows.append(dict(rows[-1]))  # 重复事件
        pf.write_text("".join(json.dumps(r) + "\n" for r in rows))
        with self.assertRaises(IntegrityError) as ctx:
            verify_replay_package(self.store, tampered)
        kinds = {p["kind"] for p in ctx.exception.details["report"]["problems"]}
        self.assertTrue({"duplicate_event_in_batch", "batch_not_matching_registration"} & kinds)

    def test_event_behind_blocker_cannot_be_sneaked_in(self):
        # p-b-1 是阻塞点；手工把阻塞点之后的 p-b-2 塞进已签发包，必须被拒。
        # 候选集以签发前落盘的意图为准（重算当前候选只用于信息展示）。
        state = self.store.load()
        attempt = state.attempts[self.issued["attempt_id"]]
        intended_ids = {e["event_id"] for e in attempt["event_order"]}
        self.assertNotIn(self.eid("p-b", 2), intended_ids)

        manifest_path = self.pkg_dir / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["events"].append({
            "event_id": self.eid("p-b", 2), "partition": "p-b", "offset": 2,
            "payload_sha256": self.sha(self.eid("p-b", 2)),
            "basis_attempt_id": self.origin_attempt,
        })
        manifest_path.write_text(json.dumps(manifest))
        origin_chain = state.chains[self.chain_id]
        origin_event = next(e for e in origin_chain["events"]
                            if e["event_id"] == self.eid("p-b", 2))
        record = origin_event["replay_record"]
        pf = self.pkg_dir / "partitions" / "p-p-b.ndjson"
        pf.parent.mkdir(parents=True, exist_ok=True)
        pf.write_text(json.dumps({
            "record_type": "replay", "sequence": 99, "partition_sequence": 1,
            "event_id": self.eid("p-b", 2), "business_key": record["business_key"],
            "partition": "p-b", "offset": 2, "event_type": record["event_type"],
            "status": record["status"], "occurred_at": record["occurred_at"],
            "payload": record["payload"], "payload_sha256": record["payload_sha256"],
            "origin": {"origin_attempt_id": self.origin_attempt,
                       "origin_event_id": record["event_id"],
                       "package_digest": self.package_digest,
                       "source_records": record["source_records"],
                       "approval": record["approval"],
                       "failure_reasons": record["failure_reasons"],
                       "failure_evidence": record["failure_evidence"]},
            "replay": {"attempt_id": self.issued["attempt_id"],
                       "prev_attempt_id": self.origin_attempt,
                       "chain_id": self.chain_id,
                       "basis": {"basis_attempt_id": self.origin_attempt,
                                 "effective_result": "not_executed", "observations": []}},
        }) + "\n")
        with self.assertRaises(IntegrityError) as ctx:
            verify_replay_package(self.store, self.pkg_dir)
        kinds = {p["kind"] for p in ctx.exception.details["report"]["problems"]}
        self.assertIn("batch_not_matching_registration", kinds)

    def test_missing_complete_marker_rejected(self):
        (self.pkg_dir / ".complete").unlink()
        with self.assertRaises(IntegrityError):
            verify_replay_package(self.store, self.pkg_dir)

    def test_unknown_package_rejected(self):
        with self.assertRaises(IntegrityError):
            verify_replay_package(self.store, self.tmp / "does-not-exist")

    def _tamper_first_row(self, mutate) -> set:
        import uuid

        tampered = self.tmp / f"tt-{uuid.uuid4().hex}"
        shutil.copytree(self.pkg_dir, tampered)
        pf = next((tampered / "partitions").glob("*.ndjson"))
        rows = [json.loads(line) for line in pf.read_text().splitlines()]
        mutate(rows[0])
        pf.write_text("".join(json.dumps(r) + "\n" for r in rows))
        with self.assertRaises(IntegrityError) as ctx:
            verify_replay_package(self.store, tampered)
        return {p["kind"] for p in ctx.exception.details["report"]["problems"]}

    def test_evidence_and_binding_tampering_rejected(self):
        kinds = self._tamper_first_row(
            lambda r: r["origin"]["approval"].__setitem__("approved_by", "mallory")
        )
        self.assertIn("approval_evidence_replaced", kinds)
        kinds = self._tamper_first_row(
            lambda r: r["origin"]["source_records"][0].__setitem__(
                "failure_reason", "forged")
        )
        self.assertIn("source_evidence_replaced", kinds)
        kinds = self._tamper_first_row(
            lambda r: r["replay"].__setitem__("attempt_id", "attempt-0009")
        )
        self.assertIn("attempt_binding_mismatch", kinds)
        kinds = self._tamper_first_row(
            lambda r: r["replay"].__setitem__("prev_attempt_id", "attempt-0009")
        )
        self.assertIn("prev_attempt_binding_mismatch", kinds)
        kinds = self._tamper_first_row(
            lambda r: r["replay"]["basis"].__setitem__("basis_attempt_id", "attempt-0009")
        )
        self.assertIn("failure_basis_mismatch", kinds)


class CliIntegrationTests(ReconciliationFixture):
    def test_full_cli_cycle_and_text_render(self):
        rows = [
            self.r(self.eid("p-a", 1), "success"),
            self.r(self.eid("p-a", 2), "not_executed"),
        ]
        path = self.tmp / "r.jsonl"
        write_receipts(path, rows)
        p = run_cli(["import-receipts", "--store", str(self.store_path),
                     "--receipts", str(path), "--by", "alice"])
        self.assertEqual(p.returncode, 0, p.stderr)
        p = run_cli(["reconcile", "--store", str(self.store_path), "--text"])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("交付对账", p.stdout)
        p = run_cli(["issue-replay", "--store", str(self.store_path), "--by", "alice"])
        self.assertEqual(p.returncode, 0, p.stderr)
        issued = json.loads(p.stdout)
        pkg = Path(issued["package_dir"])
        p = run_cli(["verify-replay", "--store", str(self.store_path),
                     "--package", str(pkg)])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(json.loads(p.stdout)["ok"])
        p = run_cli(["verify-store", "--store", str(self.store_path)])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(json.loads(p.stdout)["snapshot_in_sync"])

    def test_cli_rejects_bad_receipt_file(self):
        path = self.tmp / "bad.jsonl"
        path.write_text('{"attempt_id": 123}\n')
        p = run_cli(["import-receipts", "--store", str(self.store_path),
                     "--receipts", str(path), "--by", "alice"])
        self.assertEqual(p.returncode, 4)


if __name__ == "__main__":
    unittest.main()
