"""判定引擎测试：覆盖验收清单中的判定类场景。"""

from __future__ import annotations

import unittest

from dlq_recovery.errors import InputError
from dlq_recovery.models import Approval, payload_fingerprint
from dlq_recovery.plan import (
    VERDICT_QUARANTINED,
    VERDICT_RETRYABLE,
    VERDICT_SUPERSEDED,
    build_plan,
    make_event_id,
)

from .helpers import items_for_key, msg, plan_from_rows


class PartitionOrderTests(unittest.TestCase):
    def test_records_interleaved_across_partitions(self):
        """死信文件跨分区交错时，计划仍按分区+偏移稳定排序。"""

        rows = [
            msg(message_id="m3", business_key="k3", partition="p2", offset=10),
            msg(message_id="m1", business_key="k1", partition="p1", offset=5),
            msg(message_id="m2", business_key="k2", partition="p1", offset=2),
            msg(message_id="m4", business_key="k4", partition="p2", offset=1),
            msg(message_id="m5", business_key="k5", partition="p1", offset=9),
        ]
        plan = plan_from_rows(rows)
        order = [(it.partition, it.offset) for it in plan.items]
        self.assertEqual(
            order, [("p1", 2), ("p1", 5), ("p1", 9), ("p2", 1), ("p2", 10)]
        )

    def test_offset_order_independent_of_file_order(self):
        """同一分区内文件顺序颠倒不影响偏移顺序。"""

        forward = [
            msg(message_id=f"a{i}", business_key=f"k{i}", partition="p1", offset=i)
            for i in range(0, 20, 2)
        ]
        plan_a = plan_from_rows(forward)
        plan_b = plan_from_rows(list(reversed(forward)))
        self.assertEqual(
            [it.offset for it in plan_a.items], [it.offset for it in plan_b.items]
        )
        self.assertEqual(plan_a.digest, plan_b.digest)

    def test_cross_partition_offsets_are_independent(self):
        """不同分区可以出现相同偏移，互不冲突。"""

        rows = [
            msg(message_id="x1", business_key="kx", partition="p1", offset=3),
            msg(message_id="y1", business_key="ky", partition="p2", offset=3),
        ]
        plan = plan_from_rows(rows)
        self.assertEqual(len(plan.items), 2)
        self.assertEqual([it.verdict for it in plan.items], [VERDICT_RETRYABLE] * 2)
        self.assertEqual(plan.conflict_groups, [])


class DuplicateMergeTests(unittest.TestCase):
    def test_identical_resend_merges_into_one_version(self):
        rows = [
            msg(message_id="d1", business_key="ord-1", partition="p1", offset=4,
                payload={"a": 1}, delivery_count=3, evidence="e1"),
            msg(message_id="d2", business_key="ord-1", partition="p1", offset=8,
                payload={"a": 1}, delivery_count=1, evidence="e2"),
            msg(message_id="d3", business_key="ord-1", partition="p1", offset=12,
                payload={"a": 1}, delivery_count=2, evidence="e3"),
        ]
        plan = plan_from_rows(rows)
        self.assertEqual(len(plan.items), 1)
        item = plan.items[0]
        self.assertEqual(len(item.sources), 3)
        self.assertEqual(len(item.identities), 3)
        self.assertEqual(item.offset, 4, "规范位置应取最早偏移")
        self.assertEqual(item.delivery_count_max, 3)
        self.assertEqual(item.verdict, VERDICT_RETRYABLE)
        self.assertTrue(any(r["code"] == "merged_upstream_resend" for r in item.reasons))
        self.assertEqual(plan.counts()["merged_duplicate_records"], 2)

    def test_payload_key_order_does_not_split_duplicates(self):
        rows = [
            msg(message_id="o1", business_key="ord-2", partition="p1", offset=1,
                payload={"a": 1, "b": 2}),
            msg(message_id="o2", business_key="ord-2", partition="p1", offset=2,
                payload={"b": 2, "a": 1}),
        ]
        plan = plan_from_rows(rows)
        self.assertEqual(len(plan.items), 1)

    def test_same_message_id_with_different_content_is_rejected(self):
        rows = [
            msg(message_id="dup", business_key="k", partition="p1", offset=1,
                payload={"a": 1}),
            msg(message_id="dup", business_key="k", partition="p1", offset=2,
                payload={"a": 2}),
        ]
        with self.assertRaises(InputError) as ctx:
            plan_from_rows(rows)
        self.assertEqual(ctx.exception.code, "INPUT_INVALID")

    def test_cross_partition_duplicate_is_quarantined(self):
        rows = [
            msg(message_id="cp1", business_key="ord-3", partition="p1", offset=1,
                payload={"a": 1}),
            msg(message_id="cp2", business_key="ord-3", partition="p3", offset=1,
                payload={"a": 1}),
        ]
        plan = plan_from_rows(rows)
        self.assertEqual(len(plan.items), 1)
        item = plan.items[0]
        self.assertEqual(item.verdict, VERDICT_QUARANTINED)
        self.assertIn("duplicate_across_partitions", {r["code"] for r in item.reasons})
        self.assertFalse(item.releasable)

    def test_same_payload_different_occurred_at_is_ambiguous(self):
        rows = [
            msg(message_id="t1", business_key="ord-4", partition="p1", offset=1,
                payload={"a": 1}, occurred_at=1000),
            msg(message_id="t2", business_key="ord-4", partition="p1", offset=2,
                payload={"a": 1}, occurred_at=1200),
        ]
        plan = plan_from_rows(rows)
        self.assertEqual(len(plan.items), 2)
        for item in plan.items:
            self.assertEqual(item.verdict, VERDICT_QUARANTINED)
            self.assertIn("duplicate_metadata_ambiguous", {r["code"] for r in item.reasons})
            self.assertFalse(item.releasable)


class ConflictTests(unittest.TestCase):
    def test_same_key_different_payload_quarantines_all_versions(self):
        rows = [
            msg(message_id="c1", business_key="ord-9", partition="p1", offset=3,
                payload={"amount": 50}),
            msg(message_id="c2", business_key="ord-9", partition="p1", offset=6,
                payload={"amount": 55}),
            msg(message_id="ok1", business_key="ord-10", partition="p2", offset=1,
                payload={"amount": 10}),
        ]
        plan = plan_from_rows(rows)
        self.assertEqual(len(plan.conflict_groups), 1)
        group = plan.conflict_groups[0]
        self.assertEqual(group["kind"], "payload_conflict")
        self.assertEqual(len(group["versions"]), 2)
        payloads = {v["payload_sha256"] for v in group["versions"]}
        self.assertEqual(len(payloads), 2)
        for item in items_for_key(plan, "ord-9"):
            self.assertEqual(item.verdict, VERDICT_QUARANTINED)
            self.assertFalse(item.releasable)
            self.assertEqual(item.conflict_group, group["id"])
        self.assertEqual(items_for_key(plan, "ord-10")[0].verdict, VERDICT_RETRYABLE)

    def test_conflict_preserves_original_payloads(self):
        rows = [
            msg(message_id="p1", business_key="k", partition="p1", offset=1,
                payload={"amount": 1, "note": "原始"}),
            msg(message_id="p2", business_key="k", partition="p1", offset=2,
                payload={"amount": 2, "note": "另一版本"}),
        ]
        plan = plan_from_rows(rows)
        payloads = {tuple(sorted(v["payload"].items())) for v in plan.conflict_groups[0]["versions"]}
        self.assertEqual(
            payloads, {(("amount", 1), ("note", "原始")), (("amount", 2), ("note", "另一版本"))}
        )

    def test_different_event_types_same_key_are_not_conflict(self):
        """同一业务键的不同事件类型载荷天然不同，不应判为冲突。"""

        rows = [
            msg(message_id="e1", business_key="k", partition="p1", offset=1,
                event_type="order.created", payload={"id": "k"}),
            msg(message_id="e2", business_key="k", partition="p1", offset=2,
                event_type="order.paid", payload={"id": "k", "paid": True}),
        ]
        plan = plan_from_rows(rows)
        self.assertEqual(plan.conflict_groups, [])
        self.assertEqual([it.verdict for it in plan.items], [VERDICT_RETRYABLE] * 2)

    def test_same_queue_slot_with_different_events_conflicts(self):
        rows = [
            msg(message_id="s1", business_key="k1", partition="p1", offset=7,
                payload={"a": 1}),
            msg(message_id="s2", business_key="k2", partition="p1", offset=7,
                payload={"b": 2}),
        ]
        plan = plan_from_rows(rows)
        kinds = {g["kind"] for g in plan.conflict_groups}
        self.assertEqual(kinds, {"queue_slot_conflict"})
        self.assertTrue(all(it.verdict == VERDICT_QUARANTINED for it in plan.items))

    def test_conflict_cannot_be_released_by_approval(self):
        rows = [
            msg(message_id="c1", business_key="k", partition="p1", offset=1,
                payload={"a": 1}),
            msg(message_id="c2", business_key="k", partition="p1", offset=2,
                payload={"a": 2}),
        ]
        plan = plan_from_rows(rows)
        for item in plan.items:
            self.assertFalse(item.eligible)


class SupersessionTests(unittest.TestCase):
    def test_later_final_state_supersedes_older_event(self):
        rows = [
            msg(message_id="old", business_key="ord-1", partition="p1", offset=2,
                event_type="order.created", status="active", occurred_at=1000),
            msg(message_id="new", business_key="ord-1", partition="p1", offset=9,
                event_type="order.cancelled", status="cancelled", occurred_at=2000,
                payload={"state": "cancelled"}),
        ]
        plan = plan_from_rows(rows)
        old = plan.item(
            make_event_id(
                business_key="ord-1",
                partition="p1",
                offset=2,
                payload_sha=payload_fingerprint({"id": "ord-1", "v": 1}),
            )
        )
        self.assertEqual(old.verdict, VERDICT_SUPERSEDED)
        self.assertEqual(old.superseded_by["event_type"], "order.cancelled")
        new = items_for_key(plan, "ord-1")
        self.assertEqual(
            [it.verdict for it in new].count(VERDICT_SUPERSEDED), 1
        )
        self.assertEqual(plan.counts()["superseded"], 1)

    def test_formal_waiting_does_not_supersede_without_final_state(self):
        rows = [
            msg(message_id="a", business_key="k", partition="p1", offset=1,
                status="active", occurred_at=1000),
            msg(message_id="b", business_key="k", partition="p1", offset=2,
                event_type="order.paid", status="active", occurred_at=2000,
                payload={"paid": True}),
        ]
        plan = plan_from_rows(rows)
        self.assertFalse(any(it.verdict == VERDICT_SUPERSEDED for it in plan.items))

    def test_newer_final_state_supersedes_older_path_a_cancel(self):
        """验收条目：后续状态事件替代旧事件。"""

        rows = [
            msg(message_id="a1", business_key="ord-7", partition="p3", offset=2,
                status="cancelled", occurred_at=1000,
                event_type="order.cancelled", payload={"s": "cancelled"}),
            msg(message_id="a2", business_key="ord-7", partition="p3", offset=20,
                status="active", occurred_at=1500,
                event_type="order.reopened", payload={"s": "reopened"}),
        ]
        plan = plan_from_rows(rows)
        verdicts = sorted(it.verdict for it in plan.items)
        self.assertEqual(verdicts, [VERDICT_RETRYABLE, VERDICT_SUPERSEDED])
        superseded = next(it for it in plan.items if it.verdict == VERDICT_SUPERSEDED)
        self.assertEqual(superseded.offset, 2)
        self.assertFalse(superseded.eligible)

    def test_equal_occurred_at_never_supersedes(self):
        rows = [
            msg(message_id="a", business_key="k", partition="p1", offset=1,
                status="cancelled", event_type="order.cancelled", occurred_at=1000,
                payload={"s": 1}),
            msg(message_id="b", business_key="k", partition="p1", offset=2,
                status="active", event_type="order.created", occurred_at=1000,
                payload={"s": 2}),
        ]
        plan = plan_from_rows(rows)
        self.assertFalse(any(it.verdict == VERDICT_SUPERSEDED for it in plan.items))


class DispositionTests(unittest.TestCase):
    def test_manual_retry_does_not_bypass_approval(self):
        rows = [msg(message_id="m", business_key="k", partition="p1", offset=1)]
        plan = plan_from_rows(
            rows,
            dispositions=[{"message_id": "m", "action": "retry", "operator": "alice"}],
        )
        item = plan.items[0]
        self.assertEqual(item.verdict, VERDICT_RETRYABLE)
        self.assertIsNone(item.approval)
        self.assertEqual(plan.counts()["held_unapproved"], 1)

    def test_manual_quarantine_blocks_approval(self):
        rows = [msg(message_id="m", business_key="k", partition="p1", offset=1)]
        plan = plan_from_rows(
            rows,
            dispositions=[{"message_id": "m", "action": "quarantine", "operator": "bob"}],
        )
        item = plan.items[0]
        self.assertEqual(item.verdict, VERDICT_QUARANTINED)
        self.assertFalse(item.releasable)
        self.assertFalse(item.eligible)

    def test_conflicting_dispositions_are_quarantined(self):
        rows = [
            msg(message_id="x1", business_key="k", partition="p1", offset=1,
                payload={"a": 1}),
            msg(message_id="x2", business_key="k", partition="p1", offset=2,
                payload={"a": 1}),
        ]
        plan = plan_from_rows(
            rows,
            dispositions=[
                {"message_id": "x1", "action": "retry", "operator": "alice"},
                {"message_id": "x2", "action": "quarantine", "operator": "bob"},
            ],
        )
        item = plan.items[0]
        self.assertEqual(item.verdict, VERDICT_QUARANTINED)
        self.assertIn("disposition_divergence", {r["code"] for r in item.reasons})

    def test_unmatched_disposition_is_reported(self):
        rows = [msg(message_id="m", business_key="k", partition="p1", offset=1)]
        plan = plan_from_rows(
            rows,
            dispositions=[{"message_id": "ghost", "action": "retry", "operator": "d"}],
        )
        self.assertEqual(len(plan.unmatched_dispositions), 1)
        self.assertEqual(plan.unmatched_dispositions[0]["message_id"], "ghost")

    def test_problem_status_is_soft_quarantine(self):
        rows = [msg(message_id="m", business_key="k", partition="p1", offset=1,
                    status="needs_review")]
        plan = plan_from_rows(rows, policy={"problem_statuses": ["needs_review"]})
        item = plan.items[0]
        self.assertEqual(item.verdict, VERDICT_QUARANTINED)
        self.assertTrue(item.releasable)
        self.assertTrue(item.eligible)


class ApprovalBindingTests(unittest.TestCase):
    def _plan_with_grant(self, rows, grants, policy=None):
        return plan_from_rows(rows, policy=policy, grants=grants)

    def test_approval_must_match_plan_digest(self):
        rows = [msg(message_id="m", business_key="ord-1", partition="p1", offset=1)]
        base = plan_from_rows(rows)
        item = base.items[0]
        stale = {
            item.event_id: Approval(
                event_id=item.event_id,
                action="retry",
                approved_by="alice",
                approved_at="2026-01-01T00:00:00Z",
                plan_digest="deadbeef",
            )
        }
        plan = plan_from_rows(rows, grants=stale)
        self.assertEqual(plan.invalid_approvals[0]["reason"], "stale_plan_digest")
        self.assertIsNone(plan.items[0].approval)

    def test_approval_binds_to_one_event_version_only(self):
        """同业务键的另一个版本不能因批准其中一版而被连带放行。"""

        rows = [
            msg(message_id="c1", business_key="ord-1", partition="p1", offset=1,
                payload={"v": 1}),
            msg(message_id="c2", business_key="ord-1", partition="p1", offset=2,
                payload={"v": 2}),
        ]
        base = plan_from_rows(rows)
        target = base.items[0]
        grants = {
            target.event_id: Approval(
                event_id=target.event_id,
                action="retry",
                approved_by="alice",
                approved_at="2026-01-01T00:00:00Z",
                plan_digest=base.digest,
            )
        }
        plan = plan_from_rows(rows, grants=grants)
        # 冲突版本即使被单独批准也不可放行：批准保留在账本中但不算有效
        self.assertEqual([it.event_id for it in plan.items if it.approval], [])
        self.assertEqual(plan.invalid_approvals[0]["reason"], "event_not_eligible:quarantined")
        self.assertEqual(plan.counts()["approved"], 0)

    def test_approval_for_superseded_version_is_invalid(self):
        rows = [
            msg(message_id="old", business_key="k", partition="p1", offset=1,
                occurred_at=1000),
            msg(message_id="new", business_key="k", partition="p1", offset=2,
                event_type="order.cancelled", status="cancelled", occurred_at=2000,
                payload={"s": 1}),
        ]
        base = plan_from_rows(rows)
        old = next(it for it in base.items if it.verdict == VERDICT_SUPERSEDED)
        grants = {
            old.event_id: Approval(
                event_id=old.event_id, action="retry", approved_by="alice",
                approved_at="2026-01-01T00:00:00Z", plan_digest=base.digest,
            )
        }
        plan = plan_from_rows(rows, grants=grants)
        self.assertEqual(
            plan.invalid_approvals[0]["reason"], "event_not_eligible:superseded"
        )

    def test_digest_changes_when_delivery_evidence_changes(self):
        rows = [msg(message_id="m", business_key="k", partition="p1", offset=1,
                    delivery_count=2, evidence="e1")]
        plan_a = plan_from_rows(rows)
        rows[0]["failure"]["delivery_count"] = 9
        plan_b = plan_from_rows(rows)
        self.assertNotEqual(plan_a.digest, plan_b.digest)

    def test_version_digest_isolates_unrelated_changes(self):
        """批准绑定到事件版本：无关的新记录不会使批准失效，但本事件证据变化会。"""

        rows = [
            msg(message_id="m", business_key="k", partition="p1", offset=1,
                delivery_count=2, evidence="e1"),
        ]
        base = plan_from_rows(rows)
        item = base.items[0]
        grant = Approval(
            event_id=item.event_id,
            action="retry",
            approved_by="alice",
            approved_at="2026-01-01T00:00:00Z",
            plan_digest=base.digest,
            version_digest=base.version_digest(item.event_id),
        )
        # 追加无关记录：整计划摘要变化，但该版本批准仍有效
        expanded = rows + [
            msg(message_id="other", business_key="k2", partition="p2", offset=9)
        ]
        plan2 = plan_from_rows(expanded, grants={item.event_id: grant})
        self.assertNotEqual(plan2.digest, base.digest)
        refreshed = plan2.item(item.event_id)
        self.assertIsNotNone(refreshed.approval)
        self.assertTrue(refreshed.approval.get("plan_drift"))

        # 本事件失败证据变化：批准失效
        changed = [dict(rows[0])]
        changed[0]["failure"] = {"delivery_count": 7, "reason": "db_timeout", "evidence": "e1"}
        plan3 = plan_from_rows(changed, grants={item.event_id: grant})
        self.assertEqual(plan3.invalid_approvals[0]["reason"], "stale_event_version")


if __name__ == "__main__":
    unittest.main()
