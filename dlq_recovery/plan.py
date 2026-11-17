"""判定引擎：把死信记录 + 人工处置转换成可审计的恢复计划。

判定顺序（每一步都只依赖前一步，便于解释）：

1. **身份校验**：同一 ``message_id`` 不能指向不同内容；同一
   ``(partition, offset)`` 队列槽位不能出现不同事件。
2. **重复合并**：业务键、载荷、事件类型、状态、业务时间完全相同的记录
   视为上游重发，合并为一个"事件版本"，保留全部来源身份。
3. **后续状态事件替代**：若同业务键存在业务时间更晚的终态事件，较旧版本
   标记为 ``superseded``，不参与重投。终态事件本身若被更晚事件覆盖，也
   标记为 ``superseded``。
4. **冲突隔离**：未被替代的同业务键版本若载荷指纹不一致，全部
   ``quarantined``。冲突载荷原样保留在计划中，任何批准都不能放行。
5. **人工处置**：处置按消息身份登记；合并后的版本汇总其全部身份的处置，
   出现分歧即隔离；``quarantine`` 为硬隔离；``retry`` 只有在已批准时才
   可成为"可由人工批准放行"的毒丸版本。
6. **批准绑定**：批准只作用于指定 ``event_id``（含队列位置 + 载荷指纹），
   并且绑定计划摘要；计划变化后旧批准自动失效。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from .errors import InputError, PolicyError
from .models import (
    Approval,
    Disposition,
    Failure,
    Message,
    Policy,
    Record,
    canonical_json,
    payload_fingerprint,
    sha256_text,
)

PLAN_FORMAT = "dlq-recovery-plan"
PLAN_FORMAT_VERSION = 1

VERDICT_RETRYABLE = "retryable"
VERDICT_QUARANTINED = "quarantined"
VERDICT_SUPERSEDED = "superseded"
VERDICTS = (VERDICT_RETRYABLE, VERDICT_QUARANTINED, VERDICT_SUPERSEDED)

# 硬隔离原因：任何人工批准都不能在本流程内放行
HARD_QUARANTINE_CODES = frozenset(
    {
        "payload_conflict",
        "queue_slot_conflict",
        "duplicate_across_partitions",
        "duplicate_metadata_ambiguous",
        "manual_quarantine",
        "disposition_divergence",
    }
)

_SUCCESSOR_STATUSES_HELP = "终态状态由业务配置 final_statuses 定义"


def make_event_id(*, business_key: str, partition: str, offset: int, payload_sha: str) -> str:
    """版本级事件标识：随队列位置或载荷变化而变化。"""

    raw = canonical_json(
        {
            "v": 1,
            "business_key": business_key,
            "partition": partition,
            "offset": offset,
            "payload_sha256": payload_sha,
        }
    )
    return "ev-" + sha256_text(raw)[:20]


def _reason(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail}


@dataclass(frozen=True)
class SourceRef:
    line_no: int
    message_id: str
    partition: str
    offset: int
    delivery_count: int
    failure_reason: str
    failure_evidence: str | None
    event_type: str
    status: str
    occurred_at: int | None
    source_attempt: str | None

    @classmethod
    def from_record(cls, record: Record) -> "SourceRef":
        msg = record.message
        fail = record.failure
        return cls(
            line_no=record.line_no,
            message_id=msg.message_id,
            partition=msg.partition,
            offset=msg.offset,
            delivery_count=fail.delivery_count,
            failure_reason=fail.reason,
            failure_evidence=fail.evidence,
            event_type=msg.event_type,
            status=msg.status,
            occurred_at=msg.occurred_at,
            source_attempt=msg.source_attempt,
        )

    def to_dict(self) -> dict:
        return {
            "line": self.line_no,
            "message_id": self.message_id,
            "partition": self.partition,
            "offset": self.offset,
            "delivery_count": self.delivery_count,
            "failure_reason": self.failure_reason,
            "failure_evidence": self.failure_evidence,
            "event_type": self.event_type,
            "status": self.status,
            "occurred_at": self.occurred_at,
            "source_attempt": self.source_attempt,
        }


@dataclass
class Item:
    """合并后的一个"事件版本"。"""

    event_id: str
    business_key: str
    partition: str
    offset: int
    payload: Any
    payload_sha256: str
    event_type: str
    status: str
    occurred_at: int
    sources: list[SourceRef] = field(default_factory=list)
    verdict: str = VERDICT_RETRYABLE
    reasons: list[dict[str, str]] = field(default_factory=list)
    releasable: bool = False
    superseded_by: dict | None = None
    superseding_event_ids: list[str] = field(default_factory=list)
    conflict_group: str | None = None
    disposition: dict | None = None
    approval: dict | None = None

    @property
    def identities(self) -> list[dict]:
        seen: dict[tuple[str, str, int], dict] = {}
        for src in sorted(self.sources, key=lambda s: (s.partition, s.offset, s.message_id, s.line_no)):
            key = (src.message_id, src.partition, src.offset)
            seen.setdefault(
                key,
                {"message_id": src.message_id, "partition": src.partition, "offset": src.offset},
            )
        return [seen[k] for k in sorted(seen)]

    @property
    def delivery_count_max(self) -> int:
        return max(src.delivery_count for src in self.sources)

    @property
    def failure_reasons(self) -> list[str]:
        return sorted({src.failure_reason for src in self.sources})

    @property
    def failure_evidence(self) -> list[str]:
        return sorted({src.failure_evidence for src in self.sources if src.failure_evidence})

    @property
    def hard_quarantine(self) -> bool:
        return any(r["code"] in HARD_QUARANTINE_CODES for r in self.reasons)

    @property
    def eligible(self) -> bool:
        """是否可进入批准/重投环节。"""

        if self.verdict == VERDICT_RETRYABLE:
            return True
        if self.verdict == VERDICT_QUARANTINED:
            return self.releasable
        return False

    @property
    def sort_key(self) -> tuple[str, int, str]:
        return (self.partition, self.offset, self.event_id)

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "verdict": self.verdict,
            "eligible": self.eligible,
            "releasable": self.releasable,
            "business_key": self.business_key,
            "partition": self.partition,
            "offset": self.offset,
            "event_type": self.event_type,
            "status": self.status,
            "occurred_at": self.occurred_at,
            "payload_sha256": self.payload_sha256,
            "payload": self.payload,
            "delivery_count_max": self.delivery_count_max,
            "failure_reasons": self.failure_reasons,
            "failure_evidence": self.failure_evidence,
            "reasons": [dict(r) for r in self.reasons],
            "identities": self.identities,
            "source_records": [s.to_dict() for s in self.sources],
            "superseded_by": self.superseded_by,
            "superseding_event_ids": list(self.superseding_event_ids),
            "conflict_group": self.conflict_group,
            "disposition": self.disposition,
            "approval": self.approval,
        }


@dataclass
class Plan:
    items: list[Item]
    conflict_groups: list[dict]
    unmatched_dispositions: list[dict]
    policy: Policy
    digest: str
    approvals: list[dict] = field(default_factory=list)
    invalid_approvals: list[dict] = field(default_factory=list)

    # -- 查询 -------------------------------------------------------------
    def item(self, event_id: str) -> Item | None:
        for it in self.items:
            if it.event_id == event_id:
                return it
        return None

    def version_digest(self, event_id: str) -> str | None:
        item = self.item(event_id)
        return event_version_digest(item) if item is not None else None

    @property
    def by_verdict(self) -> dict[str, list[Item]]:
        out = {v: [] for v in VERDICTS}
        for it in self.items:
            out[it.verdict].append(it)
        return out

    def approved_items(self) -> list[Item]:
        return [it for it in self.items if it.approval is not None and it.eligible]

    def held_items(self) -> list[Item]:
        """可进入重投但尚无有效批准的版本。"""

        return [it for it in self.items if it.eligible and it.approval is None]

    def counts(self) -> dict:
        verdicts = self.by_verdict
        return {
            "records": sum(len(it.sources) for it in self.items),
            "items": len(self.items),
            "retryable": len(verdicts[VERDICT_RETRYABLE]),
            "quarantined": len(verdicts[VERDICT_QUARANTINED]),
            "superseded": len(verdicts[VERDICT_SUPERSEDED]),
            "releasable_quarantined": sum(
                1 for it in verdicts[VERDICT_QUARANTINED] if it.releasable
            ),            "approved": len(self.approved_items()),
            "held_unapproved": len(self.held_items()),
            "merged_duplicate_records": sum(len(it.sources) - 1 for it in self.items),
            "conflicts": len(self.conflict_groups),
            "unmatched_dispositions": len(self.unmatched_dispositions),
        }

    def partitions(self) -> list[dict]:
        out = []
        for partition in sorted({it.partition for it in self.items}):
            items = sorted(
                (it for it in self.items if it.partition == partition),
                key=lambda i: (i.offset, i.event_id),
            )
            delivered = [it for it in items if it.eligible and it.approval is not None]
            out.append(
                {
                    "partition": partition,
                    "items": len(items),
                    "delivered": len(delivered),
                    "first_offset": items[0].offset if items else None,
                    "last_offset": items[-1].offset if items else None,
                }
            )
        return out

    def to_dict(self) -> dict:
        return {
            "format": PLAN_FORMAT,
            "format_version": PLAN_FORMAT_VERSION,
            "digest": self.digest,
            "policy": {
                "problem_statuses": sorted(self.policy.problem_statuses),
                "final_statuses": sorted(self.policy.final_statuses),
            },
            "counts": self.counts(),
            "items": [it.to_dict() for it in self.items],
            "conflict_groups": self.conflict_groups,
            "unmatched_dispositions": self.unmatched_dispositions,
            "approvals": self.approvals,
            "invalid_approvals": self.invalid_approvals,
        }


# ---------------------------------------------------------------------------
# 摘要计算（构建与校验共用同一份规范化逻辑）
# ---------------------------------------------------------------------------
def _digest_item(value: Any) -> dict:
    item = value.to_dict() if isinstance(value, Item) else value
    disposition = item.get("disposition") or {}
    return {
        "event_id": item["event_id"],
        "verdict": item["verdict"],
        "eligible": item["eligible"],
        "releasable": item["releasable"],
        "business_key": item["business_key"],
        "partition": item["partition"],
        "offset": item["offset"],
        "payload_sha256": item["payload_sha256"],
        "event_type": item["event_type"],
        "status": item["status"],
        "occurred_at": item["occurred_at"],
        "identities": sorted(
            ({"message_id": i["message_id"], "partition": i["partition"], "offset": i["offset"]}
             for i in item["identities"]),
            key=lambda i: (i["partition"], i["offset"], i["message_id"]),
        ),
        "superseded_by": (item.get("superseded_by") or {}).get("event_id"),
        "superseding_event_ids": sorted(item.get("superseding_event_ids") or []),
        "conflict_group": item.get("conflict_group"),
        "reason_codes": sorted(r["code"] for r in item.get("reasons", [])),
        # 失败证据也纳入摘要：批准应绑定到当时看到的投递次数/失败原因/证据，
        # 但不使用文件行号，避免死信文件重新导出后行号漂移导致批准失效。
        "sources": sorted(
            (
                {
                    "message_id": s["message_id"],
                    "partition": s["partition"],
                    "offset": s["offset"],
                    "delivery_count": s["delivery_count"],
                    "failure_reason": s["failure_reason"],
                    "failure_evidence": s["failure_evidence"],
                }
                for s in item.get("source_records", [])
            ),
            key=lambda s: (
                s["message_id"],
                s["partition"],
                s["offset"],
                s["delivery_count"],
                s["failure_reason"],
                s["failure_evidence"] or "",
            ),
        ),
        "disposition_action": disposition.get("action"),
        "disposition_approved": bool(disposition.get("approved")),
    }


def _digest_conflict(group: dict) -> dict:
    return {
        "id": group["id"],
        "kind": group["kind"],
        "business_keys": list(group["business_keys"]),
        "partition": group.get("partition"),
        "offset": group.get("offset"),
        "versions": sorted(
            (
                {
                    "event_id": v["event_id"],
                    "business_key": v["business_key"],
                    "payload_sha256": v["payload_sha256"],
                }
                for v in group["versions"]
            ),
            key=lambda v: v["event_id"],
        ),
    }


def event_version_digest(item: Any) -> str:
    """单个事件版本的批准绑定摘要。"""

    value = item.to_dict() if isinstance(item, Item) else item
    return sha256_text(canonical_json(_digest_item(value)))


def plan_digest(*, items: Iterable[dict], conflict_groups: Iterable[dict], policy: Policy) -> str:
    payload = {
        "format": PLAN_FORMAT,
        "format_version": PLAN_FORMAT_VERSION,
        "policy": {
            "problem_statuses": sorted(policy.problem_statuses),
            "final_statuses": sorted(policy.final_statuses),
        },
        "items": sorted((_digest_item(i) for i in items), key=lambda i: i["event_id"]),
        "conflict_groups": sorted(
            (_digest_conflict(g) for g in conflict_groups), key=lambda g: g["id"]
        ),
    }
    return sha256_text(canonical_json(payload))


def digest_from_plan_dict(plan: dict) -> str:
    """从已保存的计划重新计算摘要，用于校验计划文件未被篡改。"""

    policy = Policy(
        problem_statuses=frozenset(plan["policy"]["problem_statuses"]),
        final_statuses=frozenset(plan["policy"]["final_statuses"]),
    )
    return plan_digest(
        items=plan["items"], conflict_groups=plan["conflict_groups"], policy=policy
    )


# ---------------------------------------------------------------------------
# 构建
# ---------------------------------------------------------------------------
def _validate_policy(policy: Policy) -> None:
    if not policy.problem_statuses:
        raise InputError("业务配置 problem_statuses 不能为空")
    if not policy.final_statuses:
        raise InputError("业务配置 final_statuses 不能为空")
    overlap = policy.problem_statuses & policy.final_statuses
    if overlap:
        raise InputError(
            f"业务配置 problem_statuses 与 final_statuses 不能重叠: {sorted(overlap)}"
        )


def _check_identity_collisions(records: list[Record]) -> None:
    by_message_id: dict[str, tuple] = {}
    for record in records:
        msg = record.message
        signature = (
            msg.business_key,
            msg.partition,
            msg.offset,
            payload_fingerprint(msg.payload),
            msg.event_type,
            msg.status,
            msg.occurred_at,
        )
        previous = by_message_id.get(msg.message_id)
        if previous is not None and previous[0] != signature:
            raise InputError(
                "同一 message_id 指向不同消息内容，无法确定消息身份",
                details={
                    "message_id": msg.message_id,
                    "lines": [previous[1], record.line_no],
                },
            )
        if previous is None:
            by_message_id[msg.message_id] = (signature, record.line_no)


def _merge_key(message: Message) -> tuple:
    """上游重发的判定键：载荷、事件类型、状态、业务时间全部一致才算重复。"""

    return (
        message.business_key,
        payload_fingerprint(message.payload),
        message.event_type,
        message.status,
        message.occurred_at,
    )


def _build_items(records: list[Record]) -> list[Item]:
    grouped: dict[tuple, list[Record]] = {}
    for record in records:
        grouped.setdefault(_merge_key(record.message), []).append(record)

    items: list[Item] = []
    for records_in_group in grouped.values():
        sources = sorted(
            (SourceRef.from_record(r) for r in records_in_group),
            key=lambda s: (s.partition, s.offset, s.message_id, s.line_no),
        )
        canonical = sources[0]
        first = records_in_group[0].message
        payload_sha = payload_fingerprint(first.payload)
        item = Item(
            event_id=make_event_id(
                business_key=first.business_key,
                partition=canonical.partition,
                offset=canonical.offset,
                payload_sha=payload_sha,
            ),
            business_key=first.business_key,
            partition=canonical.partition,
            offset=canonical.offset,
            payload=first.payload,
            payload_sha256=payload_sha,
            event_type=first.event_type,
            status=first.status,
            occurred_at=first.occurred_at,
            sources=sources,
        )
        extra_identities = len({(s.partition, s.offset, s.message_id) for s in sources}) - 1
        if extra_identities > 0:
            item.reasons.append(
                _reason(
                    "merged_upstream_resend",
                    f"上游重发合并：{extra_identities + 1} 个消息身份指向同一内容，"
                    f"以最早队列位置 {canonical.partition}@{canonical.offset} 为规范位置",
                )
            )
        items.append(item)
    # 防御：合并键相同则 event_id 必然相同，这里显式确认，避免静默覆盖
    seen: dict[str, Item] = {}
    for item in items:
        if item.event_id in seen:
            raise InputError(
                "事件版本标识冲突，输入存在无法区分的重复内容",
                details={"event_id": item.event_id},
            )
        seen[item.event_id] = item
    return items


def _mark_ambiguous_duplicates(items: list[Item]) -> None:
    """同业务键、同载荷、同事件类型但业务元数据不一致：无法判断哪个是权威版本。"""

    groups: dict[tuple[str, str, str], list[Item]] = {}
    for item in items:
        if item.verdict == VERDICT_SUPERSEDED:
            continue
        groups.setdefault(
            (item.business_key, item.payload_sha256, item.event_type), []
        ).append(item)
    for (key, _sha, event_type), group in groups.items():
        if len({(i.status, i.occurred_at) for i in group}) < 2:
            continue
        for item in group:
            if item.verdict == VERDICT_RETRYABLE:
                item.verdict = VERDICT_QUARANTINED
            item.reasons.append(
                _reason(
                    "duplicate_metadata_ambiguous",
                    f"业务键 {key} 的 {event_type} 存在载荷相同但状态/业务时间不同的多个版本，"
                    "无法判定权威版本，需人工核对",
                )
            )


def _mark_cross_partition_duplicates(items: list[Item]) -> None:
    """同一内容出现在多个分区：原业务分区不确定，禁止自动重投。"""

    for item in items:
        if item.verdict == VERDICT_SUPERSEDED:
            continue
        partitions = sorted({s.partition for s in item.sources})
        if len(partitions) < 2:
            continue
        if item.verdict == VERDICT_RETRYABLE:
            item.verdict = VERDICT_QUARANTINED
        item.reasons.append(
            _reason(
                "duplicate_across_partitions",
                f"同一事件内容出现在多个分区 {partitions}，无法确定原业务分区，"
                "需人工确认后再按正确分区重投",
            )
        )


def _apply_supersession(items: list[Item], policy: Policy) -> None:
    by_key: dict[str, list[Item]] = {}
    for item in items:
        by_key.setdefault(item.business_key, []).append(item)

    # 先按"业务时间 + 偏移"稳定排序，相同业务时间视为同一时刻，不构成取代。
    for key, group in by_key.items():
        ordered = sorted(group, key=lambda i: (i.occurred_at, i.partition, i.offset, i.event_id))
        for index, item in enumerate(ordered):
            later = ordered[index + 1:]
            if not later:
                continue
            strictly_later = [o for o in later if o.occurred_at > item.occurred_at]
            if not strictly_later:
                continue
            if item.status in policy.final_statuses:
                # 终态事件也可能被更晚的任意事件（重新激活/再次终态）取代
                candidates = strictly_later
            else:
                candidates = [o for o in strictly_later if o.status in policy.final_statuses]
            if not candidates:
                continue
            winner = candidates[0]
            item.verdict = VERDICT_SUPERSEDED
            item.superseding_event_ids = [c.event_id for c in candidates]
            item.superseded_by = {
                "event_id": winner.event_id,
                "status": winner.status,
                "event_type": winner.event_type,
                "occurred_at": winner.occurred_at,
                "partition": winner.partition,
                "offset": winner.offset,
            }
            item.reasons.append(
                _reason(
                    "superseded_by_later_state",
                    f"同业务键在业务时间 {winner.occurred_at} 出现更晚事件 "
                    f"{winner.event_id}（状态 {winner.status}），本版本不再重投",
                )
            )


def _mark_conflicts(items: list[Item], records: list[Record]) -> list[dict]:
    groups: list[dict] = []
    group_counter = 0
    survivors = [it for it in items if it.verdict != VERDICT_SUPERSEDED]

    # 1) 同业务键 + 同事件类型的载荷冲突。
    #    不同事件类型（如 created 与 cancelled）载荷天然不同，不算冲突。
    by_key: dict[tuple[str, str], list[Item]] = {}
    for item in survivors:
        by_key.setdefault((item.business_key, item.event_type), []).append(item)
    for key, event_type in sorted(by_key):
        versions = sorted(by_key[(key, event_type)], key=lambda i: i.event_id)
        fingerprints = {v.payload_sha256 for v in versions}
        if len(fingerprints) < 2:
            continue
        group_counter += 1
        group_id = f"conflict-{group_counter:04d}"
        version_dicts = [
            {
                "event_id": v.event_id,
                "business_key": v.business_key,
                "partition": v.partition,
                "offset": v.offset,
                "event_type": v.event_type,
                "status": v.status,
                "occurred_at": v.occurred_at,
                "payload_sha256": v.payload_sha256,
                "payload": v.payload,
                "source_records": [s.to_dict() for s in v.sources],
            }
            for v in versions
        ]
        groups.append(
            {
                "id": group_id,
                "kind": "payload_conflict",
                "business_keys": [key],
                "event_type": event_type,
                "partition": None,
                "offset": None,
                "detail": (
                    f"业务键 {key} 的 {event_type} 存在 {len(fingerprints)} 个不同载荷版本，"
                    "必须全部保留并阻断自动重投"
                ),
                "versions": version_dicts,
            }
        )
        for version in versions:
            version.verdict = VERDICT_QUARANTINED
            version.conflict_group = group_id
            version.reasons.append(
                _reason(
                    "payload_conflict",
                    f"业务键 {key} 的 {event_type} 存在 {len(fingerprints)} 个不同载荷版本，"
                    f"冲突组 {group_id}，需人工核对后再处理",
                )
            )

    # 2) 同一 (partition, offset) 槽位出现不同事件内容
    slot_map: dict[tuple[str, int], set[str]] = {}
    for record in records:
        slot_map.setdefault((record.partition, record.offset), set()).add(
            canonical_json(
                {
                    "business_key": record.business_key,
                    "payload_sha256": payload_fingerprint(record.message.payload),
                    "event_type": record.message.event_type,
                    "status": record.message.status,
                    "occurred_at": record.message.occurred_at,
                }
            )
        )
    conflicted_slots = sorted(slot for slot, variants in slot_map.items() if len(variants) > 1)
    for partition, offset in conflicted_slots:
        involved = [
            it for it in survivors if (it.partition, it.offset) == (partition, offset)
        ]
        if not involved:
            continue
        # 若该槽位上的版本已全部落入载荷冲突组，则不重复计组
        if all(it.conflict_group is not None for it in involved):
            continue
        involved_keys = sorted({it.business_key for it in involved})
        related = [it for it in survivors if it.business_key in involved_keys]
        group_counter += 1
        group_id = f"conflict-{group_counter:04d}"
        version_dicts = [
            {
                "event_id": v.event_id,
                "business_key": v.business_key,
                "partition": v.partition,
                "offset": v.offset,
                "event_type": v.event_type,
                "status": v.status,
                "occurred_at": v.occurred_at,
                "payload_sha256": v.payload_sha256,
                "payload": v.payload,
                "source_records": [s.to_dict() for s in v.sources],
            }
            for v in sorted(related, key=lambda i: i.event_id)
        ]
        groups.append(
            {
                "id": group_id,
                "kind": "queue_slot_conflict",
                "business_keys": involved_keys,
                "event_type": None,
                "partition": partition,
                "offset": offset,
                "detail": f"队列槽位 {partition}@{offset} 出现多个不同事件，无法确定原偏移语义",
                "versions": version_dicts,
            }
        )
        for version in related:
            version.verdict = VERDICT_QUARANTINED
            if version.conflict_group is None:
                version.conflict_group = group_id
            version.reasons.append(
                _reason(
                    "queue_slot_conflict",
                    f"队列槽位 {partition}@{offset} 存在多种事件内容，"
                    f"冲突组 {group_id}，需人工核对后再处理",
                )
            )

    groups.sort(
        key=lambda g: (g["kind"], g["business_keys"], g.get("event_type") or "",
                       g["partition"] or "", g["offset"] if g["offset"] is not None else -1)
    )
    return groups


def _apply_dispositions(
    items: list[Item], dispositions: dict[str, Disposition]
) -> tuple[list[dict], list[dict]]:
    """人工处置是分诊建议，不是批准。

    - ``quarantine``：硬隔离，不允许在本流程内放行；
    - ``retry``：把默认"可重投"降级为"需人工批准"，并留下待批准原因；
      真正的放行只来自批准账本里针对 ``event_id`` 的批准；
    - 合并后的多个身份处置矛盾：硬隔离。
    """

    used: set[str] = set()
    for item in items:
        relevant: list[Disposition] = []
        for src in item.sources:
            disp = dispositions.get(src.message_id)
            if disp is not None:
                relevant.append(disp)
                used.add(src.message_id)
        if not relevant:
            continue
        unique = sorted(
            {d.message_id: d for d in relevant}.values(), key=lambda d: d.message_id
        )
        actions = sorted({d.action for d in unique})
        item.disposition = {
            "action": actions[0] if len(actions) == 1 else "mixed",
            "actions": actions,
            "operators": sorted({d.operator for d in unique}),
            "notes": sorted({d.note for d in unique if d.note}),
            "message_ids": [d.message_id for d in unique],
        }
        if len(actions) > 1:
            if item.verdict != VERDICT_SUPERSEDED:
                item.verdict = VERDICT_QUARANTINED
            item.reasons.append(
                _reason(
                    "disposition_divergence",
                    "合并后的多个消息身份存在互相矛盾的人工处置（retry/quarantine），"
                    "需先统一处置",
                )
            )
            continue
        if actions == ["quarantine"]:
            if item.verdict == VERDICT_RETRYABLE:
                item.verdict = VERDICT_QUARANTINED
            item.reasons.append(
                _reason("manual_quarantine", "人工处置要求隔离该事件版本")
            )
            continue
        # actions == ["retry"]：保留可重投，但标注需人工批准
        if item.verdict == VERDICT_SUPERSEDED:
            item.reasons.append(
                _reason("manual_retry_requested", "人工要求重试，但该版本已被后续事件取代")
            )
            continue
        if item.verdict == VERDICT_RETRYABLE:
            item.reasons.append(
                _reason(
                    "manual_retry_requested",
                    "人工处置建议重试；仍需针对本 event_id 单独批准后才能导出",
                )
            )
        elif item.verdict == VERDICT_QUARANTINED and not item.hard_quarantine:
            item.reasons.append(
                _reason(
                    "manual_retry_requested",
                    "人工处置建议重试；该版本为软隔离，可由针对本 event_id 的批准单独放行",
                )
            )
        else:
            # 冲突/歧义/人工 quarantine 等硬隔离：人工 retry 只作为证据保留，
            # 不能把隔离版本变成"可重投"。
            item.reasons.append(
                _reason(
                    "manual_retry_requested_but_blocked",
                    "人工要求重试，但该版本为硬隔离，本流程内不能放行",
                )
            )

    unmatched = [
        {
            "message_id": mid,
            "action": disp.action,
            "operator": disp.operator,
            "note": disp.note,
        }
        for mid, disp in sorted(dispositions.items())
        if mid not in used
    ]
    return unmatched, []


def _apply_problem_statuses(items: list[Item], policy: Policy) -> None:
    for item in items:
        if item.status not in policy.problem_statuses:
            continue
        if item.verdict == VERDICT_RETRYABLE:
            item.verdict = VERDICT_QUARANTINED
        item.reasons.append(
            _reason(
                "problem_status",
                f"消息状态 {item.status!r} 属于需隔离状态，默认不自动重投",
            )
        )


def _finalize_releasable(items: list[Item]) -> None:
    """软隔离（问题状态）可以由批准账本逐版本放行；硬隔离永远不能。

    人工处置只是分诊建议：``retry`` 不会改变可重投性，``quarantine`` 会加
    一条人工隔离原因（硬隔离）。真正的放行证据只有批准账本里针对
    ``event_id`` 的批准。
    """

    for item in items:
        if item.verdict != VERDICT_QUARANTINED:
            item.releasable = False
            continue
        item.releasable = not item.hard_quarantine


# ---------------------------------------------------------------------------
# 批准
# ---------------------------------------------------------------------------
def attach_approvals(
    items: list[Item],
    digest: str,
    effective_grants: dict[str, Approval],
) -> tuple[list[dict], list[dict]]:
    """把有效批准绑定到计划，并找出失效批准。

    返回 ``(approvals, invalid_approvals)``。失效批准不会被导出，但必须
    让操作员看到，因此保留在计划里。
    """

    valid: list[dict] = []
    invalid: list[dict] = []
    known = {item.event_id: item for item in items}
    for event_id in sorted(effective_grants):
        grant = effective_grants[event_id]
        record = {
            "event_id": event_id,
            "action": grant.action,
            "approved_by": grant.approved_by,
            "approved_at": grant.approved_at,
            "plan_digest": grant.plan_digest,
        }
        item = known.get(event_id)
        if item is None:
            record["reason"] = "approval_for_unknown_event"
            invalid.append(record)
            continue
        if grant.action != "retry":
            record["reason"] = "unsupported_action"
            invalid.append(record)
            continue
        version_digest = event_version_digest(item)
        if grant.version_digest is None:
            # 旧账本（未绑定事件版本摘要）只能退化为整计划摘要校验
            if grant.plan_digest != digest:
                record["reason"] = "stale_plan_digest"
                invalid.append(record)
                continue
        else:
            if grant.version_digest != version_digest:
                record["reason"] = "stale_event_version"
                record["expected_version_digest"] = grant.version_digest
                record["actual_version_digest"] = version_digest
                invalid.append(record)
                continue
            if grant.plan_digest != digest:
                # 计划其余部分发生变化，但本版本的证据与判定未变：
                # 批准继续有效，同时留下审计提示。
                record["plan_drift"] = True
        if not item.eligible:
            record["reason"] = f"event_not_eligible:{item.verdict}"
            invalid.append(record)
            continue
        record["version_digest"] = version_digest
        record["event_version"] = {
            "business_key": item.business_key,
            "partition": item.partition,
            "offset": item.offset,
            "payload_sha256": item.payload_sha256,
        }
        valid.append(record)
        item.approval = record
    return valid, invalid


def build_plan(
    records: list[Record],
    dispositions: dict[str, Disposition] | None = None,
    policy: Policy | None = None,
    effective_grants: dict[str, Approval] | None = None,
) -> Plan:
    dispositions = dispositions or {}
    policy = policy or Policy()
    _validate_policy(policy)
    _check_identity_collisions(records)

    items = _build_items(records)
    _apply_supersession(items, policy)
    conflict_groups = _mark_conflicts(items, records)
    _mark_ambiguous_duplicates(items)
    _mark_cross_partition_duplicates(items)
    unmatched, _ = _apply_dispositions(items, dispositions)
    _apply_problem_statuses(items, policy)
    _finalize_releasable(items)

    items.sort(key=lambda i: i.sort_key)
    digest = plan_digest(items=items, conflict_groups=conflict_groups, policy=policy)
    approvals, invalid = attach_approvals(items, digest, effective_grants or {})
    return Plan(
        items=items,
        conflict_groups=conflict_groups,
        unmatched_dispositions=unmatched,
        policy=policy,
        digest=digest,
        approvals=approvals,
        invalid_approvals=invalid,
    )


# ---------------------------------------------------------------------------
# 导出资格
# ---------------------------------------------------------------------------
def assert_exportable(plan: Plan, approval_store_digest: str | None = None) -> list[Item]:
    """返回应导出的版本；任何失效批准都视为硬错误。"""

    if plan.invalid_approvals:
        raise PolicyError(
            "存在失效或不允许的批准，必须先撤回/重新批准",
            details={"invalid_approvals": plan.invalid_approvals},
        )
    approved = plan.approved_items()
    if not approved:
        raise PolicyError(
            "没有任何有效批准的事件版本，拒绝导出",
            details={"held_unapproved": [it.event_id for it in plan.held_items()]},
        )
    for item in approved:
        if item.verdict == VERDICT_SUPERSEDED:
            raise PolicyError(
                f"批准的事件版本 {item.event_id} 已被后续事件取代，禁止重投",
                details={"event_id": item.event_id},
            )
        if item.verdict == VERDICT_QUARANTINED and not item.releasable:
            raise PolicyError(
                f"批准的事件版本 {item.event_id} 处于不可放行的硬隔离状态",
                details={"event_id": item.event_id, "reasons": item.reasons},
            )
        if item.verdict == VERDICT_QUARANTINED and item.conflict_group:
            raise PolicyError(
                f"批准的事件版本 {item.event_id} 属于冲突组 {item.conflict_group}，禁止重投",
                details={"event_id": item.event_id, "conflict_group": item.conflict_group},
            )
    return approved
