"""终端预览渲染。

预览必须是纯离线、纯只读的：输出里包含判定、批准状态、冲突证据，
但不输出可执行指令，也不做任何队列连接。
"""

from __future__ import annotations

from .plan import (
    VERDICT_QUARANTINED,
    VERDICT_RETRYABLE,
    VERDICT_SUPERSEDED,
    Plan,
)

VERDICT_LABELS = {
    VERDICT_RETRYABLE: "可重投",
    VERDICT_QUARANTINED: "需隔离",
    VERDICT_SUPERSEDED: "已被取代",
}
VERDICT_ORDER = {VERDICT_RETRYABLE: 0, VERDICT_QUARANTINED: 1, VERDICT_SUPERSEDED: 2}


def _short(value: str | None, width: int = 12) -> str:
    if value is None:
        return "-"
    return value if len(value) <= width else value[: width - 1] + "…"


def render_preview(plan: Plan, *, color: bool = False, max_items_per_verdict: int | None = None) -> str:
    del color  # 预留，不引入终端控制码，便于日志归档
    counts = plan.counts()
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("死信离线恢复 · 只读预览（不连接生产队列）")
    lines.append("=" * 78)
    lines.append(
        f"记录 {counts['records']} 条 → 事件版本 {counts['items']} 个"
        f"（合并上游重发 {counts['merged_duplicate_records']} 条）"
    )
    lines.append(
        f"可重投 {counts['retryable']} | 需隔离 {counts['quarantined']}"
        f"（其中可批准放行 {counts['releasable_quarantined']}）"
        f" | 已被取代 {counts['superseded']}"
    )
    lines.append(
        f"冲突组 {counts['conflicts']} | 已有效批准 {counts['approved']}"
        f" | 待批准 {counts['held_unapproved']}"
        f" | 无主人工处置 {counts['unmatched_dispositions']}"
    )
    lines.append(f"计划摘要 {plan.digest}")
    lines.append("")

    lines.append("分区顺序（每个分区独立重排，包内按 offset 升序）")
    for info in plan.partitions():
        lines.append(
            f"  {info['partition']:<20} 版本 {info['items']:>3}  导出 {info['delivered']:>3}"
            f"  偏移范围 [{info['first_offset']}, {info['last_offset']}]"
        )
    if not plan.partitions():
        lines.append("  (无)")
    lines.append("")

    for verdict in (VERDICT_RETRYABLE, VERDICT_QUARANTINED, VERDICT_SUPERSEDED):
        items = [it for it in plan.items if it.verdict == verdict]
        lines.append(f"[{VERDICT_LABELS[verdict]}] {len(items)} 个版本")
        shown = items if max_items_per_verdict is None else items[:max_items_per_verdict]
        for item in shown:
            flag = ""
            if verdict == VERDICT_RETRYABLE:
                flag = "✓已批准" if item.approval else "·待批准"
            elif verdict == VERDICT_QUARANTINED:
                flag = "可批准放行" if item.releasable else "锁定隔离"
            lines.append(
                f"  {item.event_id}  {item.partition}@{item.offset}"
                f"  key={_short(item.business_key, 20)}  {item.event_type}/{item.status}"
                f"  来源{len(item.sources)}条  {flag}"
            )
            for reason in item.reasons:
                lines.append(f"      - [{reason['code']}] {reason['detail']}")
            if item.approval:
                lines.append(
                    f"      批准: {item.approval['approved_by']} @ {item.approval['approved_at']}"
                    f" digest={_short(item.approval['plan_digest'], 14)}"
                )
            if item.superseded_by:
                sb = item.superseded_by
                lines.append(
                    f"      取代者: {sb['event_id']} ({sb['status']} @ {sb['occurred_at']},"
                    f" {sb['partition']}@{sb['offset']})"
                )
        if max_items_per_verdict is not None and len(items) > len(shown):
            lines.append(f"  … 其余 {len(items) - len(shown)} 个未展开")
        lines.append("")

    if plan.conflict_groups:
        lines.append("[冲突组] 同业务键载荷不一致，全部保留、阻断自动重投")
        for group in plan.conflict_groups:
            lines.append(
                f"  {group['id']}  {group['kind']}  keys={','.join(group['business_keys'])}"
            )
            if group.get("partition") is not None:
                lines.append(f"      队列槽位 {group['partition']}@{group['offset']}")
            for version in group["versions"]:
                lines.append(
                    f"      {version['event_id']}  {version['partition']}@{version['offset']}"
                    f"  sha256={_short(version['payload_sha256'], 16)}"
                    f"  {version['event_type']}/{version['status']}"
                )
            lines.append(f"      {group['detail']}")
        lines.append("")

    if plan.invalid_approvals:
        lines.append("[失效批准] 不会被导出，需撤回或重新批准")
        for entry in plan.invalid_approvals:
            lines.append(
                f"  {entry['event_id']}  原因={entry['reason']}"
                f"  批准人={entry.get('approved_by')}"
            )
        lines.append("")

    if plan.unmatched_dispositions:
        lines.append("[无主人工处置] 未匹配到任何死信记录")
        for entry in plan.unmatched_dispositions:
            lines.append(
                f"  {entry['message_id']}  action={entry['action']}"
                f"  operator={entry['operator']}"
                + (f"  note={entry['note']}" if entry.get("note") else "")
            )
        lines.append("")

    lines.append("提示：批准只绑定上面列出的 event_id；同一业务键的其他版本不会被连带批准。")
    lines.append("提示：导出只包含已批准版本，分区内保持原偏移顺序。")
    return "\n".join(lines) + "\n"
