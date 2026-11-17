"""对账视图的终端渲染（只读、纯文本，便于归档）。"""

from __future__ import annotations

from .recon import (
    EFFECTIVE_CONFLICT,
    EFFECTIVE_MISSING,
    EFFECTIVE_NOT_EXECUTED,
    EFFECTIVE_SUCCESS,
    EFFECTIVE_UNKNOWN,
)

EFFECTIVE_LABELS = {
    EFFECTIVE_SUCCESS: "成功",
    EFFECTIVE_NOT_EXECUTED: "明确未执行",
    EFFECTIVE_UNKNOWN: "未知",
    EFFECTIVE_MISSING: "缺回执",
    EFFECTIVE_CONFLICT: "矛盾",
}

CHAIN_STATUS_LABELS = {
    "succeeded": "已成功",
    "conflict": "矛盾阻断",
    "in_flight": "在途尝试",
    "retryable": "可补投",
    "pending": "待结论",
}


def render_reconcile(view: dict) -> str:
    lines: list[str] = []
    lines.append("=" * 78)
    lines.append("交付对账 · 只读视图（不连接任何队列/服务）")
    lines.append("=" * 78)
    for chain in view["chains"]:
        lines.append(f"交付链 {chain['chain_id']}  原包 digest={chain['package_digest'][:16]}…")
        lines.append(f"  原尝试={chain['origin_attempt_id']}  登记于 {chain['registered_at']}")
        if chain["open_attempt_id"]:
            lines.append(f"  ⚠ 未完成补投尝试: {chain['open_attempt_id']}（完成前不能再次签发）")
        else:
            lines.append("  当前没有未完成的补投尝试，可以签发补投")
        lines.append("")
        lines.append("  尝试历史:")
        for attempt in chain["attempts"]:
            counts = attempt["result_counts"]
            parts = " / ".join(
                f"{EFFECTIVE_LABELS[k]}={counts[k]}"
                for k in (
                    EFFECTIVE_SUCCESS,
                    EFFECTIVE_NOT_EXECUTED,
                    EFFECTIVE_UNKNOWN,
                    EFFECTIVE_MISSING,
                    EFFECTIVE_CONFLICT,
                )
            )
            lines.append(
                f"    {attempt['attempt_id']} [{attempt['kind']}/{attempt['status']}] "
                f"seq={attempt['seq_in_chain']}  {parts}"
            )
        lines.append("")
        lines.append("  事件对账（按原包分区顺序）:")
        current_partition = None
        for event in chain["events"]:
            if event["partition"] != current_partition:
                current_partition = event["partition"]
                lines.append(f"    分区 {current_partition}:")
            per_attempt = " ".join(
                f"{aid}→{EFFECTIVE_LABELS.get(eff, eff)}"
                for aid, eff in sorted(event["per_attempt"].items())
            )
            lines.append(
                f"      {event['offset']:>4} {event['event_id']}  "
                f"[{CHAIN_STATUS_LABELS.get(event['chain_status'], event['chain_status'])}]  {per_attempt}"
            )
            for ev in event["evidence"]:
                lines.append(
                    f"            证据 {ev['attempt_id']} {ev['result']} by={ev['reported_by']} "
                    f"at={ev['reported_at']} 来源数={ev['sources']} hash={ev['evidence_hash'][:12]}…"
                )
        lines.append("")
        preview = chain["next_replay_preview"]
        lines.append(
            f"  下一次补投预览: 入选 {len(preview['included'])} / "
            f"阻塞点 {len(preview['blockers'])} / 截留 {len(preview['withheld'])}"
        )
        for blocker in preview["blockers"]:
            lines.append(
                f"    阻塞 {blocker['partition']}@{blocker['offset']} "
                f"{blocker['event_id']} 原因={blocker['reason']}"
            )
        if chain["anomalies"]:
            lines.append("")
            lines.append("  异常（历史保留，不自动消解）:")
            for anomaly in chain["anomalies"]:
                lines.append(f"    [{anomaly['kind']}] {anomaly['event_id']}: {anomaly['detail']}")
        lines.append("")
    return "\n".join(lines) + "\n"
