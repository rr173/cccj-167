"""命令行入口：``python -m dlq_recovery``。

子命令
------
preview   只读预览判定（可输出 JSON 计划供审批使用）
approve   为**指定 event_id** 写入批准
withdraw  撤回指定 event_id 的批准
export    仅导出已批准版本，生成按分区排序的重投包
verify    校验已导出的重投包
inspect   打印单个 event_id（或业务键）的完整证据

所有子命令都不建立任何队列连接。``--plan FILE`` 允许直接读取已保存的
计划做批准前展示；批准与导出始终以当前输入重新构建，避免陈旧计划被误用。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import TOOL_NAME, __version__
from .approvals import load_ledger, record_approval, record_withdrawal
from .errors import RecoveryError, ValidationError, WorkflowError
from .models import (
    Approval,
    load_dispositions,
    load_policy,
    load_records,
    payload_fingerprint,
)
from .offline import ensure_offline_runtime
from .package import export_package, verify_package
from .plan import Plan, assert_exportable, build_plan
from .preview import render_preview

EXIT_OK = 0
EXIT_INTEGRITY = 7


def _add_common(parser: argparse.ArgumentParser, *, need_inputs: bool = True) -> None:
    if need_inputs:
        parser.add_argument("--dead-letter", required=True, help="死信导出文件（JSONL）")
        parser.add_argument("--dispositions", help="人工处置文件（JSONL）")
        parser.add_argument("--policy", help="业务配置（JSON）")
    parser.add_argument(
        "--approvals",
        help="批准账本（JSONL）；缺省时视为没有任何批准",
    )


def _plan_from_args(args: argparse.Namespace) -> Plan:
    records = load_records(args.dead_letter)
    dispositions = load_dispositions(args.dispositions) if args.dispositions else {}
    policy = load_policy(args.policy)
    grants: dict[str, Approval] = {}
    if args.approvals:
        grants = load_ledger(args.approvals).active
    return build_plan(records, dispositions, policy, grants)


def _print_json(obj, stream=sys.stdout) -> None:
    stream.write(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def _write_json(path: str | Path, obj) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(p)


# ---------------------------------------------------------------------------
# 子命令实现
# ---------------------------------------------------------------------------
def cmd_preview(args: argparse.Namespace) -> int:
    plan = _plan_from_args(args)
    if args.json:
        text = json.dumps(plan.to_dict(), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.out:
            _write_json(args.out, plan.to_dict())
        sys.stdout.write(text)
        return EXIT_OK
    sys.stdout.write(
        render_preview(plan, max_items_per_verdict=args.max_items_per_verdict)
    )
    if args.out:
        _write_json(args.out, plan.to_dict())
        sys.stderr.write(f"计划已写入 {args.out}\n")
    return EXIT_OK


def cmd_approve(args: argparse.Namespace) -> int:
    plan = _plan_from_args(args)
    item = plan.item(args.event_id)
    if item is None:
        raise ValidationError(
            f"事件版本 {args.event_id} 不在当前计划中；请先用 preview --json 查看 event_id",
            details={"event_id": args.event_id},
        )
    if item.verdict == "superseded":
        raise WorkflowError(
            f"事件版本 {args.event_id} 已被后续事件取代，不能批准重投",
            details={"event_id": item.event_id, "superseded_by": item.superseded_by},
        )
    if item.verdict == "quarantined" and not item.releasable:
        raise WorkflowError(
            f"事件版本 {args.event_id} 为硬隔离（冲突/人工隔离/处置未决/处置矛盾），不能批准放行",
            details={"event_id": item.event_id, "reasons": item.reasons},
        )
    if not args.by.strip():
        raise WorkflowError("必须提供 --by（批准人）")
    if not item.eligible:
        raise ValidationError(
            f"事件版本 {args.event_id} 当前不可重投",
            details={"event_id": item.event_id, "verdict": item.verdict},
        )
    record = record_approval(
        args.approvals,
        event_id=item.event_id,
        action="retry",
        approved_by=args.by,
        plan_digest=plan.digest,
        version_digest=plan.version_digest(item.event_id),
        event_version={
            "business_key": item.business_key,
            "partition": item.partition,
            "offset": item.offset,
            "payload_sha256": item.payload_sha256,
        },
        note=args.note,
    )
    _print_json(
        {
            "ok": True,
            "approval": record,
            "event": {
                "event_id": item.event_id,
                "partition": item.partition,
                "offset": item.offset,
                "business_key": item.business_key,
                "payload_sha256": item.payload_sha256,
                "verdict": item.verdict,
            },
        }
    )
    return EXIT_OK


def cmd_withdraw(args: argparse.Namespace) -> int:
    # 撤回不要求当前计划中存在该版本：账本可能比最新计划更旧，
    # 但撤回必须永远可用，避免"无法撤回"的死角。
    record = record_withdrawal(
        args.approvals,
        event_id=args.event_id,
        withdrawn_by=args.by,
        reason=args.reason,
    )
    _print_json({"ok": True, "withdrawal": record})
    return EXIT_OK


def cmd_export(args: argparse.Namespace) -> int:
    plan = _plan_from_args(args)
    approved = assert_exportable(plan)
    manifest = export_package(plan, args.out)
    _print_json(
        {
            "ok": True,
            "out": str(Path(args.out)),
            "plan_digest": plan.digest,
            "exported_events": [it.event_id for it in approved],
            "counts": manifest["counts"],
            "partitions": manifest["partitions"],
            "files": sorted(manifest["files"]),
        }
    )
    return EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        report = verify_package(
            args.package, expected_plan_digest_value=args.expect_plan_digest
        )
    except RecoveryError as exc:
        _print_json({"ok": False, "error": exc.to_dict()})
        return EXIT_INTEGRITY
    _print_json(report)
    return EXIT_OK


def cmd_inspect(args: argparse.Namespace) -> int:
    plan = _plan_from_args(args)
    items = []
    if args.event_id:
        item = plan.item(args.event_id)
        if item is None:
            raise ValidationError(f"未找到事件版本 {args.event_id}")
        items = [item]
    elif args.business_key:
        items = [it for it in plan.items if it.business_key == args.business_key]
        if not items:
            raise ValidationError(f"未找到业务键 {args.business_key}")
    else:
        raise ValidationError("必须提供 --event-id 或 --business-key")
    _print_json(
        {
            "plan_digest": plan.digest,
            "items": [it.to_dict() for it in items],
            "conflict_groups": [
                g
                for g in plan.conflict_groups
                if any(v["event_id"] in {i.event_id for i in items} for v in g["versions"])
            ],
        }
    )
    return EXIT_OK


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="死信离线恢复工具：判定 → 预览 → 批准 → 导出重投包 → 校验。不连接生产队列。",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_preview = sub.add_parser("preview", help="只读预览判定")
    _add_common(p_preview)
    p_preview.add_argument("--json", action="store_true", help="输出完整 JSON 计划")
    p_preview.add_argument("--out", help="同时把 JSON 计划写入文件")
    p_preview.add_argument(
        "--max-items-per-verdict",
        type=int,
        default=50,
        help="终端预览每组最多展开条数（默认 50）",
    )
    p_preview.set_defaults(func=cmd_preview)

    p_approve = sub.add_parser("approve", help="批准指定事件版本重投")
    _add_common(p_approve)
    p_approve.add_argument("--event-id", required=True)
    p_approve.add_argument("--by", required=True, help="批准人")
    p_approve.add_argument("--note")
    p_approve.set_defaults(func=cmd_approve)

    p_withdraw = sub.add_parser("withdraw", help="撤回指定事件版本的批准")
    p_withdraw.add_argument("--approvals", required=True)
    p_withdraw.add_argument("--event-id", required=True)
    p_withdraw.add_argument("--by", required=True, help="撤回人")
    p_withdraw.add_argument("--reason")
    p_withdraw.set_defaults(func=cmd_withdraw)

    p_export = sub.add_parser("export", help="导出仅含已批准版本的重投包")
    _add_common(p_export)
    p_export.add_argument("--out", required=True, help="输出目录（必须不存在或为空）")
    p_export.set_defaults(func=cmd_export)

    p_verify = sub.add_parser("verify", help="校验重投包完整性与顺序")
    p_verify.add_argument("--package", required=True)
    p_verify.add_argument("--expect-plan-digest")
    p_verify.set_defaults(func=cmd_verify)

    p_inspect = sub.add_parser("inspect", help="查看单个事件版本或业务键的完整证据")
    _add_common(p_inspect)
    p_inspect.add_argument("--event-id")
    p_inspect.add_argument("--business-key")
    p_inspect.set_defaults(func=cmd_inspect)

    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        ensure_offline_runtime()
    except Exception as exc:  # pragma: no cover - 环境异常
        sys.stderr.write(f"离线守卫失败: {exc}\n")
        return EXIT_INTEGRITY
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except RecoveryError as exc:
        sys.stderr.write(json.dumps(exc.to_dict(), ensure_ascii=False, indent=2) + "\n")
        return exc.exit_code
    except KeyboardInterrupt:
        sys.stderr.write("已中断\n")
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
