"""重投包生成、中断恢复与结果校验。

包结构（目录）::

    <out>/
      manifest.json           包元数据 + 摘要 + 分片文件哈希
      plan.json               判定计划（完整证据，供追溯）
      README.txt              给下游的操作说明
      partitions/
        p-<id>.ndjson         按分区切分的重投记录，分区内按原偏移升序
      quarantine/
        items.ndjson          隔离件（冲突/需人工处置）
        conflicts.ndjson      冲突组明细（含全部载荷版本）
      checksums.sha256        上述文件逐行 sha256

重投记录只包含"有效批准"的版本；分区内按 ``(offset, event_id)`` 稳定排序，
跨分区互不影响。包在临时目录内构建完成后整体原子替换，配合
``manifest.json.complete`` 标记与校验和，可识别导出中断与残缺包。
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
from pathlib import Path
from typing import Iterable

from . import TOOL_NAME, __version__
from .approvals import utcnow
from .errors import IntegrityError, WorkflowError
from .models import canonical_json, sha256_text
from .plan import (
    PLAN_FORMAT,
    PLAN_FORMAT_VERSION,
    VERDICT_QUARANTINED,
    Plan,
    assert_exportable,
)

PACKAGE_FORMAT = "dlq-recovery-package"
PACKAGE_FORMAT_VERSION = 1
COMPLETE_MARKER = ".complete"

PARTITION_FILE_UNSAFE = set('/\\:*?"<>|')


def _safe_partition_filename(partition: str) -> str:
    cleaned = "".join("_" if ch in PARTITION_FILE_UNSAFE or ord(ch) < 32 else ch for ch in partition)
    if cleaned in ("", ".", ".."):
        cleaned = "_" + cleaned
    return f"p-{cleaned}.ndjson"


def _jsonl(rows: Iterable[dict]) -> str:
    return "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows)


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _delivery_record(item, *, sequence: int) -> dict:
    """一条重投记录：下游可直接按分区+偏移重放。"""

    return {
        "record_type": "replay",
        "sequence": sequence,
        "event_id": item.event_id,
        "business_key": item.business_key,
        "partition": item.partition,
        "offset": item.offset,
        "event_type": item.event_type,
        "status": item.status,
        "occurred_at": item.occurred_at,
        "payload": item.payload,
        "payload_sha256": item.payload_sha256,
        "delivery_count_max": item.delivery_count_max,
        "failure_reasons": item.failure_reasons,
        "failure_evidence": item.failure_evidence,
        "source_records": [s.to_dict() for s in sorted(
            item.sources, key=lambda s: (s.partition, s.offset, s.message_id, s.line_no)
        )],
        "approval": item.approval,
        "traces": {
            "message_ids": [i["message_id"] for i in item.identities],
            "source_lines": sorted({s.line_no for s in item.sources}),
            "queue_positions": [
                {"partition": s.partition, "offset": s.offset}
                for s in sorted(item.sources, key=lambda s: (s.partition, s.offset, s.message_id, s.line_no))
                if s.partition == item.partition
            ],
        },
    }


def _quarantine_record(item, *, sequence: int) -> dict:
    return {
        "record_type": "quarantine",
        "sequence": sequence,
        "event_id": item.event_id,
        "verdict": item.verdict,
        "releasable": item.releasable,
        "business_key": item.business_key,
        "partition": item.partition,
        "offset": item.offset,
        "payload_sha256": item.payload_sha256,
        "payload": item.payload,
        "event_type": item.event_type,
        "status": item.status,
        "occurred_at": item.occurred_at,
        "reasons": item.reasons,
        "conflict_group": item.conflict_group,
        "delivery_count_max": item.delivery_count_max,
        "failure_reasons": item.failure_reasons,
        "failure_evidence": item.failure_evidence,
        "source_records": [s.to_dict() for s in sorted(
            item.sources, key=lambda s: (s.partition, s.offset, s.message_id, s.line_no)
        )],
        "disposition": item.disposition,
        "approval": item.approval,
    }


def _build_payloads(plan: Plan) -> dict[str, str]:
    approved = assert_exportable(plan)
    files: dict[str, str] = {}

    # 分区文件：只含已批准版本，分区内按偏移排序；跨分区按分区名排序。
    by_partition: dict[str, list] = {}
    for item in approved:
        by_partition.setdefault(item.partition, []).append(item)
    for partition in sorted(by_partition):
        items = sorted(by_partition[partition], key=lambda i: (i.offset, i.event_id))
        rows = []
        for seq, item in enumerate(items, start=1):
            record = _delivery_record(item, sequence=seq)
            record["partition_sequence"] = seq
            rows.append(record)
        files[f"partitions/{_safe_partition_filename(partition)}"] = _jsonl(rows)

    approved_ids = {it.event_id for it in approved}
    quarantined = sorted(
        (
            it
            for it in plan.items
            if it.verdict == VERDICT_QUARANTINED and it.event_id not in approved_ids
        ),
        key=lambda i: (i.partition, i.offset, i.event_id),
    )
    files["quarantine/items.ndjson"] = _jsonl(
        _quarantine_record(it, sequence=seq)
        for seq, it in enumerate(quarantined, start=1)
    )
    files["quarantine/conflicts.ndjson"] = _jsonl(plan.conflict_groups)

    plan_doc = plan.to_dict()
    plan_doc["exported_approvals"] = [
        {"event_id": it.event_id, "approval": it.approval} for it in approved
    ]
    files["plan.json"] = json.dumps(plan_doc, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    summary = plan.counts()
    files["README.txt"] = (
        f"{TOOL_NAME} {__version__} 离线重投包\n"
        f"计划摘要: {plan.digest}\n"
        f"生成时间(UTC): {utcnow()}\n\n"
        f"记录数={summary['records']} 版本数={summary['items']} 已批准重投={summary['approved']} "
        f"隔离={summary['quarantined']} 被替代={summary['superseded']}\n\n"
        "partitions/*.ndjson: 仅含有效批准的事件版本，分区内按原队列偏移升序；\n"
        "  每条记录带 event_id / payload_sha256 / source_records，可追溯回原偏移与失败证据。\n"
        "quarantine/items.ndjson: 需隔离版本，下游不得重放。\n"
        "quarantine/conflicts.ndjson: 同业务键冲突载荷的完整保留件。\n"
        "本包由离线工具生成，不包含任何队列连接动作。\n"
    )

    checksums = "".join(
        f"{sha256_text(text)}  {name}\n" for name, text in sorted(files.items())
    )
    files["checksums.sha256"] = checksums
    return files


def export_package(plan: Plan, out_dir: str | Path) -> dict:
    """原子生成重投包，返回 manifest。"""

    out = Path(out_dir)
    if out.exists() and any(out.iterdir()):
        raise WorkflowError(
            f"输出目录非空，拒绝覆盖既有产物: {out}",
            details={"path": str(out)},
        )
    files = _build_payloads(plan)
    staging = out.with_name(f".{out.name}.staging-{os.getpid()}-{secrets.token_hex(4)}")
    staging.mkdir(parents=True, exist_ok=False)
    try:
        for name, text in files.items():
            _write_atomic(staging / name, text)
        manifest = {
            "format": PACKAGE_FORMAT,
            "format_version": PACKAGE_FORMAT_VERSION,
            "tool": {"name": TOOL_NAME, "version": __version__},
            "generated_at": utcnow(),
            "plan_digest": plan.digest,
            "counts": plan.counts(),
            "partitions": plan.partitions(),
            "files": {
                name: {
                    "sha256": sha256_text(text),
                    "bytes": len(text.encode("utf-8")),
                    "lines": text.count("\n"),
                }
                for name, text in sorted(files.items())
            },
        }
        _write_atomic(
            staging / "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        # 完成标记只写"本包已完整落盘"的事实，不参与摘要语义
        _write_atomic(staging / COMPLETE_MARKER, "complete\n")
        if out.exists():
            if any(out.iterdir()):
                raise WorkflowError(f"输出目录在导出期间被占用: {out}")
            out.rmdir()
        os.replace(staging, out)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------
def _load_json_file(path: Path) -> dict:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise IntegrityError(f"缺少文件: {path}")
    except (OSError, UnicodeDecodeError) as exc:
        raise IntegrityError(f"无法读取 {path}: {exc}")
    try:
        obj = json.loads(raw)
    except (ValueError, json.JSONDecodeError) as exc:
        raise IntegrityError(f"{path} 不是合法 JSON: {exc}")
    if not isinstance(obj, dict):
        raise IntegrityError(f"{path} 必须是 JSON 对象")
    return obj


def _load_ndjson(path: Path) -> list[dict]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise IntegrityError(f"缺少文件: {path}")
    except (OSError, UnicodeDecodeError) as exc:
        raise IntegrityError(f"无法读取 {path}: {exc}")
    rows = []
    for line_no, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except (ValueError, json.JSONDecodeError) as exc:
            raise IntegrityError(f"{path}:{line_no} 不是合法 JSON: {exc}")
        if not isinstance(obj, dict):
            raise IntegrityError(f"{path}:{line_no} 必须是 JSON 对象")
        rows.append(obj)
    return rows


def _approval_digest(approval: dict | None) -> str:
    """批准记录在摘要计算中只取稳定字段。"""

    if approval is None:
        return ""
    return canonical_json(approval)


def expected_plan_digest(plan_doc: dict) -> str:
    """从包内 plan.json 独立重算判定摘要（不信任其自带 digest 字段）。"""

    from .plan import Policy, digest_from_plan_dict

    try:
        digest = digest_from_plan_dict(plan_doc)
    except (KeyError, TypeError, AttributeError) as exc:
        raise IntegrityError(f"plan.json 结构不完整: {exc}")
    return digest


def verify_package(
    package_dir: str | Path,
    *,
    expected_plan_digest_value: str | None = None,
) -> dict:
    """完整校验重投包，返回报告；任何不一致抛 IntegrityError。"""

    root = Path(package_dir)
    problems: list[dict] = []
    if not root.is_dir():
        raise IntegrityError(f"包目录不存在: {root}")
    marker = root / COMPLETE_MARKER
    if not marker.exists():
        raise IntegrityError(
            "包未完整生成（缺少完成标记），导出可能中断；请重新导出",
            details={"path": str(root)},
        )
    manifest = _load_json_file(root / "manifest.json")
    if manifest.get("format") != PACKAGE_FORMAT:
        raise IntegrityError(f"manifest.format 非法: {manifest.get('format')!r}")

    # 1) 文件哈希
    file_entries = manifest.get("files")
    if not isinstance(file_entries, dict) or not file_entries:
        raise IntegrityError("manifest.files 缺失或为空")
    for name, entry in sorted(file_entries.items()):
        path = root / name
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            problems.append({"kind": "missing_file", "file": name})
            continue
        except OSError as exc:
            problems.append({"kind": "unreadable_file", "file": name, "detail": str(exc)})
            continue
        actual = sha256_text(raw.decode("utf-8"))
        if actual != entry.get("sha256"):
            problems.append({"kind": "checksum_mismatch", "file": name})
        if len(raw) != entry.get("bytes"):
            problems.append({"kind": "size_mismatch", "file": name})
        if name.endswith(".sha256") and actual == entry.get("sha256"):
            # 校验和文件自身内容也逐项复核
            declared = {}
            for line in raw.decode("utf-8").splitlines():
                if not line.strip():
                    continue
                digest, _, target = line.partition("  ")
                declared[target] = digest
            for target, digest in declared.items():
                try:
                    target_raw = (root / target).read_bytes()
                except FileNotFoundError:
                    problems.append({"kind": "checksum_file_missing_target", "file": target})
                    continue
                if sha256_text(target_raw.decode("utf-8")) != digest:
                    problems.append({"kind": "checksum_file_mismatch", "file": target})
    missing_declared = [
        p for p in problems if p["kind"] in ("missing_file", "checksum_file_missing_target")
    ]
    if missing_declared:
        raise IntegrityError("包文件缺失，拒绝校验", details={"problems": problems})

    # 2) 完成标记与计划摘要
    marker_digest = marker.read_text(encoding="utf-8").strip()
    if marker_digest != "complete":
        problems.append({"kind": "completion_marker_invalid"})
    if expected_plan_digest_value is not None and manifest.get("plan_digest") != expected_plan_digest_value:
        problems.append(
            {
                "kind": "plan_digest_mismatch",
                "expected": expected_plan_digest_value,
                "actual": manifest.get("plan_digest"),
            }
        )

    # 3) 重算判定摘要
    plan_doc = _load_json_file(root / "plan.json")
    try:
        recomputed = expected_plan_digest(plan_doc)
    except IntegrityError as exc:
        problems.append({"kind": "plan_structure_invalid", "detail": str(exc)})
        recomputed = None
    if recomputed is not None and recomputed != plan_doc.get("digest"):
        problems.append({"kind": "plan_self_digest_mismatch"})
    if recomputed is not None and recomputed != manifest.get("plan_digest"):
        problems.append({"kind": "plan_recomputed_digest_mismatch"})

    # 4) 分区内偏移次序 + 跨分区独立
    partition_reports = []
    approved_ids = set()
    plan_items = {it.get("event_id"): it for it in plan_doc.get("items", []) if isinstance(it, dict)}
    partition_files = sorted(
        name for name in file_entries if name.startswith("partitions/") and name.endswith(".ndjson")
    )
    seen_partition_names = set()
    for name in partition_files:
        rows = _load_ndjson(root / name)
        partition_names = {row.get("partition") for row in rows}
        if len(partition_names) > 1:
            problems.append(
                {"kind": "partition_file_mixed", "file": name, "partitions": sorted(partition_names)}
            )
            continue
        offsets = [row.get("offset") for row in rows]
        if any(not isinstance(o, int) for o in offsets):
            problems.append({"kind": "partition_offset_not_integer", "file": name})
            continue
        if offsets != sorted(offsets):
            problems.append({"kind": "partition_offset_out_of_order", "file": name})
        if len(set(offsets)) != len(offsets):
            problems.append({"kind": "partition_offset_duplicate", "file": name})
        sequences = [row.get("partition_sequence") for row in rows]
        if sequences != list(range(1, len(rows) + 1)):
            problems.append({"kind": "partition_sequence_invalid", "file": name})
        for row in rows:
            event_id = row.get("event_id")
            item = plan_items.get(event_id)
            if item is None:
                problems.append({"kind": "unknown_event_in_partition", "event_id": event_id})
                continue
            if item.get("partition") != row.get("partition") or item.get("offset") != row.get("offset"):
                problems.append({"kind": "event_partition_offset_mismatch", "event_id": event_id})
            if item.get("payload_sha256") != row.get("payload_sha256"):
                problems.append({"kind": "event_payload_digest_mismatch", "event_id": event_id})
            if not item.get("eligible"):
                problems.append({"kind": "ineligible_event_exported", "event_id": event_id})
            approval = row.get("approval")
            if not isinstance(approval, dict):
                problems.append({"kind": "replay_without_approval", "event_id": event_id})
            approved_ids.add(event_id)
        if partition_names:
            seen_partition_names.add(next(iter(partition_names)))
        partition_reports.append(
            {
                "file": name,
                "partition": next(iter(partition_names)) if partition_names else None,
                "records": len(rows),
                "offsets_sorted": offsets == sorted(offsets),
                "first_offset": offsets[0] if offsets else None,
                "last_offset": offsets[-1] if offsets else None,
            }
        )

    # 5) 隔离件必须不可放行 / 冲突必须保留
    quarantine_rows = _load_ndjson(root / "quarantine/items.ndjson") if (
        root / "quarantine/items.ndjson"
    ).exists() else []
    quarantine_ids = set()
    for row in quarantine_rows:
        event_id = row.get("event_id")
        quarantine_ids.add(event_id)
        if event_id in approved_ids:
            problems.append({"kind": "quarantined_event_also_exported", "event_id": event_id})
        item = plan_items.get(event_id)
        if item is not None and item.get("verdict") != VERDICT_QUARANTINED:
            problems.append({"kind": "quarantine_verdict_mismatch", "event_id": event_id})
    conflict_rows = _load_ndjson(root / "quarantine/conflicts.ndjson") if (
        root / "quarantine/conflicts.ndjson"
    ).exists() else []
    planned_conflicts = {
        g.get("id"): g for g in plan_doc.get("conflict_groups", []) if isinstance(g, dict)
    }
    exported_conflicts = {g.get("id"): g for g in conflict_rows}
    for gid, group in planned_conflicts.items():
        if gid not in exported_conflicts:
            problems.append({"kind": "conflict_group_missing", "group_id": gid})
            continue
        for version in group.get("versions", []):
            event_id = version.get("event_id")
            if event_id in approved_ids:
                problems.append({"kind": "conflict_version_exported", "event_id": event_id})
            if event_id not in quarantine_ids:
                problems.append({"kind": "conflict_version_not_quarantined", "event_id": event_id})

    report = {
        "ok": not problems,
        "package": str(root),
        "plan_digest": manifest.get("plan_digest"),
        "recomputed_plan_digest": recomputed,
        "counts": manifest.get("counts"),
        "partitions": partition_reports,
        "approved_events": len(approved_ids),
        "quarantined_events": len(quarantine_ids),
        "conflict_groups": len(exported_conflicts),
        "problems": problems,
    }
    if problems:
        raise IntegrityError(
            f"重投包校验失败，共 {len(problems)} 个问题",
            details={"report": report},
        )
    return report
