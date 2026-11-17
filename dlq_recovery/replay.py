"""补投包的生成与校验。

补投包是对账存储**内部产物**（位于 ``packages/<chain>/attempts/<attempt>/
package``），结构沿用交付包的原子发布约定（临时目录 + fsync + ``.complete``
标记），但每条记录额外携带：

- ``replay.attempt_id``：本次补投尝试；
- ``replay.prev_attempt_id``：补投链上的上一次尝试；
- ``replay.basis``：该事件被允许补投的依据（上一次明确未执行的尝试、该尝试
  内的派生态与全部失败证据哈希）；
- ``replay.origin_event_id``：原包事件身份（与 ``event_id`` 相同，显式标注），
  以及原包完整 replay 记录（载荷、批准、来源证据原样保留，回执无法修改它们）。

校验以对账日志里 ``attempt_publishing`` 意图为权威：包内事件集合、分区顺序、
每事件的载荷摘要与补投依据必须与登记内容逐字一致，防止替换源包、重复事件、
越过阻塞位置或手工伪造批次。
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
from pathlib import Path

from . import TOOL_NAME, __version__
from .approvals import utcnow
from .errors import IntegrityError
from .models import canonical_json, sha256_text
from .package import COMPLETE_MARKER, _safe_partition_filename
from .recon import (
    KIND_REPLAY,
    ReconciliationState,
)

REPLAY_FORMAT = "dlq-recovery-replay-package"
REPLAY_FORMAT_VERSION = 1


# ---------------------------------------------------------------------------
# 内容身份
# ---------------------------------------------------------------------------
def compute_package_digest(manifest: dict) -> str:
    """根据 manifest 的内容字段独立计算包内容身份。

    只纳入由包内容决定的字段（文件哈希、计划摘要、格式、分区清单），不纳入
    生成时间等环境字段，使同一内容的两次计算结果一致。
    """

    payload = {
        "format": manifest["format"],
        "format_version": manifest["format_version"],
        "plan_digest": manifest.get("plan_digest"),
        "files": manifest["files"],
        "partitions": manifest.get("partitions", []),
    }
    return sha256_text(canonical_json(payload))


def _write_atomic(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _jsonl(rows) -> str:
    return "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows)


# ---------------------------------------------------------------------------
# 构建
# ---------------------------------------------------------------------------
def _origin_index(state: ReconciliationState, chain: dict) -> dict[str, dict]:
    return {event["event_id"]: event for event in chain["events"]}


def _basis_evidence(state: ReconciliationState, basis_attempt_id: str, event_id: str) -> dict:
    effective = state.effective_for(basis_attempt_id, event_id)
    observations = state.evidence_for(basis_attempt_id, event_id)
    return {
        "basis_attempt_id": basis_attempt_id,
        "effective_result": effective,
        "observations": [
            {
                "result": obs.result,
                "evidence_hash": obs.evidence_hash,
                "reported_by": obs.receipt["reported_by"],
                "reported_at": obs.receipt["reported_at"],
                "receipt_id": obs.receipt.get("receipt_id"),
                "detail": obs.receipt.get("detail"),
            }
            for obs in observations
        ],
    }


def _build_files(
    *,
    state: ReconciliationState,
    chain: dict,
    attempt_id: str,
    prev_attempt_id: str,
    included: list[dict],
    blockers: list[dict],
    withheld: list[dict],
) -> tuple[dict[str, str], list[dict], list[dict]]:
    """构建补投包的全部文件内容与元数据（纯函数，不碰磁盘目标目录）。"""

    origin_index = _origin_index(state, chain)
    by_partition: dict[str, list[dict]] = {}
    for entry in included:
        by_partition.setdefault(entry["partition"], []).append(entry)

    files: dict[str, str] = {}
    replay_rows: list[dict] = []
    partitions_meta = []
    for partition in sorted(by_partition):
        entries = sorted(
            by_partition[partition], key=lambda e: (e["offset"], e["event_id"])
        )
        rows = []
        for seq, entry in enumerate(entries, start=1):
            origin = origin_index[entry["event_id"]]
            if origin["payload_sha256"] != entry["payload_sha256"]:
                raise IntegrityError(
                    "补投候选载荷与原包快照不符，拒绝签发",
                    details={"event_id": entry["event_id"]},
                )
            origin_record = origin["replay_record"]
            basis = _basis_evidence(
                state, entry["basis_attempt_id"], entry["event_id"]
            )
            row = {
                "record_type": "replay",
                "sequence": len(replay_rows) + 1,
                "partition_sequence": seq,
                "event_id": entry["event_id"],
                "business_key": origin_record["business_key"],
                "partition": entry["partition"],
                "offset": entry["offset"],
                "event_type": origin_record["event_type"],
                "status": origin_record["status"],
                "occurred_at": origin_record["occurred_at"],
                "payload": origin_record["payload"],
                "payload_sha256": entry["payload_sha256"],
                # 原包身份与证据原样保留，回执无法修改
                "origin": {
                    "origin_attempt_id": chain["origin_attempt_id"],
                    "origin_event_id": origin_record["event_id"],
                    "package_digest": chain["package_digest"],
                    "source_records": origin_record["source_records"],
                    "approval": origin_record["approval"],
                    "failure_reasons": origin_record["failure_reasons"],
                    "failure_evidence": origin_record["failure_evidence"],
                },
                "replay": {
                    "attempt_id": attempt_id,
                    "prev_attempt_id": prev_attempt_id,
                    "chain_id": chain["chain_id"],
                    "basis": basis,
                },
            }
            rows.append(row)
            replay_rows.append(row)
        name = f"partitions/{_safe_partition_filename(partition)}"
        files[name] = _jsonl(rows)
        partitions_meta.append(
            {"partition": partition, "records": len(rows),
             "first_offset": entries[0]["offset"], "last_offset": entries[-1]["offset"]}
        )

    files["basis/blockers.ndjson"] = _jsonl(blockers)
    files["basis/withheld.ndjson"] = _jsonl(withheld)
    checksums = "".join(
        f"{sha256_text(text)}  {name}\n" for name, text in sorted(files.items())
    )
    files["checksums.sha256"] = checksums
    return files, partitions_meta, replay_rows


def plan_replay_manifest(
    *,
    state: ReconciliationState,
    chain: dict,
    attempt_id: str,
    prev_attempt_id: str,
    included: list[dict],
    blockers: list[dict],
    withheld: list[dict],
    created_by: str,
) -> tuple[dict, dict[str, str]]:
    """在写盘之前算出 manifest（含确定性 package_digest）与文件内容。"""

    files, partitions_meta, replay_rows = _build_files(
        state=state,
        chain=chain,
        attempt_id=attempt_id,
        prev_attempt_id=prev_attempt_id,
        included=included,
        blockers=blockers,
        withheld=withheld,
    )
    manifest = {
        "format": REPLAY_FORMAT,
        "format_version": REPLAY_FORMAT_VERSION,
        "kind": KIND_REPLAY,
        "tool": {"name": TOOL_NAME, "version": __version__},
        "generated_at": utcnow(),
        "generated_by": created_by,
        "chain_id": chain["chain_id"],
        "origin_attempt_id": chain["origin_attempt_id"],
        "attempt_id": attempt_id,
        "prev_attempt_id": prev_attempt_id,
        "plan_digest": chain["plan_digest"],
        "origin_package_digest": chain["package_digest"],
        "partitions": partitions_meta,
        "counts": {
            "replayed_events": len(replay_rows),
            "blocked_partitions": len({b["partition"] for b in blockers}),
            "blocker_events": len(blockers),
            "withheld_events": len(withheld),
        },
        "events": [
            {
                "event_id": e["event_id"],
                "partition": e["partition"],
                "offset": e["offset"],
                "payload_sha256": e["payload_sha256"],
                "basis_attempt_id": e["basis_attempt_id"],
            }
            for e in sorted(included, key=lambda e: (e["partition"], e["offset"]))
        ],
        "files": {
            name: {
                "sha256": sha256_text(text),
                "bytes": len(text.encode("utf-8")),
                "lines": text.count("\n"),
            }
            for name, text in sorted(files.items())
        },
    }
    manifest["package_digest"] = compute_package_digest(manifest)
    return manifest, files


def build_replay_package(
    *,
    state: ReconciliationState,
    chain: dict,
    attempt_id: str,
    prev_attempt_id: str,
    included: list[dict],
    blockers: list[dict],
    withheld: list[dict],
    out_dir: Path,
    created_by: str,
) -> dict:
    out_dir = Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir, ignore_errors=True)
    manifest, files = plan_replay_manifest(
        state=state,
        chain=chain,
        attempt_id=attempt_id,
        prev_attempt_id=prev_attempt_id,
        included=included,
        blockers=blockers,
        withheld=withheld,
        created_by=created_by,
    )
    staging = out_dir.with_name(f".{out_dir.name}.staging-{os.getpid()}-{secrets.token_hex(4)}")
    staging.mkdir(parents=True, exist_ok=False)
    try:
        _write_atomic(
            staging / "manifest.json",
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        for name, text in files.items():
            _write_atomic(staging / name, text)
        _write_atomic(staging / COMPLETE_MARKER, "complete\n")
        os.replace(staging, out_dir)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return manifest


# ---------------------------------------------------------------------------
# 校验
# ---------------------------------------------------------------------------
def verify_replay_package(store, package_dir: str | Path) -> dict:
    """对照对账存储校验补投包。

    权威依据是日志中该尝试的 ``attempt_publishing`` 意图（事件清单与依据在
    签发前已落盘），因此即便后续回执继续到达，已签发包仍能被确定性校验。
    """

    from .recon import STATUS_ABORTED, STATUS_DELIVERED  # 局部导入避免循环

    root = Path(package_dir)
    problems: list[dict] = []
    if not root.is_dir():
        raise IntegrityError(f"补投包目录不存在: {root}")
    if not (root / COMPLETE_MARKER).exists():
        raise IntegrityError("补投包缺少完成标记，发布可能中断；请由存储恢复后重新签发")
    try:
        manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (ValueError, OSError) as exc:
        raise IntegrityError(f"manifest.json 无法读取: {exc}")
    if manifest.get("format") != REPLAY_FORMAT:
        raise IntegrityError(
            f"manifest.format 非法: {manifest.get('format')!r}（这不是补投包，请用 verify）"
        )

    state = store.load()
    attempt_id = manifest.get("attempt_id")
    attempt = state.attempts.get(attempt_id)
    if attempt is None:
        raise IntegrityError(
            f"补投包尝试 {attempt_id!r} 未在对账存储登记，拒绝来源不明的批次",
            details={"attempt_id": attempt_id},
        )
    if attempt["kind"] != KIND_REPLAY:
        problems.append({"kind": "attempt_kind_mismatch", "expected": KIND_REPLAY})
    if attempt["status"] == STATUS_ABORTED:
        problems.append({"kind": "attempt_was_aborted", "attempt_id": attempt_id})

    chain = state.chains.get(attempt["chain_id"])
    if chain is None:
        raise IntegrityError(f"尝试 {attempt_id} 所属交付链缺失，存储可能损坏")
    origin_index = _origin_index(state, chain)

    # 1) 文件哈希
    for name, entry in sorted(manifest.get("files", {}).items()):
        path = root / name
        if not path.exists():
            problems.append({"kind": "missing_file", "file": name})
            continue
        raw = path.read_bytes()
        actual = sha256_text(raw.decode("utf-8"))
        if actual != entry.get("sha256"):
            problems.append({"kind": "checksum_mismatch", "file": name})

    # 2) 内容身份摘要
    recomputed_digest = compute_package_digest(manifest)
    if recomputed_digest != manifest.get("package_digest"):
        problems.append({"kind": "package_self_digest_mismatch"})
    if attempt.get("package_digest") and manifest.get("package_digest") != attempt["package_digest"]:
        problems.append({"kind": "package_digest_not_registered"})

    # 3) 事件集合必须与签发意图逐字一致：拒绝替换源包/重复事件/越过阻塞位置
    intended = sorted(
        attempt["event_order"], key=lambda e: (e["partition"], e["offset"], e["event_id"])
    )
    packaged_events = sorted(
        manifest.get("events", []),
        key=lambda e: (e["partition"], e["offset"], e["event_id"]),
    )
    intended_keys = [(e["event_id"], e["partition"], e["offset"]) for e in intended]
    packaged_keys = [(e["event_id"], e["partition"], e["offset"]) for e in packaged_events]
    if len(set(packaged_keys)) != len(packaged_keys):
        problems.append({"kind": "duplicate_event_in_batch"})
    if packaged_keys != intended_keys:
        problems.append(
            {
                "kind": "batch_not_matching_registration",
                "intended": intended_keys,
                "actual": packaged_keys,
            }
        )

    # 4) 分区记录逐条核对：载荷、依据、顺序
    seen_ids: set[str] = set()
    for partition_file in sorted((root / "partitions").glob("*.ndjson")):
        rows = [json.loads(line) for line in partition_file.read_text(encoding="utf-8").splitlines()
                if line.strip()]
        offsets = [r["offset"] for r in rows]
        if offsets != sorted(offsets):
            problems.append({"kind": "partition_offset_out_of_order", "file": partition_file.name})
        if len(offsets) != len(set(offsets)):
            problems.append({"kind": "partition_offset_duplicate", "file": partition_file.name})
        sequences = [r["partition_sequence"] for r in rows]
        if sequences != list(range(1, len(rows) + 1)):
            problems.append({"kind": "partition_sequence_invalid", "file": partition_file.name})
        for row in rows:
            eid = row["event_id"]
            if eid in seen_ids:
                problems.append({"kind": "duplicate_event_in_batch", "event_id": eid})
            seen_ids.add(eid)
            origin = origin_index.get(eid)
            if origin is None:
                problems.append({"kind": "unknown_event", "event_id": eid})
                continue
            if row["payload_sha256"] != origin["payload_sha256"]:
                problems.append({"kind": "payload_replaced", "event_id": eid})
            if row["payload"] != origin["replay_record"]["payload"]:
                problems.append({"kind": "payload_content_replaced", "event_id": eid})
            if row.get("origin", {}).get("source_records") != origin["replay_record"]["source_records"]:
                problems.append({"kind": "source_evidence_replaced", "event_id": eid})
            if row.get("origin", {}).get("approval") != origin["replay_record"]["approval"]:
                problems.append({"kind": "approval_evidence_replaced", "event_id": eid})
            intended_entry = next((e for e in intended if e["event_id"] == eid), None)
            if intended_entry is None:
                problems.append({"kind": "event_not_in_registration", "event_id": eid})
                continue
            replay = row.get("replay", {})
            if replay.get("attempt_id") != attempt_id:
                problems.append({"kind": "attempt_binding_mismatch", "event_id": eid})
            if replay.get("prev_attempt_id") != attempt["prev_attempt_id"]:
                problems.append({"kind": "prev_attempt_binding_mismatch", "event_id": eid})
            basis = replay.get("basis", {})
            if basis.get("basis_attempt_id") != intended_entry.get("basis_attempt_id"):
                problems.append({"kind": "failure_basis_mismatch", "event_id": eid})
            elif basis.get("effective_result") != "not_executed":
                problems.append(
                    {"kind": "failure_basis_not_definitive", "event_id": eid,
                     "effective_result": basis.get("effective_result")}
                )

    if seen_ids != {e["event_id"] for e in intended}:
        problems.append({"kind": "batch_event_set_mismatch"})

    # 5) 重新独立计算一次候选集，作为信息项展示当前状态是否仍支持该批次
    from .recon import compute_replay_candidates

    current = compute_replay_candidates(state, chain["chain_id"])
    current_ids = {e["event_id"] for e in current["included"]}
    stale = sorted(seen_ids - current_ids)

    report = {
        "ok": not problems,
        "package": str(root),
        "attempt_id": attempt_id,
        "chain_id": chain["chain_id"],
        "attempt_status": attempt["status"],
        "package_digest": manifest.get("package_digest"),
        "verified_events": len(seen_ids),
        "current_replayable_not_in_package": sorted(current_ids - seen_ids),
        "package_events_no_longer_replayable": stale,
        "problems": problems,
    }
    if problems:
        raise IntegrityError(
            f"补投包校验失败，共 {len(problems)} 个问题",
            details={"report": report},
        )
    return report
