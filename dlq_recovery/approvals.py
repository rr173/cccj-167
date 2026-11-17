"""人工批准账本。

- 追加式 JSONL，最新一条记录决定该事件版本当前是否被批准；
- 每条批准绑定 ``event_id``（含队列位置 + 载荷指纹）与 ``plan_digest``；
- 撤回不需要删除历史，新增一条 ``withdraw`` 即可审计；
- 写入使用临时文件 + fsync + 原子替换，并用文件锁避免并发覆盖。
"""

from __future__ import annotations

import contextlib
import datetime as _dt
import fcntl
import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from .errors import InputError, WorkflowError
from .models import Approval, strict_json_loads

RECORD_TYPES = frozenset({"approve", "withdraw"})


def utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}-{secrets.token_hex(4)}")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


@contextlib.contextmanager
def _locked(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    with open(lock_path, "a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


@dataclass
class LedgerState:
    grants: dict[str, Approval]
    records: list[dict]

    @property
    def active(self) -> dict[str, Approval]:
        return dict(self.grants)


def load_ledger(path: str | Path) -> LedgerState:
    p = Path(path)
    if not p.exists():
        return LedgerState(grants={}, records=[])
    try:
        raw = p.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"无法读取批准账本 {p}: {exc}")
    grants: dict[str, Approval] = {}
    records: list[dict] = []
    for line_no, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = strict_json_loads(line)
        except (ValueError, json.JSONDecodeError) as exc:
            raise InputError(f"批准账本第 {line_no} 行不是合法 JSON: {exc}")
        if not isinstance(obj, dict):
            raise InputError(f"批准账本第 {line_no} 行必须是 JSON 对象")
        kind = obj.get("type")
        if kind not in RECORD_TYPES:
            raise InputError(f"批准账本第 {line_no} 行 type 非法: {kind!r}")
        event_id = obj.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            raise InputError(f"批准账本第 {line_no} 行缺少 event_id")
        records.append(obj)
        if kind == "approve":
            for field in ("action", "approved_by", "approved_at", "plan_digest"):
                if not isinstance(obj.get(field), str) or not obj.get(field):
                    raise InputError(f"批准账本第 {line_no} 行缺少 {field}")
            version_digest = obj.get("version_digest")
            if version_digest is not None and (
                not isinstance(version_digest, str) or not version_digest
            ):
                raise InputError(f"批准账本第 {line_no} 行 version_digest 非法")
            grants[event_id] = Approval(
                event_id=event_id,
                action=obj["action"],
                approved_by=obj["approved_by"],
                approved_at=obj["approved_at"],
                plan_digest=obj["plan_digest"],
                version_digest=version_digest,
            )
        else:
            grants.pop(event_id, None)
    return LedgerState(grants=grants, records=records)


def _append_record(path: Path, record: dict) -> None:
    with _locked(path):
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
        # 保留原有字节（含末尾换行），只追加
        text = existing
        if text and not text.endswith("\n"):
            text += "\n"
        text += json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n"
        _atomic_write_text(path, text)


def record_approval(
    path: str | Path,
    *,
    event_id: str,
    action: str,
    approved_by: str,
    plan_digest: str,
    event_version: dict,
    version_digest: str | None = None,
    approved_at: str | None = None,
    note: str | None = None,
) -> dict:
    if action != "retry":
        raise WorkflowError(f"仅支持 retry 批准，实际为 {action!r}")
    if not approved_by.strip():
        raise WorkflowError("批准人不能为空")
    state = load_ledger(path)
    if event_id in state.grants:
        raise WorkflowError(
            f"事件版本 {event_id} 已有有效批准，请先撤回再重新批准",
            details={"event_id": event_id},
        )
    record = {
        "type": "approve",
        "event_id": event_id,
        "action": action,
        "approved_by": approved_by,
        "approved_at": approved_at or utcnow(),
        "plan_digest": plan_digest,
        "event_version": event_version,
    }
    if version_digest:
        record["version_digest"] = version_digest
    if note:
        record["note"] = note
    _append_record(Path(path), record)
    return record


def record_withdrawal(
    path: str | Path,
    *,
    event_id: str,
    withdrawn_by: str,
    reason: str | None = None,
    withdrawn_at: str | None = None,
) -> dict:
    if not withdrawn_by.strip():
        raise WorkflowError("撤回人不能为空")
    state = load_ledger(path)
    if event_id not in state.grants:
        raise WorkflowError(
            f"事件版本 {event_id} 没有可撤回的有效批准",
            details={"event_id": event_id},
        )
    record = {
        "type": "withdraw",
        "event_id": event_id,
        "withdrawn_by": withdrawn_by,
        "withdrawn_at": withdrawn_at or utcnow(),
    }
    if reason:
        record["reason"] = reason
    _append_record(Path(path), record)
    return record
