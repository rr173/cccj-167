"""输入模型：死信记录、消息、人工处置、业务配置、人工批准。

输入采用逐行 JSON（JSON Lines），便于跨分区交错与定位行号。所有解析失败
都带行号，绝不猜测或丢弃记录。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .errors import InputError

# 顶层字段（人工批准 / CLI 覆盖判断依赖此白名单）
RECORD_KEYS = frozenset({"message", "failure"})
MESSAGE_KEYS = frozenset(
    {
        "message_id",
        "business_key",
        "partition",
        "offset",
        "payload",
        "event_type",
        "status",
        "occurred_at",
        "source_attempt",
    }
)
FAILURE_KEYS = frozenset({"delivery_count", "reason", "evidence"})
DISPOSITION_KEYS = frozenset({"message_id", "action", "operator", "note"})

DEFAULT_STATUSES = frozenset({"needs_review", "suspended"})
DEFAULT_FINAL_STATUSES = frozenset({"deleted", "cancelled", "closed", "completed"})
DISPOSITION_ACTIONS = frozenset({"retry", "quarantine"})


# ---------------------------------------------------------------------------
# 规范 JSON（用于载荷指纹与计划摘要）
# ---------------------------------------------------------------------------
def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def payload_fingerprint(payload: Any) -> str:
    return sha256_text(canonical_json(payload))


# ---------------------------------------------------------------------------
# 数据模型
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Message:
    message_id: str
    business_key: str
    partition: str
    offset: int
    payload: Any
    event_type: str
    status: str
    occurred_at: int | None
    source_attempt: str | None

    @property
    def payload_fingerprint(self) -> str:
        return payload_fingerprint(self.payload)

    @property
    def sort_key(self) -> tuple[str, int, str]:
        return (self.partition, self.offset, self.message_id)


@dataclass(frozen=True)
class Failure:
    delivery_count: int
    reason: str
    evidence: str | None


@dataclass(frozen=True)
class Record:
    """死信文件中的一条记录。"""

    line_no: int
    message: Message
    failure: Failure

    @property
    def message_id(self) -> str:
        return self.message.message_id

    @property
    def business_key(self) -> str:
        return self.message.business_key

    @property
    def partition(self) -> str:
        return self.message.partition

    @property
    def offset(self) -> int:
        return self.message.offset

    @property
    def identity(self) -> tuple[str, str]:
        return (self.partition, self.message_id)


@dataclass(frozen=True)
class Disposition:
    """人工分诊意见。

    这是"建议"，不是"批准"：真正放行必须通过批准账本按 event_id 单独批准。
    """

    message_id: str
    action: str
    operator: str
    note: str | None


@dataclass(frozen=True)
class Policy:
    problem_statuses: frozenset[str] = DEFAULT_STATUSES
    final_statuses: frozenset[str] = DEFAULT_FINAL_STATUSES
    same_offset_payload_rule: str = "error"


@dataclass(frozen=True)
class Approval:
    """一条批准。

    ``version_digest`` 绑定到被批准的事件版本（含队列位置、载荷、失败证据、
    判定原因）；``plan_digest`` 记录批准时的完整计划，用于审计与回放。
    """

    event_id: str
    action: str
    approved_by: str
    approved_at: str
    plan_digest: str
    version_digest: str | None = None


# ---------------------------------------------------------------------------
# 底层校验工具
# ---------------------------------------------------------------------------
def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"重复的 JSON 键: {key!r}")
        out[key] = value
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"不允许的 JSON 常量: {name}")


def strict_json_loads(text: str) -> Any:
    """严格 JSON：拒绝重复键与 NaN/Infinity，避免校验歧义。"""

    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_constant,
    )


def _read_jsonl(path: str | Path, *, what: str) -> list[tuple[int, Any]]:
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise InputError(f"{what}文件不存在: {p}", details={"path": str(p)})
    except OSError as exc:
        raise InputError(f"无法读取{what}文件 {p}: {exc}", details={"path": str(p)})
    except UnicodeDecodeError as exc:
        raise InputError(f"{what}文件不是 UTF-8 编码: {p}: {exc}", details={"path": str(p)})

    out: list[tuple[int, Any]] = []
    for line_no, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = strict_json_loads(line)
        except (ValueError, json.JSONDecodeError) as exc:
            raise InputError(
                f"{what}第 {line_no} 行不是合法 JSON: {exc}",
                details={"path": str(p), "line": line_no},
            )
        if not isinstance(obj, dict):
            raise InputError(
                f"{what}第 {line_no} 行必须是 JSON 对象",
                details={"path": str(p), "line": line_no},
            )
        out.append((line_no, obj))
    return out


def _require_str(obj: dict, key: str, where: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"{where}: 字段 {key!r} 必须是非空字符串")
    return value


def _optional_int(obj: dict, key: str, where: str) -> int | None:
    value = obj.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputError(f"{where}: 字段 {key!r} 必须是整数或 null")
    return value


def _unknown_keys(obj: dict, allowed: frozenset[str], where: str) -> None:
    extra = sorted(set(obj) - allowed)
    if extra:
        raise InputError(f"{where}: 不认识的字段 {extra}")


def _parse_message(obj: Any, where: str) -> Message:
    if not isinstance(obj, dict):
        raise InputError(f"{where}: message 必须是 JSON 对象")
    _unknown_keys(obj, MESSAGE_KEYS, f"{where}.message")
    message_id = _require_str(obj, "message_id", f"{where}.message")
    business_key = _require_str(obj, "business_key", f"{where}.message")
    partition = _require_str(obj, "partition", f"{where}.message")
    offset = _optional_int(obj, "offset", f"{where}.message")
    if offset is None or offset < 0:
        raise InputError(f"{where}.message: offset 必须是 >= 0 的整数")
    if "payload" not in obj:
        raise InputError(f"{where}.message: 缺少 payload")
    event_type = _require_str(obj, "event_type", f"{where}.message")
    status = _require_str(obj, "status", f"{where}.message")
    occurred_at = _optional_int(obj, "occurred_at", f"{where}.message")
    if occurred_at is None:
        raise InputError(
            f"{where}.message: 缺少 occurred_at；判断事件先后顺序必须提供业务时间"
        )
    source_attempt = obj.get("source_attempt")
    if source_attempt is not None and not isinstance(source_attempt, str):
        raise InputError(f"{where}.message: source_attempt 必须是字符串或 null")
    return Message(
        message_id=message_id,
        business_key=business_key,
        partition=partition,
        offset=offset,
        payload=obj["payload"],
        event_type=event_type,
        status=status,
        occurred_at=occurred_at,
        source_attempt=source_attempt,
    )


def _parse_failure(obj: Any, where: str) -> Failure:
    if not isinstance(obj, dict):
        raise InputError(f"{where}: failure 必须是 JSON 对象")
    _unknown_keys(obj, FAILURE_KEYS, f"{where}.failure")
    delivery_count = obj.get("delivery_count")
    if isinstance(delivery_count, bool) or not isinstance(delivery_count, int) or delivery_count < 1:
        raise InputError(f"{where}.failure: delivery_count 必须是 >= 1 的整数")
    reason = _require_str(obj, "reason", f"{where}.failure")
    evidence = obj.get("evidence")
    if evidence is not None and not isinstance(evidence, str):
        raise InputError(f"{where}.failure: evidence 必须是字符串或 null")
    return Failure(delivery_count=delivery_count, reason=reason, evidence=evidence)


def load_records(path: str | Path) -> list[Record]:
    records: list[Record] = []
    for line_no, obj in _read_jsonl(path, what="死信"):
        where = f"{Path(path)} 第 {line_no} 行"
        _unknown_keys(obj, RECORD_KEYS, where)
        if "message" not in obj or "failure" not in obj:
            raise InputError(f"{where}: 记录必须同时包含 message 与 failure")
        records.append(
            Record(
                line_no=line_no,
                message=_parse_message(obj["message"], where),
                failure=_parse_failure(obj["failure"], where),
            )
        )
    if not records:
        raise InputError(f"死信文件没有任何记录: {path}", details={"path": str(path)})
    return records


def load_dispositions(path: str | Path) -> dict[str, Disposition]:
    out: dict[str, Disposition] = {}
    for line_no, obj in _read_jsonl(path, what="人工处置"):
        where = f"{Path(path)} 第 {line_no} 行"
        _unknown_keys(obj, DISPOSITION_KEYS, where)
        message_id = _require_str(obj, "message_id", where)
        # 处置按消息身份登记：同一身份只允许一条，避免"撤回"语义含糊
        if message_id in out:
            raise InputError(f"{where}: 消息 {message_id!r} 存在重复的人工处置记录")
        action = _require_str(obj, "action", where)
        if action not in DISPOSITION_ACTIONS:
            raise InputError(
                f"{where}: action 必须是 {sorted(DISPOSITION_ACTIONS)} 之一，实际为 {action!r}"
            )
        operator = _require_str(obj, "operator", where)
        note = obj.get("note")
        if note is not None and not isinstance(note, str):
            raise InputError(f"{where}: note 必须是字符串或 null")
        out[message_id] = Disposition(
            message_id=message_id,
            action=action,
            operator=operator,
            note=note,
        )
    return out


def load_policy(path: str | Path | None) -> Policy:
    if path is None:
        return Policy()
    try:
        obj = strict_json_loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise InputError(f"业务配置文件不存在: {path}")
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"无法读取业务配置文件 {path}: {exc}")
    except (ValueError, json.JSONDecodeError) as exc:
        raise InputError(f"业务配置不是合法 JSON {path}: {exc}")
    if not isinstance(obj, dict):
        raise InputError("业务配置必须是 JSON 对象")
    allowed = {"problem_statuses", "final_statuses", "same_offset_payload_rule"}
    _unknown_keys(obj, frozenset(allowed), "业务配置")
    policy = Policy()
    if "problem_statuses" in obj:
        policy = _with_statuses(policy, "problem_statuses", obj["problem_statuses"])
    if "final_statuses" in obj:
        policy = _with_statuses(policy, "final_statuses", obj["final_statuses"])
    rule = obj.get("same_offset_payload_rule", "error")
    if rule not in ("error", "prefer_earliest_line"):
        raise InputError("same_offset_payload_rule 只能是 'error' 或 'prefer_earliest_line'")
    return Policy(
        problem_statuses=policy.problem_statuses,
        final_statuses=policy.final_statuses,
        same_offset_payload_rule=rule,
    )


def _with_statuses(policy: Policy, key: str, value: Any) -> Policy:
    if not isinstance(value, list) or not value or not all(isinstance(v, str) and v for v in value):
        raise InputError(f"业务配置 {key} 必须是非空字符串数组")
    statuses = frozenset(value)
    if key == "problem_statuses":
        return Policy(problem_statuses=statuses, final_statuses=policy.final_statuses,
                      same_offset_payload_rule=policy.same_offset_payload_rule)
    return Policy(problem_statuses=policy.problem_statuses, final_statuses=statuses,
                  same_offset_payload_rule=policy.same_offset_payload_rule)


def iter_message_ids(records: Iterable[Record]) -> Iterable[str]:
    for record in records:
        yield record.message_id
