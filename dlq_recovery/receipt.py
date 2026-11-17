"""下游执行回执：格式定义、严格解析与身份绑定校验。

回执是下游（或操作员代下游）对**某一次交付尝试**中单个事件执行结果的离线
证据。每条回执必须同时绑定三件事，缺一即视为身份不明、整文件拒收：

1. ``attempt_id``：哪一次交付尝试（登记时生成，补投会生成新的尝试）；
2. ``package_digest``：该次尝试交付包的**内容身份**（登记时对包内容计算的
   sha256），业务键碰巧相同的另一个包无法顶替；
3. ``event_id`` + ``payload_sha256``：包内的具体事件版本，回执不能把结果
   挂到别的载荷上。

结果只有三种确定程度：

- ``success``      明确已成功执行（禁止再次补投）；
- ``not_executed`` 明确没有执行，可以再试；
- ``unknown``      无法确认是否执行（超时等）。**未知不是失败**：它不能被
  当成 ``not_executed`` 自动补投，只能被同次尝试后续的确定结果消解。

没有任何回执（``missing``）与同次尝试内成功/未执行并存（``conflict``）是
对账阶段派生的状态，不出现在回执文件里。
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .errors import InputError, ValidationError
from .models import canonical_json, sha256_text, strict_json_loads

RECEIPT_FORMAT = "dlq-recovery-receipt"
RECEIPT_FORMAT_VERSION = 1

RESULT_SUCCESS = "success"
RESULT_NOT_EXECUTED = "not_executed"
RESULT_UNKNOWN = "unknown"
RECEIPT_RESULTS = frozenset({RESULT_SUCCESS, RESULT_NOT_EXECUTED, RESULT_UNKNOWN})

RECEIPT_KEYS = frozenset(
    {
        "receipt_id",
        "attempt_id",
        "package_digest",
        "event_id",
        "payload_sha256",
        "result",
        "reported_at",
        "reported_by",
        "detail",
    }
)
RECEIPT_REQUIRED = (
    "attempt_id",
    "package_digest",
    "event_id",
    "payload_sha256",
    "result",
    "reported_at",
    "reported_by",
)
_HEX64 = set("0123456789abcdef")


@dataclass(frozen=True)
class Receipt:
    """一条解析通过的回执（保留原始 dict 用于证据哈希与归档）。"""

    raw: dict
    line_no: int
    attempt_id: str
    package_digest: str
    event_id: str
    payload_sha256: str
    result: str
    reported_at: str
    reported_by: str
    receipt_id: str | None
    detail: str | None

    @property
    def evidence_hash(self) -> str:
        return evidence_hash_of(self.raw)


def evidence_hash_of(raw: dict) -> str:
    """证据内容哈希：只对回执本身做规范哈希，不含导入来源等 Provenance。

    同一份证据无论被导入多少次、拆成几个文件，哈希都相同，据此做幂等收敛。
    """

    return sha256_text(canonical_json(raw))


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in _HEX64 for ch in value)


def _parse_one(obj: dict, *, line_no: int, where: str) -> Receipt:
    extra = sorted(set(obj) - RECEIPT_KEYS)
    if extra:
        raise InputError(f"{where}: 不认识的回执字段 {extra}")
    for key in RECEIPT_REQUIRED:
        if key not in obj:
            raise InputError(f"{where}: 缺少必填字段 {key!r}")
    for key in ("attempt_id", "package_digest", "event_id", "payload_sha256",
                "result", "reported_at", "reported_by"):
        value = obj[key]
        if not isinstance(value, str) or not value.strip():
            raise InputError(f"{where}: 字段 {key!r} 必须是非空字符串")
    receipt_id = obj.get("receipt_id")
    if receipt_id is not None and (not isinstance(receipt_id, str) or not receipt_id.strip()):
        raise InputError(f"{where}: receipt_id 必须是非空字符串或省略")
    detail = obj.get("detail")
    if detail is not None and not isinstance(detail, str):
        raise InputError(f"{where}: detail 必须是字符串或省略")
    result = obj["result"]
    if result not in RECEIPT_RESULTS:
        raise InputError(
            f"{where}: result 必须是 {sorted(RECEIPT_RESULTS)} 之一，实际为 {result!r}"
        )
    if not _is_hex64(obj["package_digest"]):
        raise InputError(f"{where}: package_digest 必须是 64 位十六进制 sha256")
    if not _is_hex64(obj["payload_sha256"]):
        raise InputError(f"{where}: payload_sha256 必须是 64 位十六进制 sha256")
    return Receipt(
        raw=obj,
        line_no=line_no,
        attempt_id=obj["attempt_id"],
        package_digest=obj["package_digest"],
        event_id=obj["event_id"],
        payload_sha256=obj["payload_sha256"],
        result=result,
        reported_at=obj["reported_at"],
        reported_by=obj["reported_by"],
        receipt_id=receipt_id,
        detail=detail,
    )


def load_receipt_file(path: str | Path) -> list[Receipt]:
    """严格解析回执 JSONL。

    任何一行格式非法都抛 :class:`InputError`；调用方必须在**全部行解析并通过
    身份绑定校验之后**才允许落盘，保证一份坏文件不会留下部分状态。
    """

    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise InputError(f"回执文件不存在: {p}", details={"path": str(p)})
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"无法读取回执文件 {p}: {exc}", details={"path": str(p)})

    receipts: list[Receipt] = []
    seen_attempt: str | None = None
    for line_no, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            continue
        where = f"回执文件 {p} 第 {line_no} 行"
        try:
            obj = strict_json_loads(line)
        except ValueError as exc:  # JSONDecodeError 是 ValueError 子类
            raise InputError(f"{where} 不是合法 JSON: {exc}",
                             details={"path": str(p), "line": line_no})
        if not isinstance(obj, dict):
            raise InputError(f"{where} 必须是 JSON 对象",
                             details={"path": str(p), "line": line_no})
        receipt = _parse_one(obj, line_no=line_no, where=where)
        # 一份回执文件只服务一次交付尝试：混装尝试会让分块/重试语义含糊。
        if seen_attempt is None:
            seen_attempt = receipt.attempt_id
        elif receipt.attempt_id != seen_attempt:
            raise InputError(
                f"{where}: 同一份回执文件出现多个 attempt_id（{seen_attempt!r} 与 "
                f"{receipt.attempt_id!r}）；每次交付的回执请分开导入",
                details={"path": str(p), "line": line_no},
            )
        receipts.append(receipt)
    if not receipts:
        raise InputError(f"回执文件没有任何记录: {p}", details={"path": str(p)})
    return receipts


def validate_bindings(receipts: list[Receipt], attempts: dict) -> None:
    """把回执绑定到对账存储中的已登记尝试。

    ``attempts`` 由对账存储提供：``attempt_id -> {package_digest, events:
    {event_id: payload_sha256}, deliverable}``。任何绑定错误都抛
    :class:`ValidationError`，且发生在落盘之前，因此整份文件原子拒收。
    """

    for receipt in receipts:
        where = f"回执第 {receipt.line_no} 行"
        attempt = attempts.get(receipt.attempt_id)
        if attempt is None:
            raise ValidationError(
                f"{where}: attempt_id {receipt.attempt_id!r} 未在对账存储登记，"
                "迟到回执必须仍然指向它原本所属的尝试",
                details={"attempt_id": receipt.attempt_id, "line": receipt.line_no},
            )
        if not attempt.get("deliverable", False):
            raise ValidationError(
                f"{where}: 尝试 {receipt.attempt_id!r} 未形成可交付包（已中止），"
                "不能导入回执",
                details={"attempt_id": receipt.attempt_id, "line": receipt.line_no},
            )
        if receipt.package_digest != attempt["package_digest"]:
            raise ValidationError(
                f"{where}: package_digest 与登记包不符（回执 "
                f"{receipt.package_digest[:12]}… / 登记 "
                f"{attempt['package_digest'][:12]}…）；拒绝业务键相同但内容不同的包顶替",
                details={
                    "attempt_id": receipt.attempt_id,
                    "line": receipt.line_no,
                    "expected": attempt["package_digest"],
                    "actual": receipt.package_digest,
                },
            )
        payload_sha = attempt["events"].get(receipt.event_id)
        if payload_sha is None:
            raise ValidationError(
                f"{where}: 事件 {receipt.event_id!r} 不在尝试 {receipt.attempt_id!r} 的包内",
                details={"attempt_id": receipt.attempt_id, "event_id": receipt.event_id,
                         "line": receipt.line_no},
            )
        if payload_sha != receipt.payload_sha256:
            raise ValidationError(
                f"{where}: payload_sha256 与登记的事件版本不符，回执不能绑定到别的载荷",
                details={"attempt_id": receipt.attempt_id, "event_id": receipt.event_id,
                         "expected": payload_sha, "actual": receipt.payload_sha256,
                         "line": receipt.line_no},
            )
