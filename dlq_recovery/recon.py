"""持久化对账存储：登记交付、收敛回执、驱动补投。

设计要点
========

1. **只追加的哈希链日志是唯一事实源**（``log/events.log``）。登记、回执导入、
   尝试签发/发布/中止/封存都写成带 ``prev_hash``/``entry_hash`` 的日志条目；
   ``state.json`` 只是可重建的物化快照，与日志尾哈希不符时自动按日志重放。
2. **回执证据按 (attempt, event, evidence_hash) 幂等去重**。重复文件、拆分
   文件、乱序导入都收敛到同一结果；每条证据的全部导入来源（provenance）都
   保留，可追溯。
3. **同次尝试成功与明确未执行并存 = 矛盾证据**，派生态为 ``conflict``，
   绝不按文件顺序覆盖，并永久阻断该事件的自动补投。
4. **未知/缺回执不是失败**：派生态 ``unknown``/``missing`` 只能被同次尝试的
   确定结果消解；在补投选批时它们是分区阻塞点，后面的事件不能越过。
5. **补投签发走可恢复发布协议**：先落 ``attempt_publishing`` 意图（事件已
   占用）→ 构建包 → 落 ``attempt_published``。重开存储时自动恢复：有完整包
   则追认已签发，否则中止意图释放事件，不会出现"没有可用包却永久占用"或
   "旧包可执行却能再次签发"。

整个模块只做本地文件 I/O，不含任何网络/队列依赖。
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import secrets
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from .approvals import utcnow
from .errors import IntegrityError, PolicyError, ValidationError, WorkflowError
from .models import canonical_json, sha256_text
from .package import COMPLETE_MARKER, verify_package
from .receipt import (
    RESULT_NOT_EXECUTED,
    RESULT_SUCCESS,
    load_receipt_file,
    validate_bindings,
)

STORE_FORMAT = "dlq-recovery-reconciliation-store"
STORE_FORMAT_VERSION = 1

LOG_DIR = "log"
RECEIPT_ARCHIVE_DIR = "log/receipts"
PACKAGES_DIR = "packages"
STATE_FILE = "state.json"
LOG_FILE = "log/events.log"
LOCK_FILE = ".lock"

# 派生态（不出现在回执文件中，由证据收敛得到）
EFFECTIVE_SUCCESS = "success"
EFFECTIVE_NOT_EXECUTED = "not_executed"
EFFECTIVE_UNKNOWN = "unknown"
EFFECTIVE_MISSING = "missing"
EFFECTIVE_CONFLICT = "conflict"
DEFINITE_EFFECTIVES = frozenset({EFFECTIVE_SUCCESS, EFFECTIVE_NOT_EXECUTED})
BLOCKING_EFFECTIVES = frozenset(
    {EFFECTIVE_UNKNOWN, EFFECTIVE_MISSING, EFFECTIVE_CONFLICT}
)

# 尝试生命周期
STATUS_DELIVERED = "delivered"      # 包已发布，等待/正在对账
STATUS_SEALED = "sealed"            # 操作员宣告该尝试对账结束
STATUS_ABORTED = "aborted"          # 发布失败被恢复，或人工中止（无可执行包）
OPEN_STATUSES = frozenset({STATUS_DELIVERED})

KIND_ORIGIN = "origin"
KIND_REPLAY = "replay"

ENTRY_TYPES = frozenset(
    {
        "package_registered",
        "receipts_imported",
        "attempt_publishing",
        "attempt_published",
        "attempt_aborted",
        "attempt_sealed",
    }
)


# ---------------------------------------------------------------------------
# 哈希链日志条目
# ---------------------------------------------------------------------------
def _entry_hash(payload: dict) -> str:
    return sha256_text(canonical_json(payload))


def make_log_entry(seq: int, prev_hash: str | None, entry_type: str, body: dict,
                   *, ts: str | None = None) -> dict:
    payload = {
        "seq": seq,
        "type": entry_type,
        "ts": ts or utcnow(),
        "prev_hash": prev_hash,
        "body": body,
    }
    payload["entry_hash"] = _entry_hash(payload)
    return payload


# ---------------------------------------------------------------------------
# 物化状态
# ---------------------------------------------------------------------------
@dataclass
class Observation:
    """一条去重后的回执证据，附带全部导入来源。"""

    evidence_hash: str
    attempt_id: str
    event_id: str
    result: str
    receipt: dict
    provenance: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "evidence_hash": self.evidence_hash,
            "attempt_id": self.attempt_id,
            "event_id": self.event_id,
            "result": self.result,
            "receipt": self.receipt,
            "provenance": list(self.provenance),
        }


@dataclass
class ReconciliationState:
    chains: dict = field(default_factory=dict)          # chain_id -> chain
    attempts: dict = field(default_factory=dict)        # attempt_id -> attempt
    # (attempt_id, event_id, evidence_hash) -> Observation
    observations: dict = field(default_factory=dict)
    import_seq: int = 0
    attempt_seq: int = 0
    last_seq: int = 0
    last_entry_hash: str | None = None
    recovered: list[dict] = field(default_factory=list)  # 本次加载时的恢复动作

    # -- 序列化 -----------------------------------------------------------
    def to_dict(self) -> dict:
        return {
            "format": STORE_FORMAT,
            "format_version": STORE_FORMAT_VERSION,
            "last_seq": self.last_seq,
            "last_entry_hash": self.last_entry_hash,
            "import_seq": self.import_seq,
            "attempt_seq": self.attempt_seq,
            "chains": self.chains,
            "attempts": self.attempts,
            "observations": [
                obs.to_dict()
                for obs in sorted(
                    self.observations.values(),
                    key=lambda o: (o.attempt_id, o.event_id, o.evidence_hash),
                )
            ],
        }

    @classmethod
    def from_dict(cls, doc: dict) -> "ReconciliationState":
        if doc.get("format") != STORE_FORMAT:
            raise IntegrityError(f"对账快照格式非法: {doc.get('format')!r}")
        state = cls()
        state.chains = doc.get("chains", {})
        state.attempts = doc.get("attempts", {})
        for raw in doc.get("observations", []):
            obs = Observation(
                evidence_hash=raw["evidence_hash"],
                attempt_id=raw["attempt_id"],
                event_id=raw["event_id"],
                result=raw["result"],
                receipt=raw["receipt"],
                provenance=list(raw.get("provenance", [])),
            )
            state.observations[(obs.attempt_id, obs.event_id, obs.evidence_hash)] = obs
        state.import_seq = doc.get("import_seq", 0)
        state.attempt_seq = doc.get("attempt_seq", 0)
        state.last_seq = doc.get("last_seq", 0)
        state.last_entry_hash = doc.get("last_entry_hash")
        return state

    # -- 查询 -------------------------------------------------------------
    def chain_for_attempt(self, attempt_id: str) -> dict | None:
        attempt = self.attempts.get(attempt_id)
        if attempt is None:
            return None
        return self.chains.get(attempt["chain_id"])

    def chain_attempts(self, chain_id: str) -> list[dict]:
        return sorted(
            (a for a in self.attempts.values() if a["chain_id"] == chain_id),
            key=lambda a: a["seq_in_chain"],
        )

    def effective_for(self, attempt_id: str, event_id: str) -> str:
        """某尝试内某事件的收敛派生态。"""

        results = {
            obs.result
            for (aid, eid, _hash), obs in self.observations.items()
            if aid == attempt_id and eid == event_id
        }
        if not results:
            return EFFECTIVE_MISSING
        if RESULT_SUCCESS in results and RESULT_NOT_EXECUTED in results:
            return EFFECTIVE_CONFLICT
        if RESULT_SUCCESS in results:
            return EFFECTIVE_SUCCESS
        if RESULT_NOT_EXECUTED in results:
            return EFFECTIVE_NOT_EXECUTED
        return EFFECTIVE_UNKNOWN

    def evidence_for(self, attempt_id: str, event_id: str) -> list[Observation]:
        return sorted(
            (
                obs
                for (aid, eid, _h), obs in self.observations.items()
                if aid == attempt_id and eid == event_id
            ),
            key=lambda o: o.evidence_hash,
        )

    def chain_event_view(self, chain_id: str, event_id: str) -> dict:
        """跨尝试汇总单个事件的完整对账视图。"""

        per_attempt: dict[str, str] = {}
        conflict_attempts: list[str] = []
        success_attempts: list[str] = []
        not_executed_attempts: list[str] = []
        unknown_attempts: list[str] = []
        for attempt in self.chain_attempts(chain_id):
            if event_id not in attempt["events"]:
                continue
            effective = self.effective_for(attempt["attempt_id"], event_id)
            per_attempt[attempt["attempt_id"]] = effective
            if effective == EFFECTIVE_CONFLICT:
                conflict_attempts.append(attempt["attempt_id"])
            elif effective == EFFECTIVE_SUCCESS:
                success_attempts.append(attempt["attempt_id"])
            elif effective == EFFECTIVE_NOT_EXECUTED:
                not_executed_attempts.append(attempt["attempt_id"])
            elif effective in (EFFECTIVE_UNKNOWN, EFFECTIVE_MISSING):
                unknown_attempts.append(attempt["attempt_id"])
        succeeded = bool(success_attempts)
        # 已签发但未完成对账的补投尝试占用其中全部事件：它们不能进入下一个
        # 补投包（避免同一失败事件出现在两个同时待执行的包里）。
        occupied_by_open_replay = any(
            attempt["status"] in OPEN_STATUSES
            and attempt["kind"] == KIND_REPLAY
            and event_id in attempt["events"]
            for attempt in self.chain_attempts(chain_id)
        )
        # "在途"还包括该事件本身仍无确定结论（未知/缺回执）的开放尝试；
        # 已有明确未执行结论的事件不会因为原包尝试整体未封存而被永久挂起——
        # 否则一次尝试里只要有一个事件缺回执，所有明确失败的事件都无法补投。
        unresolved_in_open = any(
            attempt["status"] in OPEN_STATUSES
            and event_id in attempt["events"]
            and self.effective_for(attempt["attempt_id"], event_id)
            in (EFFECTIVE_UNKNOWN, EFFECTIVE_MISSING)
            for attempt in self.chain_attempts(chain_id)
        )
        if succeeded:
            chain_status = "succeeded"
        elif conflict_attempts:
            chain_status = "conflict"
        elif occupied_by_open_replay or unresolved_in_open:
            chain_status = "in_flight"
        elif not_executed_attempts:
            # 最近一次明确未执行的尝试作为补投依据
            chain_status = "retryable"
        else:
            chain_status = "pending"
        latest_failure = not_executed_attempts[-1] if not_executed_attempts else None
        return {
            "event_id": event_id,
            "chain_status": chain_status,
            "per_attempt": per_attempt,
            "succeeded": succeeded,
            "success_attempts": success_attempts,
            "conflict_attempts": conflict_attempts,
            "not_executed_attempts": not_executed_attempts,
            "unknown_attempts": unknown_attempts,
            "latest_failure_attempt": latest_failure,
            "in_open_attempt": occupied_by_open_replay or unresolved_in_open,
        }

    def open_attempt(self, chain_id: str) -> dict | None:
        for attempt in self.chain_attempts(chain_id):
            if attempt["status"] in OPEN_STATUSES:
                return attempt
        return None


def _fold_entries(entries: list[dict]) -> ReconciliationState:
    """从哈希链日志重放物化状态。日志是唯一事实源。"""

    state = ReconciliationState()
    prev_hash: str | None = None
    for entry in entries:
        if entry.get("prev_hash") != prev_hash:
            raise IntegrityError(
                "对账日志哈希链断裂（prev_hash 不符），拒绝在不可信状态上继续操作",
                details={"seq": entry.get("seq")},
            )
        expected = entry.get("entry_hash")
        payload = {k: v for k, v in entry.items() if k != "entry_hash"}
        if expected != _entry_hash(payload):
            raise IntegrityError(
                "对账日志条目哈希校验失败，日志可能被篡改",
                details={"seq": entry.get("seq")},
            )
        _apply_entry(state, entry)
        prev_hash = expected
        state.last_seq = entry["seq"]
        state.last_entry_hash = expected
    return state


def _apply_entry(state: ReconciliationState, entry: dict) -> None:
    body = entry["body"]
    etype = entry["type"]
    if etype == "package_registered":
        _apply_registration(state, body)
    elif etype == "receipts_imported":
        _apply_receipts(state, body, ts=entry["ts"])
    elif etype == "attempt_publishing":
        _apply_publishing(state, body)
    elif etype == "attempt_published":
        attempt = state.attempts[body["attempt_id"]]
        attempt["status"] = STATUS_DELIVERED
        attempt["published_at"] = body["published_at"]
        attempt["recovered_publish"] = bool(body.get("recovered"))
        # 发布落定后清除待发布标记；恢复逻辑只处理残留的发布意图。
        attempt.pop("pending_publish", None)
        if body.get("package_digest"):
            attempt["package_digest"] = body["package_digest"]
    elif etype == "attempt_aborted":
        attempt = state.attempts[body["attempt_id"]]
        attempt["status"] = STATUS_ABORTED
        attempt["abort"] = {
            "reason": body["reason"],
            "by": body.get("by"),
            "at": body["at"],
        }
    elif etype == "attempt_sealed":
        attempt = state.attempts[body["attempt_id"]]
        attempt["status"] = STATUS_SEALED
        attempt["seal"] = {"reason": body.get("reason"), "by": body["by"], "at": body["at"]}
    else:  # pragma: no cover - ENTRY_TYPES 已在写入侧约束
        raise IntegrityError(f"未知对账日志条目类型: {etype!r}")


def _apply_registration(state: ReconciliationState, body: dict) -> None:
    chain_id = body["chain_id"]
    if chain_id in state.chains:
        raise IntegrityError(
            f"包内容身份 {body['package_digest'][:12]}… 已登记，禁止重复登记同一包",
            details={"chain_id": chain_id},
        )
    attempt_id = body["origin_attempt_id"]
    state.attempt_seq = max(state.attempt_seq, body["attempt_number"])
    state.chains[chain_id] = {
        "chain_id": chain_id,
        "origin_attempt_id": attempt_id,
        "origin_path": body["origin_path"],
        "package_digest": body["package_digest"],
        "plan_digest": body["plan_digest"],
        "registered_at": body["registered_at"],
        "registered_by": body["registered_by"],
        "note": body.get("note"),
        "events": body["events"],
    }
    state.attempts[attempt_id] = {
        "attempt_id": attempt_id,
        "attempt_number": body["attempt_number"],
        "chain_id": chain_id,
        "kind": KIND_ORIGIN,
        "seq_in_chain": 1,
        "prev_attempt_id": None,
        "package_digest": body["package_digest"],
        "package_path": body["package_path"],
        "events": {e["event_id"]: e["payload_sha256"] for e in body["events"]},
        "event_order": [
            {
                "event_id": e["event_id"],
                "partition": e["partition"],
                "offset": e["offset"],
                "partition_sequence": e["partition_sequence"],
            }
            for e in body["events"]
        ],
        "blockers": [],
        "withheld": [],
        "status": STATUS_DELIVERED,
        "created_at": body["registered_at"],
        "published_at": body["registered_at"],
    }


def _apply_receipts(state: ReconciliationState, body: dict, *, ts: str) -> None:
    state.import_seq = max(state.import_seq, body["import_seq"])
    for item in body["observations"]:
        key = (item["attempt_id"], item["event_id"], item["evidence_hash"])
        provenance = {
            "import_seq": body["import_seq"],
            "source_file": body["source_file"],
            "source_sha256": body["source_sha256"],
            "line_no": item["line_no"],
            "imported_by": body["imported_by"],
            "imported_at": ts,
        }
        existing = state.observations.get(key)
        if existing is None:
            state.observations[key] = Observation(
                evidence_hash=item["evidence_hash"],
                attempt_id=item["attempt_id"],
                event_id=item["event_id"],
                result=item["result"],
                receipt=item["receipt"],
                provenance=[provenance],
            )
        else:
            # 幂等：同一证据重复/分块/乱序导入，只追加来源，不改变收敛结果
            existing.provenance.append(provenance)


def _apply_publishing(state: ReconciliationState, body: dict) -> None:
    state.attempt_seq = max(state.attempt_seq, body["attempt_number"])
    state.attempts[body["attempt_id"]] = {
        "attempt_id": body["attempt_id"],
        "attempt_number": body["attempt_number"],
        "chain_id": body["chain_id"],
        "kind": KIND_REPLAY,
        "seq_in_chain": body["seq_in_chain"],
        "prev_attempt_id": body["prev_attempt_id"],
        "package_digest": body["package_digest"],
        "package_path": body["package_path"],
        "events": {e["event_id"]: e["payload_sha256"] for e in body["events"]},
        "event_order": [
            {
                "event_id": e["event_id"],
                "partition": e["partition"],
                "offset": e["offset"],
                "partition_sequence": e["partition_sequence"],
                "basis_attempt_id": e["basis_attempt_id"],
            }
            for e in body["events"]
        ],
        "blockers": body.get("blockers", []),
        "withheld": body.get("withheld", []),
        "status": STATUS_DELIVERED,  # 恢复前先视作占用；恢复逻辑可能改写成 aborted
        "created_at": body["created_at"],
        "published_at": None,
        "pending_publish": True,
        "created_by": body.get("created_by"),
    }


# ---------------------------------------------------------------------------
# 选批：单分区顺序 + 阻塞点
# ---------------------------------------------------------------------------
def compute_replay_candidates(state: ReconciliationState, chain_id: str) -> dict:
    """计算下一次补投尝试允许包含的事件。

    每个分区按原包偏移从前向后检查：

    - 已成功：跳过（不阻塞后续）；
    - 最近一次结论为明确未执行且未成功：可加入候选（若尚未遇到阻塞点）；
    - 未知/缺回执/矛盾/尚在未完成尝试中：成为本分区阻塞点，其后事件全部截留；
    - 其他分区不受牵连。
    """

    chain = state.chains[chain_id]
    origin_events = sorted(
        chain["events"], key=lambda e: (e["partition"], e["offset"], e["event_id"])
    )
    partitions: dict[str, list[dict]] = {}
    for event in origin_events:
        partitions.setdefault(event["partition"], []).append(event)

    included: list[dict] = []
    blockers: list[dict] = []
    withheld: list[dict] = []
    for partition in sorted(partitions):
        blocked_by: dict | None = None
        for event in partitions[partition]:
            view = state.chain_event_view(chain_id, event["event_id"])
            if view["succeeded"]:
                continue
            if view["chain_status"] == "retryable":
                if blocked_by is None:
                    included.append(
                        {
                            "event_id": event["event_id"],
                            "partition": event["partition"],
                            "offset": event["offset"],
                            "partition_sequence": event["partition_sequence"],
                            "payload_sha256": event["payload_sha256"],
                            "basis_attempt_id": view["latest_failure_attempt"],
                        }
                    )
                else:
                    withheld.append(
                        {
                            "event_id": event["event_id"],
                            "partition": event["partition"],
                            "offset": event["offset"],
                            "reason": "behind_partition_blocker",
                            "blocker_event_id": blocked_by["event_id"],
                        }
                    )
                continue
            # 阻塞点：未知 / 缺回执 / 矛盾 / 在途
            if blocked_by is None:
                reason = {
                    "conflict": "conflicting_evidence",
                    "pending": "unknown_or_missing_receipt",
                    "in_flight": "open_attempt",
                }.get(view["chain_status"], view["chain_status"])
                blocked_by = {
                    "event_id": event["event_id"],
                    "partition": event["partition"],
                    "offset": event["offset"],
                    "reason": reason,
                    "chain_status": view["chain_status"],
                }
                blockers.append(blocked_by)
            else:
                # 阻塞点本身计入 blockers；只有它后面的事件计入 withheld
                withheld.append(
                    {
                        "event_id": event["event_id"],
                        "partition": event["partition"],
                        "offset": event["offset"],
                        "reason": "behind_partition_blocker",
                        "blocker_event_id": blocked_by["event_id"],
                    }
                )
    return {"included": included, "blockers": blockers, "withheld": withheld}


def detect_anomalies(state: ReconciliationState, chain_id: str) -> list[dict]:
    """跨尝试异常：成功与后续登记尝试矛盾、成功/未执行跨尝试冲突。

    异常只展示，绝不抹掉既有交付历史。
    """

    anomalies: list[dict] = []
    chain = state.chains[chain_id]
    attempts = state.chain_attempts(chain_id)
    attempt_order = {a["attempt_id"]: a["seq_in_chain"] for a in attempts}
    for event in sorted(chain["events"], key=lambda e: (e["partition"], e["offset"])):
        view = state.chain_event_view(chain_id, event["event_id"])
        if view["success_attempts"] and view["not_executed_attempts"]:
            anomalies.append(
                {
                    "kind": "cross_attempt_contradiction",
                    "event_id": event["event_id"],
                    "partition": event["partition"],
                    "offset": event["offset"],
                    "success_attempts": view["success_attempts"],
                    "not_executed_attempts": view["not_executed_attempts"],
                    "detail": "同一事件在不同尝试中分别被报告成功与明确未执行，历史全部保留，需人工核查",
                }
            )
        # 只要某次尝试出现过成功证据（即便同次还伴随矛盾证据），而该事件又
        # 进入了更晚的登记尝试，就展示迟到成功异常，且禁止再次补投。
        success_like = set(view["success_attempts"]) | set(view["conflict_attempts"])
        for success_id in sorted(success_like):
            for attempt in attempts:
                if (
                    attempt["seq_in_chain"] > attempt_order[success_id]
                    and event["event_id"] in attempt["events"]
                ):
                    anomalies.append(
                        {
                            "kind": "late_success_after_reissue",
                            "event_id": event["event_id"],
                            "partition": event["partition"],
                            "offset": event["offset"],
                            "success_attempt_id": success_id,
                            "reissued_attempt_id": attempt["attempt_id"],
                            "detail": "事件已出现成功（或矛盾）证据，但证据到达前它已进入后续补投尝试；禁止再次补投并保留异常",
                        }
                    )
        for conflict_id in view["conflict_attempts"]:
            anomalies.append(
                {
                    "kind": "conflicting_evidence",
                    "event_id": event["event_id"],
                    "partition": event["partition"],
                    "offset": event["offset"],
                    "attempt_id": conflict_id,
                    "detail": "同次尝试同时存在成功与明确未执行证据，已阻断该事件自动补投",
                }
            )
    # 去重并稳定排序
    unique: dict[tuple, dict] = {}
    for anomaly in anomalies:
        key = tuple(sorted(anomaly.items()))
        unique[key] = anomaly
    return sorted(unique.values(), key=lambda a: (a["kind"], a["partition"], a["offset"]))


# ---------------------------------------------------------------------------
# 存储
# ---------------------------------------------------------------------------
class ReconciliationStore:
    """对账存储句柄。所有变更在同一把文件锁内完成。"""

    def __init__(self, path: str | Path):
        self.root = Path(path)
        self.log_path = self.root / LOG_FILE
        self.state_path = self.root / STATE_FILE
        self.lock_path = self.root / LOCK_FILE
        self.receipt_archive = self.root / RECEIPT_ARCHIVE_DIR
        self.packages_dir = self.root / PACKAGES_DIR

    # -- 基础设施 ---------------------------------------------------------
    @contextlib.contextmanager
    def _locked(self, exclusive: bool = True):
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / LOG_DIR).mkdir(parents=True, exist_ok=True)
        with open(self.lock_path, "a+", encoding="utf-8") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _read_log_entries(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        entries = []
        for line_no, line in enumerate(self.log_path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                entries.append(json.loads(line))
            except ValueError as exc:
                raise IntegrityError(f"对账日志第 {line_no} 行不是合法 JSON: {exc}")
        return entries

    def _append_entry(self, entry_type: str, body: dict, *, ts: str | None = None) -> dict:
        entries = self._read_log_entries()
        seq = (entries[-1]["seq"] + 1) if entries else 1
        prev_hash = entries[-1]["entry_hash"] if entries else None
        entry = make_log_entry(seq, prev_hash, entry_type, body, ts=ts)
        with open(self.log_path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    def _truncate_log_to(self, seq: int) -> None:
        """把日志截断回指定 seq（用于同事务内归档失败后的回滚）。

        只在持有排他锁、且被截断条目是本进程刚追加的情况下调用；截断后
        哈希链尾自然指回上一条，无需重写历史。
        """

        entries = self._read_log_entries()
        kept = [json.dumps(e, ensure_ascii=False, sort_keys=True) for e in entries if e["seq"] <= seq]
        text = ("\n".join(kept) + "\n") if kept else ""
        tmp = self.log_path.with_name(
            f".{self.log_path.name}.trunc-{os.getpid()}-{secrets.token_hex(4)}"
        )
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.log_path)

    def _write_snapshot(self, state: ReconciliationState) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.state_path.with_name(
            f".{STATE_FILE}.tmp-{os.getpid()}-{secrets.token_hex(4)}"
        )
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps(state.to_dict(), ensure_ascii=False, indent=2, sort_keys=True))
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self.state_path)

    def _fold(self) -> ReconciliationState:
        entries = self._read_log_entries()
        state = _fold_entries(entries)
        # 快照只是缓存：与日志尾不一致时以日志为准重放，不阻塞操作员。
        if self.state_path.exists():
            try:
                snapshot = ReconciliationState.from_dict(
                    json.loads(self.state_path.read_text(encoding="utf-8"))
                )
                if (snapshot.last_seq, snapshot.last_entry_hash) != (
                    state.last_seq,
                    state.last_entry_hash,
                ):
                    state.recovered.append(
                        {"kind": "snapshot_rebuilt", "detail": "物化快照落后于日志，已按日志重放"}
                    )
            except (ValueError, KeyError, IntegrityError):
                state.recovered.append(
                    {"kind": "snapshot_rebuilt", "detail": "物化快照不可读，已按日志重放"}
                )
        return state

    def load(self) -> ReconciliationState:
        """只读加载（共享锁），不做发布恢复。"""

        with self._locked(exclusive=False):
            return self._fold()

    def _load_and_recover(self) -> ReconciliationState:
        """排他加载，并把上次进程残留的发布意图恢复到确定状态。"""

        state = self._fold()
        for attempt in list(state.attempts.values()):
            if not attempt.get("pending_publish"):
                continue
            package_dir = self.root / attempt["package_path"]
            complete = package_dir.is_dir() and (package_dir / COMPLETE_MARKER).exists()
            if complete and self._package_digest_matches(package_dir, attempt["package_digest"]):
                # 包已完整落盘：追认签发，事件保持占用，绝不允许再签一次。
                entry = self._append_entry(
                    "attempt_published",
                    {
                        "attempt_id": attempt["attempt_id"],
                        "package_path": attempt["package_path"],
                        "package_digest": attempt["package_digest"],
                        "published_at": utcnow(),
                        "recovered": True,
                    },
                )
                _apply_entry(state, entry)
                state.recovered.append(
                    {
                        "kind": "publish_confirmed",
                        "attempt_id": attempt["attempt_id"],
                        "package_path": attempt["package_path"],
                    }
                )
            else:
                # 没有可用包：中止意图、释放事件，允许重新签发。
                shutil.rmtree(package_dir, ignore_errors=True)
                entry = self._append_entry(
                    "attempt_aborted",
                    {
                        "attempt_id": attempt["attempt_id"],
                        "reason": "publish_interrupted_recovered",
                        "by": "system-recovery",
                        "at": utcnow(),
                    },
                )
                _apply_entry(state, entry)
                state.recovered.append(
                    {"kind": "publish_aborted", "attempt_id": attempt["attempt_id"]}
                )
        if state.recovered:
            self._write_snapshot(state)
        return state

    @staticmethod
    def _package_digest_matches(package_dir: Path, expected_digest: str) -> bool:
        manifest_path = package_dir / "manifest.json"
        if not manifest_path.exists():
            return False
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except ValueError:
            return False
        return manifest.get("package_digest") == expected_digest

    # -- 登记 -------------------------------------------------------------
    def register_package(self, package_dir: str | Path, *, by: str, note: str | None = None) -> dict:
        from .replay import compute_package_digest  # 避免循环导入

        with self._locked():
            state = self._load_and_recover()
            root = Path(package_dir)
            report = verify_package(root)  # 先过原有完整性校验，失败直接拒绝
            manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
            package_digest = compute_package_digest(manifest)
            chain_id = "chain-" + package_digest[:16]
            if chain_id in state.chains:
                raise WorkflowError(
                    "该包内容身份已登记；同一交付包不能重复登记",
                    details={"chain_id": chain_id,
                             "origin_attempt_id": state.chains[chain_id]["origin_attempt_id"]},
                )
            events = self._snapshot_origin_events(root)
            state.attempt_seq += 1
            attempt_number = state.attempt_seq
            attempt_id = f"attempt-{attempt_number:04d}"
            package_path = f"{PACKAGES_DIR}/{chain_id}/origin"
            stored = self.root / package_path
            if stored.exists():
                raise IntegrityError(f"登记目标已存在且与日志不一致: {stored}")
            shutil.copytree(root, stored)
            body = {
                "chain_id": chain_id,
                "origin_attempt_id": attempt_id,
                "attempt_number": attempt_number,
                "origin_path": str(root.resolve()),
                "package_path": package_path,
                "package_digest": package_digest,
                "plan_digest": manifest["plan_digest"],
                "registered_by": by,
                "registered_at": utcnow(),
                "note": note,
                "events": events,
                "verify_report_summary": {
                    "approved_events": report.get("approved_events"),
                    "partitions": report.get("partitions"),
                },
            }
            try:
                entry = self._append_entry("package_registered", body)
            except BaseException:
                # 日志落盘失败：清理刚复制的包，避免留下无登记记录的孤儿目录
                shutil.rmtree(stored, ignore_errors=True)
                raise
            _apply_entry(state, entry)
            self._write_snapshot(state)
            return {
                "ok": True,
                "chain_id": chain_id,
                "attempt_id": attempt_id,
                "package_digest": package_digest,
                "plan_digest": manifest["plan_digest"],
                "events": len(events),
                "stored_package": str(stored),
            }

    @staticmethod
    def _snapshot_origin_events(root: Path) -> list[dict]:
        """从已校验包的分区文件提取不可变事件快照（含完整重投记录）。"""

        events: list[dict] = []
        partition_files = sorted((root / "partitions").glob("*.ndjson"))
        for pf in partition_files:
            for line_no, line in enumerate(pf.read_text(encoding="utf-8").splitlines(), 1):
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("record_type") != "replay":
                    raise IntegrityError(f"{pf}:{line_no} 不是 replay 记录，拒绝登记")
                events.append(
                    {
                        "event_id": row["event_id"],
                        "business_key": row["business_key"],
                        "partition": row["partition"],
                        "offset": row["offset"],
                        "partition_sequence": row["partition_sequence"],
                        "payload_sha256": row["payload_sha256"],
                        "replay_record": row,
                    }
                )
        if not events:
            raise IntegrityError("交付包内没有任何 replay 事件，无法登记对账")
        events.sort(key=lambda e: (e["partition"], e["offset"], e["event_id"]))
        return events

    # -- 回执导入 ---------------------------------------------------------
    def import_receipts(self, receipt_file: str | Path, *, by: str) -> dict:
        path = Path(receipt_file)
        with self._locked():
            state = self._load_and_recover()
            # 1) 先完整解析（任何一行坏 → 整体拒绝，不写任何状态）
            receipts = load_receipt_file(path)
            attempts_view = {
                aid: {
                    "package_digest": attempt["package_digest"],
                    "events": dict(attempt["events"]),
                    "deliverable": attempt["status"] != STATUS_ABORTED,
                }
                for aid, attempt in state.attempts.items()
            }
            # 2) 身份绑定全部通过后才允许落盘
            validate_bindings(receipts, attempts_view)

            source_bytes = path.read_bytes()
            source_sha = sha256_text(source_bytes.decode("utf-8"))
            state.import_seq += 1
            import_seq = state.import_seq
            self.receipt_archive.mkdir(parents=True, exist_ok=True)
            safe_name = path.name.replace("/", "_")
            archive = self.receipt_archive / f"{import_seq:04d}-{safe_name}"

            observations = []
            new_hashes: set[tuple] = set()
            duplicate = 0
            for receipt in receipts:
                key = (receipt.attempt_id, receipt.event_id, receipt.evidence_hash)
                if key in state.observations:
                    duplicate += 1
                else:
                    new_hashes.add(key)
                observations.append(
                    {
                        "evidence_hash": receipt.evidence_hash,
                        "attempt_id": receipt.attempt_id,
                        "event_id": receipt.event_id,
                        "result": receipt.result,
                        "line_no": receipt.line_no,
                        "receipt": receipt.raw,
                    }
                )
            before = {
                (aid, eid): state.effective_for(aid, eid)
                for (aid, eid, _h) in new_hashes
            }
            body = {
                "import_seq": import_seq,
                "source_file": str(path.resolve()),
                "source_name": path.name,
                "source_sha256": source_sha,
                "archive_path": str(archive.relative_to(self.root)),
                "imported_by": by,
                "observations": observations,
            }
            # 日志先落盘（事实源），随后才写归档文件；归档失败则回滚日志条目，
            # 保证不会出现"有归档无对账记录"或反之的部分状态。
            entry = self._append_entry("receipts_imported", body)
            try:
                tmp_archive = archive.with_name(
                    f".{archive.name}.tmp-{secrets.token_hex(4)}"
                )
                tmp_archive.write_bytes(source_bytes)
                os.replace(tmp_archive, archive)
            except BaseException:
                # 截断回刚追加的条目：哈希链重新指回上一条，状态保持一致
                self._truncate_log_to(entry["seq"] - 1)
                raise
            _apply_entry(state, entry)
            self._write_snapshot(state)

            resolutions = []
            for (aid, eid), old_effective in sorted(before.items()):
                new_effective = state.effective_for(aid, eid)
                if new_effective != old_effective:
                    resolutions.append(
                        {"attempt_id": aid, "event_id": eid,
                         "from": old_effective, "to": new_effective}
                    )
            return {
                "ok": True,
                "import_seq": import_seq,
                "attempt_id": receipts[0].attempt_id,
                "received": len(receipts),
                "new_evidence": len(receipts) - duplicate,
                "duplicate_evidence": duplicate,
                "resolutions": resolutions,
                "archived_to": str(archive),
            }

    # -- 对账预览（只读，不占用事件）--------------------------------------
    def reconcile_view(self, chain_id: str | None = None) -> dict:
        with self._locked(exclusive=False):
            state = self._fold()
            chain_ids = [chain_id] if chain_id else sorted(state.chains)
            # 只读视图不触发发布恢复，也不报告快照重建等写路径动作
            return {
                "store": str(self.root),
                "chains": [self._chain_view(state, cid) for cid in chain_ids],
            }

    def _chain_view(self, state: ReconciliationState, chain_id: str) -> dict:
        if chain_id not in state.chains:
            raise ValidationError(f"对账存储中没有链 {chain_id!r}")
        chain = state.chains[chain_id]
        attempts = state.chain_attempts(chain_id)
        # 只有未完成的**补投**尝试会阻止下一次签发；原包尝试在回执收集期保持
        # delivered 属于正常状态，不作为告警展示。
        open_replay = next(
            (a for a in attempts if a["status"] in OPEN_STATUSES and a["kind"] == KIND_REPLAY),
            None,
        )
        candidates = compute_replay_candidates(state, chain_id)
        events_view = []
        for event in sorted(chain["events"], key=lambda e: (e["partition"], e["offset"])):
            view = state.chain_event_view(chain_id, event["event_id"])
            evidence = []
            for attempt in attempts:
                if event["event_id"] not in attempt["events"]:
                    continue
                for obs in state.evidence_for(attempt["attempt_id"], event["event_id"]):
                    evidence.append(
                        {
                            "attempt_id": attempt["attempt_id"],
                            "result": obs.result,
                            "evidence_hash": obs.evidence_hash,
                            "reported_by": obs.receipt["reported_by"],
                            "reported_at": obs.receipt["reported_at"],
                            "sources": len(obs.provenance),
                            "detail": obs.receipt.get("detail"),
                        }
                    )
            events_view.append(
                {
                    "event_id": event["event_id"],
                    "business_key": event["business_key"],
                    "partition": event["partition"],
                    "offset": event["offset"],
                    "payload_sha256": event["payload_sha256"],
                    "chain_status": view["chain_status"],
                    "per_attempt": view["per_attempt"],
                    "latest_failure_attempt": view["latest_failure_attempt"],
                    "evidence": evidence,
                }
            )
        return {
            "chain_id": chain_id,
            "origin_attempt_id": chain["origin_attempt_id"],
            "package_digest": chain["package_digest"],
            "plan_digest": chain["plan_digest"],
            "registered_at": chain["registered_at"],
            "open_attempt_id": open_replay["attempt_id"] if open_replay else None,
            "attempts": [
                {
                    "attempt_id": a["attempt_id"],
                    "kind": a["kind"],
                    "seq_in_chain": a["seq_in_chain"],
                    "prev_attempt_id": a["prev_attempt_id"],
                    "status": a["status"],
                    "package_digest": a["package_digest"],
                    "package_path": a["package_path"],
                    "created_at": a["created_at"],
                    "published_at": a.get("published_at"),
                    "result_counts": self._attempt_counts(state, a),
                }
                for a in attempts
            ],
            "events": events_view,
            "next_replay_preview": candidates,
            "anomalies": detect_anomalies(state, chain_id),
        }

    @staticmethod
    def _attempt_counts(state: ReconciliationState, attempt: dict) -> dict:
        counts = {EFFECTIVE_SUCCESS: 0, EFFECTIVE_NOT_EXECUTED: 0, EFFECTIVE_UNKNOWN: 0,
                  EFFECTIVE_MISSING: 0, EFFECTIVE_CONFLICT: 0}
        for event_id in attempt["events"]:
            counts[state.effective_for(attempt["attempt_id"], event_id)] += 1
        return counts

    def resolve_chain_id(self, state: ReconciliationState, chain_id: str | None) -> str:
        if chain_id:
            if chain_id not in state.chains:
                raise ValidationError(f"对账存储中没有链 {chain_id!r}")
            return chain_id
        if len(state.chains) == 1:
            return next(iter(state.chains))
        if not state.chains:
            raise WorkflowError("对账存储尚未登记任何交付包")
        raise ValidationError(
            f"存储中有 {len(state.chains)} 条交付链，请用 --chain 指定",
            details={"chains": sorted(state.chains)},
        )

    # -- 签发补投（可恢复发布协议）----------------------------------------
    def issue_replay(self, *, chain_id: str | None, by: str) -> dict:
        from .replay import build_replay_package, plan_replay_manifest

        with self._locked():
            state = self._load_and_recover()
            chain_id = self.resolve_chain_id(state, chain_id)
            open_replay = next(
                (
                    a
                    for a in state.chain_attempts(chain_id)
                    if a["status"] in OPEN_STATUSES and a["kind"] == KIND_REPLAY
                ),
                None,
            )
            if open_replay is not None:
                # 已发出的补投尝试未完成对账前禁止再次签发，避免同一失败事件
                # 同时出现在两个待执行补投包里。原包尝试（origin）在回执收集
                # 期间保持 delivered，其未决事件由分区阻塞点逐事件保护。
                raise WorkflowError(
                    f"补投尝试 {open_replay['attempt_id']} 尚未完成对账（状态 "
                    f"{open_replay['status']}），不能重复签发；请先导入回执或封存",
                    details={"open_attempt_id": open_replay["attempt_id"]},
                )
            candidates = compute_replay_candidates(state, chain_id)
            if not candidates["included"]:
                raise PolicyError(
                    "没有可补投事件：成功事件跳过，其余被未知/缺回执/矛盾阻塞或已在阻塞点之后",
                    details={"blockers": candidates["blockers"], "withheld": candidates["withheld"]},
                )
            chain = state.chains[chain_id]
            seq_in_chain = len(state.chain_attempts(chain_id)) + 1
            prev_attempt = state.chain_attempts(chain_id)[-1]
            state.attempt_seq += 1
            attempt_number = state.attempt_seq
            attempt_id = f"attempt-{attempt_number:04d}"
            package_path = f"{PACKAGES_DIR}/{chain_id}/attempts/{attempt_id}/package"
            package_dir = self.root / package_path

            # 先在内存中确定包内容与摘要：意图里携带确定性 package_digest，
            # 崩溃恢复时可用它确认落盘包是不是这次签发的内容。
            manifest, _files = plan_replay_manifest(
                state=state,
                chain=chain,
                attempt_id=attempt_id,
                prev_attempt_id=prev_attempt["attempt_id"],
                included=candidates["included"],
                blockers=candidates["blockers"],
                withheld=candidates["withheld"],
                created_by=by,
            )
            package_digest = manifest["package_digest"]

            # 阶段 1：先持久化发布意图——此刻事件已被占用。
            publishing_body = {
                "attempt_id": attempt_id,
                "attempt_number": attempt_number,
                "chain_id": chain_id,
                "seq_in_chain": seq_in_chain,
                "prev_attempt_id": prev_attempt["attempt_id"],
                "package_path": package_path,
                "package_digest": package_digest,
                "created_at": utcnow(),
                "created_by": by,
                "events": candidates["included"],
                "blockers": candidates["blockers"],
                "withheld": candidates["withheld"],
            }
            entry = self._append_entry("attempt_publishing", publishing_body)
            _apply_entry(state, entry)
            self._write_snapshot(state)

            # 阶段 2：在存储内部构建包（失败可由恢复逻辑识别并中止意图）。
            try:
                build_replay_package(
                    state=state,
                    chain=chain,
                    attempt_id=attempt_id,
                    prev_attempt_id=prev_attempt["attempt_id"],
                    included=candidates["included"],
                    blockers=candidates["blockers"],
                    withheld=candidates["withheld"],
                    out_dir=package_dir,
                    created_by=by,
                )
            except BaseException:
                # 崩溃模拟/磁盘错误：不在此伪造 published，留给下次打开时恢复。
                raise
            published = self._append_entry(
                "attempt_published",
                {
                    "attempt_id": attempt_id,
                    "package_path": package_path,
                    "package_digest": package_digest,
                    "published_at": utcnow(),
                    "recovered": False,
                },
            )
            _apply_entry(state, published)
            self._write_snapshot(state)
            return {
                "ok": True,
                "chain_id": chain_id,
                "attempt_id": attempt_id,
                "prev_attempt_id": prev_attempt["attempt_id"],
                "package_digest": package_digest,
                "package_dir": str(package_dir),
                "events": [e["event_id"] for e in candidates["included"]],
                "blockers": candidates["blockers"],
                "withheld_count": len(candidates["withheld"]),
            }

    # -- 封存 / 人工中止 --------------------------------------------------
    def seal_attempt(self, attempt_id: str, *, by: str, reason: str | None) -> dict:
        with self._locked():
            state = self._load_and_recover()
            attempt = state.attempts.get(attempt_id)
            if attempt is None:
                raise ValidationError(f"未知尝试 {attempt_id!r}")
            if attempt["status"] != STATUS_DELIVERED:
                raise WorkflowError(
                    f"尝试 {attempt_id} 当前状态 {attempt['status']}，只有交付中的尝试可以封存",
                    details={"attempt_id": attempt_id, "status": attempt["status"]},
                )
            entry = self._append_entry(
                "attempt_sealed",
                {"attempt_id": attempt_id, "by": by, "reason": reason, "at": utcnow()},
            )
            _apply_entry(state, entry)
            self._write_snapshot(state)
            return {"ok": True, "attempt_id": attempt_id, "status": STATUS_SEALED}

    def abort_attempt(self, attempt_id: str, *, by: str, reason: str) -> dict:
        with self._locked():
            state = self._load_and_recover()
            attempt = state.attempts.get(attempt_id)
            if attempt is None:
                raise ValidationError(f"未知尝试 {attempt_id!r}")
            if attempt["status"] != STATUS_DELIVERED:
                raise WorkflowError(
                    f"尝试 {attempt_id} 当前状态 {attempt['status']}，不能中止",
                    details={"attempt_id": attempt_id, "status": attempt["status"]},
                )
            package_dir = self.root / attempt["package_path"]
            if package_dir.is_dir() and (package_dir / COMPLETE_MARKER).exists():
                raise WorkflowError(
                    f"尝试 {attempt_id} 的包仍完整存在且可能已交付下游，不能直接中止；"
                    "请先收回下游并删除包目录，或改用封存",
                    details={"attempt_id": attempt_id, "package_path": attempt["package_path"]},
                )
            entry = self._append_entry(
                "attempt_aborted",
                {"attempt_id": attempt_id, "reason": reason, "by": by, "at": utcnow()},
            )
            _apply_entry(state, entry)
            self._write_snapshot(state)
            return {"ok": True, "attempt_id": attempt_id, "status": STATUS_ABORTED}

    # -- 校验日志完整性 ---------------------------------------------------
    def verify_log(self) -> dict:
        with self._locked():
            entries = self._read_log_entries()
            state = _fold_entries(entries)  # 链断裂会抛 IntegrityError
            snapshot_ok = True
            if self.state_path.exists():
                try:
                    snap = ReconciliationState.from_dict(
                        json.loads(self.state_path.read_text(encoding="utf-8"))
                    )
                    snapshot_ok = (snap.last_seq, snap.last_entry_hash) == (
                        state.last_seq,
                        state.last_entry_hash,
                    )
                except (ValueError, KeyError, IntegrityError):
                    snapshot_ok = False
            else:
                snapshot_ok = False
            if not snapshot_ok:
                # 快照只是缓存：落后/缺失时按日志重建，不改变任何对账事实
                self._write_snapshot(state)
            return {
                "ok": True,
                "entries": len(entries),
                "last_entry_hash": state.last_entry_hash,
                "snapshot_in_sync": True,
                "snapshot_rebuilt": not snapshot_ok,
            }
