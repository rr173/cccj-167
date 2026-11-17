"""交付后对账与补投的测试夹具与构造辅助。

夹具刻意保持小型且可提交：两个分区（p-a / p-b）、每分区三个事件，足以
演示"缺回执只阻断一个分区""阻塞点截留后续事件"等全部语义。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from dlq_recovery.models import Approval
from dlq_recovery.package import export_package, verify_package
from dlq_recovery.plan import build_plan
from dlq_recovery.recon import ReconciliationStore
from dlq_recovery.replay import verify_replay_package
from tests.helpers import msg, write_jsonl


def _row(message_id: str, partition: str, offset: int):
    return msg(
        message_id=message_id,
        business_key=f"key-{message_id}",
        partition=partition,
        offset=offset,
        payload={"id": message_id, "n": offset},
    )


def build_origin_package(root: Path) -> tuple[Path, dict]:
    """构造一个含两个分区、各三个事件的已批准交付包。

    返回 (包目录, 事件元信息 {event_id: {partition, offset, payload_sha256}})。
    """

    rows = [
        _row("ma1", "p-a", 1),
        _row("ma2", "p-a", 2),
        _row("ma3", "p-a", 3),
        _row("mb1", "p-b", 1),
        _row("mb2", "p-b", 2),
        _row("mb3", "p-b", 3),
    ]
    dl = write_jsonl(root / "dead_letter.jsonl", rows)
    from dlq_recovery.models import load_policy, load_records

    records = load_records(dl)
    base = build_plan(records, {}, load_policy(None))
    grants = {
        it.event_id: Approval(
            event_id=it.event_id,
            action="retry",
            approved_by="alice",
            approved_at="2026-11-17T00:00:00Z",
            plan_digest=base.digest,
            version_digest=None,
        )
        for it in base.items
    }
    plan = build_plan(records, {}, load_policy(None), grants)
    pkg = root / "origin-pkg"
    export_package(plan, pkg)
    verify_package(pkg)  # 登记前置条件：包必须先通过原有校验
    meta = {}
    for pf in sorted((pkg / "partitions").glob("*.ndjson")):
        for line in pf.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            meta[row["event_id"]] = {
                "partition": row["partition"],
                "offset": row["offset"],
                "payload_sha256": row["payload_sha256"],
            }
    return pkg, meta


def receipt(attempt_id: str, package_digest: str, event_id: str, payload_sha256: str,
            result: str, *, reported_by: str = "downstream", detail: str | None = None,
            reported_at: str = "2026-11-17T10:00:00Z") -> dict:
    row = {
        "attempt_id": attempt_id,
        "package_digest": package_digest,
        "event_id": event_id,
        "payload_sha256": payload_sha256,
        "result": result,
        "reported_at": reported_at,
        "reported_by": reported_by,
    }
    if detail is not None:
        row["detail"] = detail
    return row


def write_receipts(path: Path, rows: list[dict]) -> Path:
    return write_jsonl(path, rows)


class ReconciliationFixture(unittest.TestCase):
    """每个用例获得独立临时目录、已登记交付包与事件索引。"""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(self._cleanup)
        self.pkg, self.event_meta = build_origin_package(self.tmp)
        self.store_path = self.tmp / "store"
        self.store = ReconciliationStore(self.store_path)
        reg = self.store.register_package(self.pkg, by="alice", note="fixture")
        self.chain_id = reg["chain_id"]
        self.origin_attempt = reg["attempt_id"]
        self.package_digest = reg["package_digest"]
        self.state = self.store.load()
        self.chain = self.state.chains[self.chain_id]
        # 按 (分区, 偏移) 索引 event_id
        self.events_at = {
            (m["partition"], m["offset"]): eid for eid, m in self.event_meta.items()
        }

    def _cleanup(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def eid(self, partition: str, offset: int) -> str:
        return self.events_at[(partition, offset)]

    def sha(self, event_id: str) -> str:
        return self.event_meta[event_id]["payload_sha256"]

    def r(self, event_id: str, result: str, *, attempt_id: str | None = None, **kw):
        return receipt(
            attempt_id or self.origin_attempt,
            self.package_digest,
            event_id,
            self.sha(event_id),
            result,
            **kw,
        )

    def import_rows(self, rows: list[dict], *, name: str = "receipts.jsonl", by: str = "alice"):
        path = self.tmp / name
        write_receipts(path, rows)
        return self.store.import_receipts(path, by=by)

    def view(self):
        return self.store.reconcile_view(self.chain_id)["chains"][0]

    def effective(self, event_id: str, attempt_id: str | None = None) -> str:
        state = self.store.load()
        return state.effective_for(attempt_id or self.origin_attempt, event_id)
