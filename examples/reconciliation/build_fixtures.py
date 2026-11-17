#!/usr/bin/env python3
"""生成交付后对账的小型可提交夹具（只写本地文件，不接触任何服务）。

运行：

    python3 examples/reconciliation/build_fixtures.py [输出目录]

产物（默认 examples/reconciliation/fixtures）：

    origin-dead-letter.jsonl     两个分区（p-a/p-b）各三个事件的死信输入
    origin-policy.json           业务配置
    origin-approvals.jsonl       逐事件批准
    origin-pkg/                  已导出并校验的原始交付包
    receipts/                    分场景回执文件（文件名即场景说明）
    walkthrough.md               逐步对账/补投操作手册

回执覆盖：缺回执只阻断一个分区、重复/乱序收敛、未知转成功、矛盾证据、
迟到旧尝试回执、禁止重复签发与发布失败恢复（恢复场景由测试演示）。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from dlq_recovery.approvals import load_ledger, record_approval  # noqa: E402
from dlq_recovery.models import load_policy, load_records  # noqa: E402
from dlq_recovery.package import export_package, verify_package  # noqa: E402
from dlq_recovery.plan import build_plan  # noqa: E402
from dlq_recovery.replay import compute_package_digest  # noqa: E402

PARTITIONS = ("p-a", "p-b")
OFFSETS = (1, 2, 3)


def _row(message_id: str, partition: str, offset: int) -> dict:
    return {
        "message": {
            "message_id": message_id,
            "business_key": f"order-{message_id}",
            "partition": partition,
            "offset": offset,
            "payload": {"order_id": f"order-{message_id}", "amount": offset * 10},
            "event_type": "order.created",
            "status": "active",
            "occurred_at": 1000 + offset,
        },
        "failure": {
            "delivery_count": 2,
            "reason": "db_timeout",
            "evidence": f"fixture evidence {message_id}",
        },
    }


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                    encoding="utf-8")


def main(out: Path) -> None:
    import shutil

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)
    rows = [
        _row(f"m-{p[-1]}{o}", p, o)
        for p in PARTITIONS for o in OFFSETS
    ]
    dl_path = out / "origin-dead-letter.jsonl"
    _write_jsonl(dl_path, rows)
    policy_path = out / "origin-policy.json"
    policy_path.write_text(json.dumps({
        "problem_statuses": ["needs_review"],
        "final_statuses": ["cancelled", "deleted", "closed", "completed"],
    }, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    records = load_records(dl_path)
    base = build_plan(records, {}, load_policy(policy_path))
    ledger = out / "origin-approvals.jsonl"
    for item in base.items:
        record_approval(
            ledger, event_id=item.event_id, action="retry", approved_by="alice",
            plan_digest=base.digest,
            version_digest=base.version_digest(item.event_id),
            event_version={
                "business_key": item.business_key, "partition": item.partition,
                "offset": item.offset, "payload_sha256": item.payload_sha256,
            },
        )
    plan = build_plan(records, {}, load_policy(policy_path), load_ledger(ledger).active)
    # 批准过程的文件锁只是运行期同步工具，不随夹具提交
    lock = out / ".origin-approvals.jsonl.lock"
    if lock.exists():
        lock.unlink()
    pkg = out / "origin-pkg"
    export_package(plan, pkg)
    verify_package(pkg)

    # 读取包内事件身份，供回执引用
    events: dict[tuple[str, int], dict] = {}
    for pf in sorted((pkg / "partitions").glob("*.ndjson")):
        for line in pf.read_text(encoding="utf-8").splitlines():
            r = json.loads(line)
            events[(r["partition"], r["offset"])] = r
    manifest = json.loads((pkg / "manifest.json").read_text(encoding="utf-8"))
    digest = manifest["package_digest"]
    attempt = "attempt-0001"

    def rc(partition: str, offset: int, result: str, *, by: str = "downstream-batch-a",
           detail: str | None = None, at: str = "2026-11-17T10:00:00Z") -> dict:
        r = events[(partition, offset)]
        row = {
            "attempt_id": attempt,
            "package_digest": digest,
            "event_id": r["event_id"],
            "payload_sha256": r["payload_sha256"],
            "result": result,
            "reported_at": at,
            "reported_by": by,
        }
        if detail:
            row["detail"] = detail
        return row

    rdir = out / "receipts"
    # 场景 1：p-a 全部有确定结论；p-b-1 缺回执（整分区阻断）
    _write_jsonl(rdir / "01-pa-definite-pb-missing.jsonl", [
        rc("p-a", 1, "success"),
        rc("p-a", 2, "not_executed"),
        rc("p-a", 3, "not_executed"),
        rc("p-b", 2, "not_executed"),
        rc("p-b", 3, "not_executed"),
    ])
    # 场景 2：先报未知，后补成功（未知被同次尝试确定结果消解）
    _write_jsonl(rdir / "02a-unknown-first.jsonl", [
        rc("p-b", 1, "unknown", detail="下游处理超时，结果未知", at="2026-11-17T09:00:00Z"),
    ])
    _write_jsonl(rdir / "02b-success-resolves-unknown.jsonl", [
        rc("p-b", 1, "success", by="downstream-batch-b", at="2026-11-17T11:00:00Z"),
    ])
    # 场景 3：同次尝试矛盾证据（先成功后明确未执行），用于独立演示冲突
    _write_jsonl(rdir / "03a-conflict-success.jsonl", [
        rc("p-b", 2, "success", by="downstream-x"),
    ])
    _write_jsonl(rdir / "03b-conflict-not-executed.jsonl", [
        rc("p-b", 2, "not_executed", by="downstream-y"),
    ])
    # 场景 4：重复/乱序文件（与 01 内容重叠，演示幂等）
    _write_jsonl(rdir / "04-duplicate-split-out-of-order.jsonl", [
        rc("p-a", 3, "not_executed"),
        rc("p-a", 2, "not_executed"),
        rc("p-a", 1, "success"),
    ])
    # 场景 5：身份绑定错误的反例（错误 package_digest），导入必须被拒
    _write_jsonl(rdir / "05-invalid-wrong-package-digest.jsonl", [
        {**rc("p-a", 2, "success"), "package_digest": "00" * 32},
    ])

    (out / "walkthrough.md").write_text(_walkthrough(digest), encoding="utf-8")
    print(f"夹具已生成: {out}")
    print(f"原始交付包内容身份 package_digest={digest}")


def _walkthrough(digest: str) -> str:
    return f"""# 对账与补投操作手册（夹具演示）

所有命令只读写本地文件。设 `$W` 为仓库根目录，`$F` 为本夹具目录。

## 0. 原始交付包已经过原有校验

```bash
python3 -m dlq_recovery verify --package "$F/origin-pkg"
```

## 1. 登记交付包（形成首次交付尝试 attempt-0001）

```bash
python3 -m dlq_recovery register --store "$F/store" \\
    --package "$F/origin-pkg" --by alice --note "首批交付"
```

登记后包被复制进对账存储，内容身份 `package_digest`（见
`origin-pkg/manifest.json`，本次为 `{digest}`）与
`attempt_id`、每个事件的 `event_id + payload_sha256` 绑定，业务键相同的
另一个包无法顶替。

## 2. 导入回执（整文件原子生效，坏文件不留部分状态）

```bash
python3 -m dlq_recovery import-receipts --store "$F/store" \\
    --receipts "$F/receipts/01-pa-definite-pb-missing.jsonl" --by alice
```

重复导入同一文件、或导入内容重叠的 `04-duplicate-split-out-of-order.jsonl`
都是幂等的：证据按内容哈希去重，全部导入来源仍保留可追溯。

## 3. 对账预览

```bash
python3 -m dlq_recovery reconcile --store "$F/store" --text
```

`p-b` 第一个事件缺回执，是本分区阻塞点：`p-b-2/p-b-3` 即便明确未执行也被
截留；`p-a` 不受牵连。

## 4. 未知转成功

```bash
python3 -m dlq_recovery import-receipts --store "$F/store" \\
    --receipts "$F/receipts/02a-unknown-first.jsonl" --by alice
python3 -m dlq_recovery import-receipts --store "$F/store" \\
    --receipts "$F/receipts/02b-success-resolves-unknown.jsonl" --by alice
```

未知不是失败：它只在确定结果到达前阻塞补投；成功回执到达后被消解。

## 5. 矛盾证据阻断自动补投

```bash
python3 -m dlq_recovery import-receipts --store "$F/store" \\
    --receipts "$F/receipts/03a-conflict-success.jsonl" --by alice
python3 -m dlq_recovery import-receipts --store "$F/store" \\
    --receipts "$F/receipts/03b-conflict-not-executed.jsonl" --by alice
```

同次尝试同时出现成功与明确未执行时，派生态为 `conflict`，不会按文件顺序
覆盖；该事件永久退出自动补投，并在 `reconcile` 的 anomalies 中展示。

## 6. 签发补投与校验

```bash
python3 -m dlq_recovery issue-replay --store "$F/store" --by alice
python3 -m dlq_recovery verify-replay --store "$F/store" --package <输出的 package_dir>
```

补投尝试获得新的 `attempt_id`，只包含上一次明确未执行且尚未成功的事件；
每条记录带本次尝试、前次尝试与失败依据。未完成对账前再次 `issue-replay`
会被拒绝（退出码 8）。

## 7. 错误回执与迟到回执

```bash
# 身份绑定错误：整文件拒收（退出码 5），存储状态不变
python3 -m dlq_recovery import-receipts --store "$F/store" \\
    --receipts "$F/receipts/05-invalid-wrong-package-digest.jsonl" --by alice
```

迟到的旧尝试回执必须仍指向原 `attempt_id`；指向新尝试的旧 digest 回执同样
被拒。已确认成功的事件禁止再次补投，与后续登记尝试矛盾时只展示异常，
不抹掉交付历史。

## 8. 存储自检

```bash
python3 -m dlq_recovery verify-store --store "$F/store"
```

哈希链日志是唯一事实源，`state.json` 只是可重建的物化快照。
"""


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        Path(__file__).resolve().parent / "fixtures"
    )
    main(target)
