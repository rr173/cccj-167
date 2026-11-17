"""测试辅助：构造死信记录与计划，全部在临时目录内完成。"""

from __future__ import annotations

import json
from pathlib import Path

from dlq_recovery.models import (
    Approval,
    Disposition,
    load_dispositions,
    load_policy,
    load_records,
)
from dlq_recovery.plan import build_plan


def msg(
    *,
    message_id: str,
    business_key: str,
    partition: str,
    offset: int,
    payload: dict | None = None,
    event_type: str = "order.created",
    status: str = "active",
    occurred_at: int = 1000,
    delivery_count: int = 3,
    reason: str = "db_timeout",
    evidence: str | None = None,
    source_attempt: str | None = None,
) -> dict:
    message = {
        "message_id": message_id,
        "business_key": business_key,
        "partition": partition,
        "offset": offset,
        "payload": payload if payload is not None else {"id": business_key, "v": 1},
        "event_type": event_type,
        "status": status,
        "occurred_at": occurred_at,
    }
    if source_attempt is not None:
        message["source_attempt"] = source_attempt
    return {
        "message": message,
        "failure": {
            "delivery_count": delivery_count,
            "reason": reason,
            "evidence": evidence or f"line-{message_id}",
        },
    }


def write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8"
    )
    return path


def write_json(path: Path, obj) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def plan_from_rows(rows, dispositions=None, policy=None, grants=None):
    tmp = Path("/tmp")
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        dl = write_jsonl(Path(td) / "dl.jsonl", rows)
        records = load_records(dl)
        disp = {}
        if dispositions:
            disp_path = write_jsonl(Path(td) / "disp.jsonl", dispositions)
            disp = load_dispositions(disp_path)
        pol = None
        if policy is not None:
            pol_path = write_json(Path(td) / "policy.json", policy)
            pol = load_policy(pol_path)
        return build_plan(records, disp, pol, grants or {})


def item_by_event(plan, event_id):
    item = plan.item(event_id)
    assert item is not None, event_id
    return item


def items_for_key(plan, business_key):
    return [it for it in plan.items if it.business_key == business_key]
