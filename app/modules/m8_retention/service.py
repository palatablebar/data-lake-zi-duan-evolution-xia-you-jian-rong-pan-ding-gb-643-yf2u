"""版本处置编排：处置清单、清理执行、归档恢复、处置导出。

处置清单（plan）、影响面（断链阻塞）、导出（disposal.csv）都从
build_plan() 出，清理执行的归档集合就是清单里的可归档集合，
四个面看到的是同一结论。

幂等：当前清单的每一项结论若已被最新处置记录覆盖（归档未被恢复、
动作与原因一致），本次清理就是同一清理的重跑，直接复用、不新增
处置记录；只有结论变了（新批次、断链修复、恢复后重清）才落新一轮。
"""

from __future__ import annotations

import csv
import io
import sqlite3

from app import config, errors, store
from app.modules.m8_retention import policy

CSV_HEADER = [
    "cleanup_key", "run_id", "version_seq", "version_label", "action",
    "primary_reason", "reasons", "blockers", "size_bytes",
]


def build_plan() -> dict:
    """当前库状态的处置清单；没有批次时 404。"""
    rows = store.list_runs_full()
    if not rows:
        raise errors.NotFound("还没有批次，先在版本历史页跑一次")
    return policy.plan(rows, store.current_version_seq())


def execute_cleanup(pressure: bool = False, note: str = "") -> dict:
    """执行一次清理：可归档的进归档表，保留的留在活动表。

    pressure 只记录在返回里，绝不放宽保留判定：仍被未完成迁移
    引用的版本，容量告急也不动它的记录数据。
    """
    plan = build_plan()
    key = plan["cleanup_key"]
    latest = store.latest_disposals_by_run()
    if all(_covered_by(item, latest.get(item["run_id"])) for item in plan["items"]):
        # 同一清理重跑：复用已有处置，不新增记录、不再动版本表
        return _result(key, plan, reused=True, attempt=store.max_attempt(key),
                       pressure=pressure, note=note, archived_now=[],
                       freed_now=0, records_written=0)

    attempt = store.max_attempt(key) + 1
    created_at = config.now_utc().isoformat()
    items = [
        {**item, "disposal_id": policy.disposal_id(key, attempt, item["run_id"])}
        for item in plan["items"]
    ]
    try:
        store.execute_cleanup_tx(key, attempt, items, created_at)
    except store.ArchiveFailed as exc:
        raise errors.Conflict(
            f"归档中止：{exc}，本次清理已整体回滚",
            detail={"reason": "ARCHIVE_FAILED", "cleanup_key": key},
        ) from exc
    except sqlite3.IntegrityError as exc:
        raise errors.Conflict(
            "归档写入冲突，本次清理已整体回滚，版本数据未动",
            detail={"reason": "ARCHIVE_CONFLICT", "cleanup_key": key},
        ) from exc
    archived_now = [item["run_id"] for item in items if item["action"] == "archived"]
    freed_now = sum(item["size_bytes"] for item in items if item["action"] == "archived")
    return _result(key, plan, reused=False, attempt=attempt, pressure=pressure,
                   note=note, archived_now=archived_now, freed_now=freed_now,
                   records_written=len(items))


def restore(run_id: str) -> dict:
    """把归档版本原样恢复到活动表；处置记录销记 restored_at。"""
    if store.run_by_id(run_id) is not None:
        raise errors.Conflict("该版本仍在活动表中，无需恢复",
                              detail={"run_id": run_id, "reason": "ALREADY_ACTIVE"})
    payload = store.restore_run_tx(run_id, config.now_utc().isoformat())
    if payload is None:
        raise errors.NotFound("归档里没有这个版本",
                              detail={"run_id": run_id})
    return payload


def disposal_csv_text(plan: dict) -> str:
    """处置清单的 CSV 形态：与 plan 同序、同行、同结论。"""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_HEADER)
    for item in plan["items"]:
        writer.writerow([
            plan["cleanup_key"],
            item["run_id"],
            str(item["version_seq"]),
            f"{item.get('version_label_old') or ''} → {item.get('version_label_new') or ''}",
            item["action"],
            item["primary"],
            ";".join(item["reasons"]),
            str(len(item["blockers"])),
            str(item["size_bytes"]),
        ])
    return buffer.getvalue()


def _covered_by(item: dict, disposal: dict | None) -> bool:
    """清单项是否已被最新处置记录覆盖：动作与原因一致，归档未被恢复。"""
    if disposal is None:
        return False
    if disposal["action"] != item["action"]:
        return False
    if disposal["reasons"] != item["reasons"]:
        return False
    if item["action"] == policy.ACTION_ARCHIVE and disposal["restored_at"]:
        return False
    return True


def _result(key: str, plan: dict, reused: bool, attempt: int, pressure: bool,
            note: str, archived_now: list[str], freed_now: int,
            records_written: int) -> dict:
    return {
        "cleanup_key": key,
        "reused": reused,
        "attempt": int(attempt),
        "pressure": bool(pressure),
        "note": note or "",
        "archived": archived_now,
        "retained": [item["run_id"] for item in plan["items"]
                     if item["action"] == "retained"],
        "freed_bytes": int(freed_now),
        "records_written": int(records_written),
        "summary": plan["summary"],
    }
