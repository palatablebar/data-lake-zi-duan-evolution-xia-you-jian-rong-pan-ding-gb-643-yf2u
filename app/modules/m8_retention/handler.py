"""M8 入口：版本处置页、处置清单、清理与恢复、处置导出。"""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, Response

from app import errors, store, web
from app.modules.m8_retention import service

router = APIRouter()

ALLOWED_CLEANUP_KEYS = {"pressure", "note"}


@router.get("/retention", response_class=HTMLResponse)
def retention_page(request: Request):
    run = store.latest_run()
    plan = None
    if run is not None:
        plan = service.build_plan()
    return web.page_or_404(
        request,
        "retention.html",
        "retention",
        run,
        plan=plan,
        disposals=store.list_disposals(),
        archives=store.list_archives(),
    )


@router.get("/api/retention/plan")
def plan_api():
    return service.build_plan()


@router.post("/api/retention/cleanup")
def cleanup_api(payload: dict | None = None):
    body = payload or {}
    unknown = set(body) - ALLOWED_CLEANUP_KEYS
    if unknown:
        raise errors.BadInput("出现未知参数", detail={"keys": sorted(unknown)})
    note = body.get("note") or ""
    if not isinstance(note, str):
        raise errors.BadInput("note 必须是字符串", detail={"field": "note"})
    return service.execute_cleanup(pressure=bool(body.get("pressure")), note=note)


@router.post("/api/retention/restore")
def restore_api(payload: dict | None = None):
    body = payload or {}
    run_id = str(body.get("run_id") or "").strip()
    if not run_id:
        raise errors.BadInput("缺少 run_id", detail={"field": "run_id"})
    restored = service.restore(run_id)
    return {
        "run_id": run_id,
        "restored": True,
        "version_seq": restored["version_seq"],
        "reason": "ARCHIVE_RESTORED",
    }


@router.get("/api/retention/disposals")
def disposals_api():
    return {
        "disposals": store.list_disposals(),
        "archives": store.list_archives(),
    }


@router.get("/api/export/disposal.csv")
def export_disposal():
    plan = service.build_plan()
    return Response(
        content=service.disposal_csv_text(plan),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="fieldmap-disposal.csv"'},
    )
