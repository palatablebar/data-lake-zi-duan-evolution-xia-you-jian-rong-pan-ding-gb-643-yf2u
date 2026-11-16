"""版本处置判定：哪些版本可以归档、哪些必须保留。

保留优先于容量：任何一条保留原因命中，版本就留在活动表，
容量告急（pressure）不改变这里的结论。原因按优先级排列，
primary 取第一条；可归档的版本统一给 ARCHIVE_OK。

保留原因优先级：
1. RETAIN_HEAD         当前基线版本，下一批次的版本序号与陈旧守卫都靠它
2. RETAIN_WINDOW_OPEN  生效区间未关闭，回放还要以它为界
3. RETAIN_REFS_BROKEN  迁移未完成，下游仍引用断掉的旧字段
4. RETAIN_UNBALANCED   账目未摆平，审计还要原始记录
"""

from __future__ import annotations

import json

from app import config, manifest as manifest_mod

POLICY_VERSION = "ret-2026.11.1"

RETAIN_PRIORITY = (
    "RETAIN_HEAD",
    "RETAIN_WINDOW_OPEN",
    "RETAIN_REFS_BROKEN",
    "RETAIN_UNBALANCED",
)

ACTION_ARCHIVE = "archived"
ACTION_RETAIN = "retained"


def classify(run: dict, current_seq: int) -> dict:
    """单个批次的处置结论：动作、原因（按优先级）、断链阻塞明细。"""
    reasons: list[str] = []
    if int(run.get("version_seq") or 0) == int(current_seq):
        reasons.append("RETAIN_HEAD")
    if not run.get("effective_to"):
        reasons.append("RETAIN_WINDOW_OPEN")
    ledger = run.get("ledger") or {}
    refs = ledger.get("refs") or {}
    broken = int(refs.get("broken") or 0)
    if broken > 0:
        reasons.append("RETAIN_REFS_BROKEN")
    if (ledger.get("balanced") or {}).get("all") is not True:
        # 账目缺失也算未摆平：数据不全时宁可保留
        reasons.append("RETAIN_UNBALANCED")

    blockers: list[dict] = []
    if "RETAIN_REFS_BROKEN" in reasons:
        # 与 /impact 页、refs.csv 的断链行同源，保证影响面结论一致
        blockers = list((run.get("resolution") or {}).get("broken") or [])

    action = ACTION_RETAIN if reasons else ACTION_ARCHIVE
    return {
        "run_id": run["run_id"],
        "action": action,
        "reasons": reasons if reasons else ["ARCHIVE_OK"],
        "primary": reasons[0] if reasons else "ARCHIVE_OK",
        "blockers": blockers,
    }


def plan(runs_with_sizes: list[dict], current_seq: int) -> dict:
    """处置清单：逐版本结论 + 汇总 + 清理键。

    清理键覆盖每个版本的动作与原因：库状态不变则键不变，
    同一清理重跑命中已有处置记录，不新增行。
    """
    items: list[dict] = []
    for entry in runs_with_sizes:
        run, size = entry["run"], int(entry["size_bytes"])
        verdict = classify(run, current_seq)
        items.append({
            **verdict,
            "version_seq": int(run.get("version_seq") or 0),
            "version_label_old": run.get("version_label_old"),
            "version_label_new": run.get("version_label_new"),
            "effective_from": run.get("effective_from"),
            "effective_to": run.get("effective_to"),
            "size_bytes": size,
        })
    items.sort(key=lambda item: item["version_seq"])

    archivable = [item for item in items if item["action"] == ACTION_ARCHIVE]
    summary = {
        "total": len(items),
        "archivable": len(archivable),
        "retained": len(items) - len(archivable),
        "reclaimable_bytes": sum(item["size_bytes"] for item in archivable),
        "current_version_seq": int(current_seq),
    }
    return {
        "cleanup_key": cleanup_key(items),
        "policy_version": POLICY_VERSION,
        "ruleset": config.RULESET_VERSION,
        "summary": summary,
        "items": items,
    }


def cleanup_key(items: list[dict]) -> str:
    """结论的规范化摘要：同一结论同一键，结论变了就是另一次清理。"""
    payload = json.dumps(
        {
            "policy": POLICY_VERSION,
            "ruleset": config.RULESET_VERSION,
            "items": [
                {"run_id": item["run_id"], "action": item["action"],
                 "reasons": item["reasons"]}
                for item in items
            ],
        },
        ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    )
    return manifest_mod.sha256_bytes(payload.encode("utf-8"))


def disposal_id(key: str, attempt: int, run_id: str) -> str:
    return f"dp-{key[:8]}-{int(attempt):02d}-{run_id}"
