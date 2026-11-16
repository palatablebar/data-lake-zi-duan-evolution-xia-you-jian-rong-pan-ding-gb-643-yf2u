"""M8 版本处置：保留判定、幂等清理、失败回滚、恢复、三面一致。"""

from __future__ import annotations

import csv
import io
import sqlite3

import pytest

from app import store
from app.modules.m6_batches import history
from app.modules.m8_retention import policy, service
from tests.fixtures import expected


def make_run(seq, *, broken=0, balanced=True, open_window=False):
    """构造一个批次记录：断链数、账平、区间开闭都可控。"""
    run = {
        "run_id": f"fm-craft{seq:04d}",
        "batch_key": f"craft-key-{seq}",
        "old_schema_id": "sch-old",
        "new_schema_id": "sch-new",
        "version_seq": seq,
        "input_sha256": "0" * 64,
        "ruleset": "test-ruleset",
        "created_at": "2026-11-01T00:00:00+00:00",
        "effective_from": "2026-08-01T00:00:00+00:00",
        "effective_to": None if open_window else "2026-09-01T00:00:00+00:00",
        "version_label_old": "v2026_06",
        "version_label_new": "v2026_09",
        "ledger": {
            "counts": {"old_total": 1, "new_total": 1, "breaking": 0,
                       "refs_total": broken, "refs_broken": broken, "consumers": 1},
            "balanced": {"all": balanced},
            "refs": {"refs_total": broken, "reachable": 0, "broken": broken,
                     "aliased": 0, "direct": 0, "gap": 0, "balanced": True},
            "fields": {"old_total": 1, "new_total": 1, "buckets": {},
                       "old_side": 1, "new_side": 1, "old_gap": 0, "new_gap": 0},
        },
        "resolution": {
            "broken": [
                {"consumer": f"consumer_{i}", "kind": "view",
                 "ref": f"dim_order.c{i}", "table": "dim_order", "column": f"c{i}"}
                for i in range(broken)
            ],
        },
    }
    run["summary"] = history.summary_of(run)
    return run


@pytest.fixture()
def mixed(client):
    """种子批次之外再补三个：干净可归档、断链保留、干净但是当前基线。"""
    runs = {
        "clean": make_run(2),
        "broken": make_run(3, broken=2),
        "head": make_run(4),
    }
    for run in runs.values():
        store.save_run(run)
    return runs


def test_seeded_run_is_retained(client):
    plan = client.get("/api/retention/plan").json()
    assert plan["summary"]["archivable"] == 0
    assert plan["summary"]["retained"] == 1
    item = plan["items"][0]
    assert item["action"] == "retained"
    assert item["reasons"] == ["RETAIN_HEAD", "RETAIN_WINDOW_OPEN", "RETAIN_REFS_BROKEN"]
    assert item["primary"] == "RETAIN_HEAD"
    assert len(item["blockers"]) == expected.REFS_BROKEN


def test_classify_priority_and_archive_ok():
    run = make_run(9, broken=1, balanced=False, open_window=True)
    verdict = policy.classify(run, current_seq=9)
    assert verdict["action"] == "retained"
    assert verdict["reasons"] == ["RETAIN_HEAD", "RETAIN_WINDOW_OPEN",
                                  "RETAIN_REFS_BROKEN", "RETAIN_UNBALANCED"]
    assert verdict["primary"] == "RETAIN_HEAD"
    assert len(verdict["blockers"]) == 1

    clean = policy.classify(make_run(3), current_seq=9)
    assert clean["action"] == "archived"
    assert clean["reasons"] == ["ARCHIVE_OK"]
    assert clean["primary"] == "ARCHIVE_OK"
    assert clean["blockers"] == []


def test_cleanup_archives_only_clean_versions(client, mixed):
    plan = service.build_plan()
    by_id = {item["run_id"]: item for item in plan["items"]}
    assert by_id[mixed["clean"]["run_id"]]["action"] == "archived"
    assert by_id[mixed["broken"]["run_id"]]["action"] == "retained"
    assert by_id[mixed["head"]["run_id"]]["action"] == "retained"

    result = client.post("/api/retention/cleanup", json={}).json()
    assert result["reused"] is False
    assert result["archived"] == [mixed["clean"]["run_id"]]
    assert mixed["broken"]["run_id"] in result["retained"]
    assert result["records_written"] == 4
    assert result["freed_bytes"] > 0

    assert store.count_runs() == 3
    assert store.count_archives() == 1
    assert store.count_disposals() == 4
    # 断链版本记录数据原样保留，一个字节都没动
    assert store.run_by_id(mixed["broken"]["run_id"]) == mixed["broken"]
    # 归档负载完整，回放依据还在
    assert store.load_archive(mixed["clean"]["run_id"]) == mixed["clean"]


def test_cleanup_rerun_adds_no_records(client, mixed):
    first = client.post("/api/retention/cleanup", json={}).json()
    assert first["reused"] is False
    again = client.post("/api/retention/cleanup", json={}).json()
    assert again["reused"] is True
    assert again["records_written"] == 0
    assert again["archived"] == []
    assert again["freed_bytes"] == 0
    assert store.count_disposals() == 4
    assert store.count_archives() == 1
    assert store.count_runs() == 3


def test_pressure_never_relaxes_retention(client, mixed):
    before = store.run_by_id(mixed["broken"]["run_id"])
    result = client.post("/api/retention/cleanup", json={"pressure": True}).json()
    assert result["pressure"] is True
    assert result["archived"] == [mixed["clean"]["run_id"]]
    assert mixed["broken"]["run_id"] in result["retained"]
    # 容量告急也不丢记录数据：断链版本逐字节还在
    assert store.run_by_id(mixed["broken"]["run_id"]) == before


def test_failed_archive_rolls_back(client, mixed):
    target = mixed["clean"]["run_id"]
    # 制造归档写入冲突：归档表里已躺着同 run_id 的行
    conn = sqlite3.connect(store.db_path())
    conn.execute(
        """INSERT INTO archives (run_id, cleanup_key, version_seq, size_bytes,
               archived_at, payload_json) VALUES (?,?,?,?,?,?)""",
        (target, "planted", 2, 4, "2026-11-01T00:00:00+00:00", "{}"),
    )
    conn.commit()
    conn.close()

    response = client.post("/api/retention/cleanup", json={})
    assert response.status_code == 409
    assert response.json()["detail"]["reason"] == "ARCHIVE_CONFLICT"
    # 整体回滚：版本表、处置记录都没动，故障排除后可恢复
    assert store.count_runs() == 4
    assert store.count_disposals() == 0
    assert store.run_by_id(target) == mixed["clean"]

    conn = sqlite3.connect(store.db_path())
    conn.execute("DELETE FROM archives WHERE run_id=?", (target,))
    conn.commit()
    conn.close()
    retry = client.post("/api/retention/cleanup", json={}).json()
    assert retry["reused"] is False
    assert retry["archived"] == [target]
    assert store.count_runs() == 3
    assert store.load_archive(target) == mixed["clean"]


def test_restore_roundtrip_and_recleanup(client, mixed):
    target = mixed["clean"]["run_id"]
    client.post("/api/retention/cleanup", json={})
    assert store.run_by_id(target) is None

    restored = client.post("/api/retention/restore", json={"run_id": target}).json()
    assert restored["restored"] is True
    assert restored["version_seq"] == 2
    # 记录数据逐字节恢复
    assert store.run_by_id(target) == mixed["clean"]
    assert store.count_archives() == 0
    archived_rows = [row for row in store.list_disposals()
                     if row["run_id"] == target and row["action"] == "archived"]
    assert archived_rows and all(row["restored_at"] for row in archived_rows)

    # 恢复后重清：状态变了，是新一轮处置
    again = client.post("/api/retention/cleanup", json={}).json()
    assert again["reused"] is False
    assert again["attempt"] == 2
    assert again["archived"] == [target]
    assert store.count_disposals() == 8

    # 第三次：同一清理重跑，不再新增处置记录
    third = client.post("/api/retention/cleanup", json={}).json()
    assert third["reused"] is True
    assert third["records_written"] == 0
    assert store.count_disposals() == 8


def test_plan_csv_and_page_share_one_conclusion(client, mixed):
    plan = client.get("/api/retention/plan").json()
    text = client.get("/api/export/disposal.csv").text
    assert text == client.get("/api/export/disposal.csv").text  # 导出确定性

    rows = list(csv.DictReader(io.StringIO(text)))
    assert len(rows) == len(plan["items"]) == 4
    for row, item in zip(rows, plan["items"]):
        assert row["cleanup_key"] == plan["cleanup_key"]
        assert row["run_id"] == item["run_id"]
        assert row["action"] == item["action"]
        assert row["primary_reason"] == item["primary"]
        assert row["reasons"] == ";".join(item["reasons"])
        assert int(row["blockers"]) == len(item["blockers"])
        assert int(row["size_bytes"]) == item["size_bytes"]

    page = client.get("/retention")
    assert page.status_code == 200
    for item in plan["items"]:
        assert item["run_id"] in page.text
    assert "保留" in page.text and "归档" in page.text


def test_blockers_match_impact_and_refs_export(client):
    plan = client.get("/api/retention/plan").json()
    item = plan["items"][0]
    run = store.latest_run()
    # 与影响面同源：断链明细就是 resolution.broken
    assert item["blockers"] == run["resolution"]["broken"]
    # 与引用账导出同源：REF_BROKEN 行一一对应
    refs_rows = list(csv.DictReader(io.StringIO(client.get("/api/export/refs.csv").text)))
    broken_rows = [row for row in refs_rows if row["reason"] == "REF_BROKEN"]
    assert len(broken_rows) == len(item["blockers"]) == expected.REFS_BROKEN
    assert {row["ref"] for row in broken_rows} == {b["ref"] for b in item["blockers"]}


def test_head_retained_keeps_seq_monotonic(client, mixed):
    before = store.current_version_seq()
    client.post("/api/retention/cleanup", json={})
    assert store.current_version_seq() == before  # 基线版本不动
    response = client.post("/api/runs", json={"params": {"wave": "post-cleanup"}})
    assert response.status_code == 200
    assert response.json()["version_seq"] == before + 1


def test_unbalanced_ledger_is_retained(client):
    store.save_run(make_run(2, balanced=False))
    plan = client.get("/api/retention/plan").json()
    by_seq = {item["version_seq"]: item for item in plan["items"]}
    assert by_seq[2]["action"] == "retained"
    assert "RETAIN_UNBALANCED" in by_seq[2]["reasons"]


def test_disposals_api_and_cleanup_key_stability(client, mixed):
    plan_a = client.get("/api/retention/plan").json()
    plan_b = client.get("/api/retention/plan").json()
    assert plan_a["cleanup_key"] == plan_b["cleanup_key"]  # 同一结论同一键

    client.post("/api/retention/cleanup", json={})
    body = client.get("/api/retention/disposals").json()
    assert len(body["disposals"]) == 4
    assert len(body["archives"]) == 1
    recorded = {row["run_id"]: row for row in body["disposals"]}
    for item in plan_a["items"]:
        assert recorded[item["run_id"]]["action"] == item["action"]
        assert recorded[item["run_id"]]["reasons"] == item["reasons"]


def test_cleanup_rejects_unknown_keys(client):
    response = client.post("/api/retention/cleanup", json={"force": True})
    assert response.status_code == 400


def test_restore_guards(client, mixed):
    missing = client.post("/api/retention/restore", json={})
    assert missing.status_code == 400
    unknown = client.post("/api/retention/restore", json={"run_id": "fm-nope"})
    assert unknown.status_code == 404
    active = store.latest_run()["run_id"]
    conflict = client.post("/api/retention/restore", json={"run_id": active})
    assert conflict.status_code == 409


def test_empty_state(empty_client):
    assert empty_client.get("/api/retention/plan").status_code == 404
    assert empty_client.post("/api/retention/cleanup", json={}).status_code == 404
    assert empty_client.get("/api/export/disposal.csv").status_code == 404
    page = empty_client.get("/retention")
    assert page.status_code == 200
    assert "还没有批次" in page.text
