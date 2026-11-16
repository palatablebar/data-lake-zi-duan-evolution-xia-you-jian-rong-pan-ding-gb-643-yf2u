"""SQLite 读写：批次快照、运行清单、隔离行、键值状态。

只放数据访问，不放判定；调用方拿到的是普通字典。
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path

from app import config

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    schema_id      TEXT PRIMARY KEY,
    version_label  TEXT NOT NULL,
    source_path    TEXT NOT NULL,
    source_sha256  TEXT NOT NULL,
    encoding       TEXT NOT NULL,
    bom            INTEGER NOT NULL,
    field_count    INTEGER NOT NULL,
    blocked_count  INTEGER NOT NULL,
    created_at     TEXT NOT NULL,
    payload_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id         TEXT PRIMARY KEY,
    batch_key      TEXT NOT NULL UNIQUE,
    old_schema_id  TEXT NOT NULL,
    new_schema_id  TEXT NOT NULL,
    version_seq    INTEGER NOT NULL,
    input_sha256   TEXT NOT NULL,
    ruleset        TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    effective_to   TEXT,
    summary_json   TEXT NOT NULL,
    payload_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine (
    schema_id     TEXT NOT NULL,
    line          INTEGER,
    table_name    TEXT,
    column_name   TEXT,
    reason        TEXT NOT NULL,
    blocking      INTEGER NOT NULL,
    detail        TEXT,
    raw           TEXT
);
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS archives (
    run_id       TEXT PRIMARY KEY,
    cleanup_key  TEXT NOT NULL,
    version_seq  INTEGER NOT NULL,
    size_bytes   INTEGER NOT NULL,
    archived_at  TEXT NOT NULL,
    payload_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS disposals (
    disposal_id  TEXT PRIMARY KEY,
    cleanup_key  TEXT NOT NULL,
    attempt      INTEGER NOT NULL,
    run_id       TEXT NOT NULL,
    version_seq  INTEGER NOT NULL,
    action       TEXT NOT NULL,
    reasons_json TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL,
    created_at   TEXT NOT NULL,
    restored_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_quarantine_schema ON quarantine(schema_id);
CREATE INDEX IF NOT EXISTS idx_disposals_cleanup ON disposals(cleanup_key);
"""


def db_path() -> Path:
    raw = os.environ.get("FIELDMAP_DB", "").strip()
    path = Path(raw) if raw else config.DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _LOCK, _connect() as conn:
        conn.executescript(SCHEMA)


def reset() -> None:
    """测试与重建用：清空全部业务表。"""
    with _LOCK, _connect() as conn:
        conn.executescript(SCHEMA)
        for table in ("snapshots", "runs", "quarantine", "kv", "archives", "disposals"):
            conn.execute(f"DELETE FROM {table}")


def _dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads(value):
    if not value:
        return None
    return json.loads(value)


# ---------- 快照 ----------

def save_snapshot(snapshot: dict) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            """INSERT INTO snapshots (schema_id, version_label, source_path, source_sha256,
                   encoding, bom, field_count, blocked_count, created_at, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(schema_id) DO UPDATE SET
                   version_label=excluded.version_label,
                   source_path=excluded.source_path,
                   source_sha256=excluded.source_sha256,
                   encoding=excluded.encoding,
                   bom=excluded.bom,
                   field_count=excluded.field_count,
                   blocked_count=excluded.blocked_count,
                   created_at=excluded.created_at,
                   payload_json=excluded.payload_json""",
            (
                snapshot["schema_id"], snapshot["version_label"], snapshot["source_path"],
                snapshot["source_sha256"], snapshot["encoding"], int(bool(snapshot["bom"])),
                int(snapshot["field_count"]), int(snapshot["blocked_count"]),
                snapshot["created_at"], _dumps(snapshot),
            ),
        )


def load_snapshot(schema_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM snapshots WHERE schema_id=?", (schema_id,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def list_snapshots(limit: int = 20) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT schema_id, version_label, source_path, source_sha256, encoding, bom,
                      field_count, blocked_count, created_at
               FROM snapshots ORDER BY created_at DESC, schema_id LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def save_quarantine(schema_id: str, rows: list[dict]) -> None:
    with _LOCK, _connect() as conn:
        conn.execute("DELETE FROM quarantine WHERE schema_id=?", (schema_id,))
        conn.executemany(
            """INSERT INTO quarantine (schema_id, line, table_name, column_name, reason,
                   blocking, detail, raw) VALUES (?,?,?,?,?,?,?,?)""",
            [
                (
                    schema_id, int(row.get("line") or 0), row.get("table") or "",
                    row.get("column") or "", row["reason"], int(bool(row.get("blocking"))),
                    row.get("detail") or "", row.get("raw") or "",
                )
                for row in rows
            ],
        )


def list_quarantine(schema_id: str) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT line, table_name, column_name, reason, blocking, detail, raw
               FROM quarantine WHERE schema_id=? ORDER BY line, reason""",
            (schema_id,),
        ).fetchall()
    return [
        {
            "line": row["line"],
            "table": row["table_name"],
            "column": row["column_name"],
            "reason": row["reason"],
            "blocking": bool(row["blocking"]),
            "detail": row["detail"],
            "raw": row["raw"],
        }
        for row in rows
    ]


# ---------- 运行清单 ----------

def save_run(run: dict) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            """INSERT INTO runs (run_id, batch_key, old_schema_id, new_schema_id, version_seq,
                   input_sha256, ruleset, created_at, effective_from, effective_to,
                   summary_json, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                run["run_id"], run["batch_key"], run["old_schema_id"], run["new_schema_id"],
                int(run["version_seq"]), run["input_sha256"], run["ruleset"],
                run["created_at"], run["effective_from"], run["effective_to"],
                _dumps(run["summary"]), _dumps(run),
            ),
        )


def find_run_by_key(batch_key: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs WHERE batch_key=?", (batch_key,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def run_by_id(run_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def latest_run() -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs ORDER BY version_seq DESC LIMIT 1"
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def list_runs(limit: int = 30) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT summary_json FROM runs ORDER BY version_seq DESC, run_id LIMIT ?""",
            (limit,),
        ).fetchall()
    return [_loads(row["summary_json"]) for row in rows]


def count_runs() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()
    return int(row["n"])


def next_version_seq() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COALESCE(MAX(version_seq), 0) AS n FROM runs").fetchone()
    return int(row["n"]) + 1


def current_version_seq() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COALESCE(MAX(version_seq), 0) AS n FROM runs").fetchone()
    return int(row["n"])


def list_windows() -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT run_id, effective_from, effective_to FROM runs ORDER BY version_seq"
        ).fetchall()
    return [dict(row) for row in rows]


# ---------- 键值 ----------

def set_kv(key: str, value) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT INTO kv (k, v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, _dumps(value)),
        )


def get_kv(key: str, default=None):
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return _loads(row["v"]) if row else default


# ---------- 版本处置（归档 / 保留） ----------

class ArchiveFailed(Exception):
    """归档事务内部的失败：连接已回滚，活动表保持原样。"""


def list_runs_full() -> list[dict]:
    """全部批次的完整负载与占用字节，按版本序号升序。"""
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT payload_json, LENGTH(payload_json) AS size_bytes
               FROM runs ORDER BY version_seq, run_id"""
        ).fetchall()
    return [
        {"run": _loads(row["payload_json"]), "size_bytes": int(row["size_bytes"])}
        for row in rows
    ]


def execute_cleanup_tx(cleanup_key: str, attempt: int, items: list[dict],
                       created_at: str) -> None:
    """一次清理一个事务：归档负载 → 记处置 → 移出版本表。

    任一步失败整体回滚，runs 表保持原样，重试不会留下半归档状态。
    items 里 action=archived 的才动 runs；retained 只落处置记录。
    """
    archived = [item for item in items if item["action"] == "archived"]
    with _LOCK, _connect() as conn:
        for item in archived:
            row = conn.execute(
                "SELECT payload_json FROM runs WHERE run_id=?", (item["run_id"],)
            ).fetchone()
            if row is None:
                raise ArchiveFailed(f"批次 {item['run_id']} 在清理期间被改动")
            conn.execute(
                """INSERT INTO archives (run_id, cleanup_key, version_seq, size_bytes,
                       archived_at, payload_json) VALUES (?,?,?,?,?,?)""",
                (item["run_id"], cleanup_key, int(item["version_seq"]),
                 int(item["size_bytes"]), created_at, row["payload_json"]),
            )
        for item in items:
            conn.execute(
                """INSERT INTO disposals (disposal_id, cleanup_key, attempt, run_id,
                       version_seq, action, reasons_json, size_bytes, created_at,
                       restored_at) VALUES (?,?,?,?,?,?,?,?,?,NULL)""",
                (item["disposal_id"], cleanup_key, int(attempt), item["run_id"],
                 int(item["version_seq"]), item["action"], _dumps(item["reasons"]),
                 int(item["size_bytes"]), created_at),
            )
        for item in archived:
            conn.execute("DELETE FROM runs WHERE run_id=?", (item["run_id"],))


def restore_run_tx(run_id: str, restored_at: str) -> dict | None:
    """把归档批次原样写回版本表，并销掉对应处置的 restored_at。

    与归档同一事务语义：写回、删归档、销记录要么全成要么全不成。
    """
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM archives WHERE run_id=?", (run_id,)
        ).fetchone()
        if row is None:
            return None
        payload = _loads(row["payload_json"])
        conn.execute(
            """INSERT INTO runs (run_id, batch_key, old_schema_id, new_schema_id,
                   version_seq, input_sha256, ruleset, created_at, effective_from,
                   effective_to, summary_json, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                payload["run_id"], payload["batch_key"], payload["old_schema_id"],
                payload["new_schema_id"], int(payload["version_seq"]),
                payload["input_sha256"], payload["ruleset"], payload["created_at"],
                payload["effective_from"], payload["effective_to"],
                _dumps(payload["summary"]), row["payload_json"],
            ),
        )
        conn.execute("DELETE FROM archives WHERE run_id=?", (run_id,))
        conn.execute(
            """UPDATE disposals SET restored_at=?
               WHERE run_id=? AND action='archived' AND restored_at IS NULL""",
            (restored_at, run_id),
        )
    return payload


def max_attempt(cleanup_key: str) -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(MAX(attempt), 0) AS n FROM disposals WHERE cleanup_key=?",
            (cleanup_key,),
        ).fetchone()
    return int(row["n"])


def latest_disposals_by_run() -> dict:
    """每个批次最新一条处置记录，用于判断同一清理重跑。"""
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT disposal_id, cleanup_key, attempt, run_id, version_seq, action,
                      reasons_json, size_bytes, created_at, restored_at
               FROM disposals ORDER BY created_at, attempt, disposal_id"""
        ).fetchall()
    latest: dict[str, dict] = {}
    for row in rows:
        latest[row["run_id"]] = _disposal_row(row)
    return latest


def list_disposals(limit: int = 100) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT disposal_id, cleanup_key, attempt, run_id, version_seq, action,
                      reasons_json, size_bytes, created_at, restored_at
               FROM disposals
               ORDER BY created_at DESC, cleanup_key, attempt, version_seq LIMIT ?""",
            (limit,),
        ).fetchall()
    return [_disposal_row(row) for row in rows]


def count_disposals() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM disposals").fetchone()
    return int(row["n"])


def list_archives() -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT run_id, cleanup_key, version_seq, size_bytes, archived_at
               FROM archives ORDER BY version_seq, run_id"""
        ).fetchall()
    return [dict(row) for row in rows]


def count_archives() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM archives").fetchone()
    return int(row["n"])


def load_archive(run_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM archives WHERE run_id=?", (run_id,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def _disposal_row(row) -> dict:
    return {
        "disposal_id": row["disposal_id"],
        "cleanup_key": row["cleanup_key"],
        "attempt": int(row["attempt"]),
        "run_id": row["run_id"],
        "version_seq": int(row["version_seq"]),
        "action": row["action"],
        "reasons": _loads(row["reasons_json"]) or [],
        "size_bytes": int(row["size_bytes"]),
        "created_at": row["created_at"],
        "restored_at": row["restored_at"],
    }
