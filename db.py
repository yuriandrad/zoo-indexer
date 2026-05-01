"""Acesso ao SQLite usado pelo zoo-indexer."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable


DEFAULT_DB_PATH = Path("zoo-indexer.sqlite3")

SCHEMA = """
CREATE TABLE IF NOT EXISTS malware (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    path TEXT NOT NULL UNIQUE,
    type TEXT,
    platform TEXT,
    architecture TEXT,
    md5 TEXT,
    sha256 TEXT,
    tags TEXT,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_malware_name ON malware(name);
CREATE INDEX IF NOT EXISTS idx_malware_type ON malware(type);
CREATE INDEX IF NOT EXISTS idx_malware_platform ON malware(platform);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with connect(db_path) as conn:
        conn.executescript(SCHEMA)


def upsert_malware(db_path: Path, records: Iterable[dict]) -> tuple[int, int]:
    """Insere ou atualiza registros pelo path, evitando duplicidade."""
    inserted = 0
    updated = 0
    sql = """
    INSERT INTO malware (name, path, type, platform, architecture, md5, sha256, tags, updated_at)
    VALUES (:name, :path, :type, :platform, :architecture, :md5, :sha256, :tags, CURRENT_TIMESTAMP)
    ON CONFLICT(path) DO UPDATE SET
        name = excluded.name,
        type = excluded.type,
        platform = excluded.platform,
        architecture = excluded.architecture,
        md5 = excluded.md5,
        sha256 = excluded.sha256,
        tags = excluded.tags,
        updated_at = CURRENT_TIMESTAMP
    """
    with connect(db_path) as conn:
        for record in records:
            existed = conn.execute("SELECT 1 FROM malware WHERE path = ?", (record["path"],)).fetchone()
            conn.execute(sql, record)
            if existed:
                updated += 1
            else:
                inserted += 1
        conn.commit()
    return inserted, updated


def query(db_path: Path, sql: str, params: tuple | list = ()) -> list[dict]:
    with connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]
