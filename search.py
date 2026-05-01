"""Consultas e busca aproximada no indice SQLite."""

from __future__ import annotations

import difflib
from pathlib import Path

from db import query


def list_malware(db_path: Path, limit: int = 100) -> list[dict]:
    return query(
        db_path,
        """
        SELECT id, name, path, type, platform, architecture, md5, sha256, tags
        FROM malware
        ORDER BY name COLLATE NOCASE
        LIMIT ?
        """,
        (limit,),
    )


def search_malware(
    db_path: Path,
    *,
    name: str | None = None,
    malware_type: str | None = None,
    platform: str | None = None,
    tags: list[str] | None = None,
    fuzzy: bool = False,
) -> list[dict]:
    clauses = []
    params: list[str] = []

    if name and not fuzzy:
        clauses.append("name LIKE ?")
        params.append(f"%{name}%")
    if malware_type:
        clauses.append("type = ?")
        params.append(malware_type.lower())
    if platform:
        clauses.append("platform = ?")
        params.append(platform.lower())
    for tag in tags or []:
        clauses.append("tags LIKE ?")
        params.append(f"%{tag.lower()}%")

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = query(
        db_path,
        f"""
        SELECT id, name, path, type, platform, architecture, md5, sha256, tags
        FROM malware
        {where}
        ORDER BY name COLLATE NOCASE
        """,
        params,
    )

    if name and fuzzy:
        rows = fuzzy_filter(rows, name)

    return rows


def fuzzy_filter(rows: list[dict], name: str, cutoff: float = 0.55) -> list[dict]:
    scored = []
    needle = name.lower()
    for row in rows:
        candidate = (row.get("name") or "").lower()
        ratio = difflib.SequenceMatcher(None, needle, candidate).ratio()
        if needle in candidate:
            ratio = max(ratio, 0.95)
        if ratio >= cutoff:
            item = dict(row)
            item["score"] = round(ratio, 3)
            scored.append(item)
    scored.sort(key=lambda item: item["score"], reverse=True)
    return scored
