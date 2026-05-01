"""Logica de indexacao segura do theZoo."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from db import upsert_malware
from utils import (
    ARCH_KEYWORDS,
    PLATFORM_KEYWORDS,
    TYPE_KEYWORDS,
    file_digest,
    infer_from_keywords,
    infer_tags,
    read_first_hash_file,
)


ZIP_EXTENSIONS = {".zip", ".7z", ".rar"}


@dataclass
class IndexStats:
    indexed: int = 0
    updated: int = 0
    skipped: int = 0


def index_thezoo(thezoo_path: Path, db_path: Path) -> IndexStats:
    binaries_dir = thezoo_path / "malware" / "Binaries"
    source_dir = thezoo_path / "malware" / "Source"

    if not binaries_dir.exists():
        raise FileNotFoundError(f"Diretorio nao encontrado: {binaries_dir}")

    records = []
    skipped = 0

    for folder in iter_malware_folders(binaries_dir):
        record = build_record(folder, thezoo_path, source_dir)
        if record:
            records.append(record)
        else:
            skipped += 1

    indexed, updated = upsert_malware(db_path, records)
    return IndexStats(indexed=indexed, updated=updated, skipped=skipped)


def iter_malware_folders(binaries_dir: Path):
    """Retorna pastas que aparentam conter uma amostra compactada ou hashes."""
    for folder in binaries_dir.rglob("*"):
        if not folder.is_dir():
            continue
        files = [item for item in folder.iterdir() if item.is_file()]
        has_archive = any(item.suffix.lower() in ZIP_EXTENSIONS for item in files)
        has_hash = any("md5" in item.name.lower() or "sha256" in item.name.lower() for item in files)
        if has_archive or has_hash:
            yield folder


def build_record(folder: Path, thezoo_path: Path, source_dir: Path) -> dict | None:
    archive = find_archive(folder)
    md5 = read_first_hash_file(folder, ("*md5*", "*.md5")) or safe_digest(archive, "md5")
    sha256 = read_first_hash_file(folder, ("*sha256*", "*.sha256")) or safe_digest(archive, "sha256")

    name = folder.name
    relative_path = str(folder.relative_to(thezoo_path))
    source_hint = find_source_hint(source_dir, name)
    haystack = " ".join(filter(None, [name, relative_path, archive.name if archive else None, source_hint]))

    malware_type = infer_from_keywords(haystack, TYPE_KEYWORDS)
    platform = infer_from_keywords(haystack, PLATFORM_KEYWORDS)
    architecture = infer_from_keywords(haystack, ARCH_KEYWORDS)
    tags = infer_tags(haystack, malware_type, platform)

    logging.debug("Indexando %s", relative_path)
    return {
        "name": name,
        "path": str(folder.resolve()),
        "type": malware_type,
        "platform": platform,
        "architecture": architecture,
        "md5": md5,
        "sha256": sha256,
        "tags": ",".join(tags),
    }


def find_archive(folder: Path) -> Path | None:
    for item in folder.iterdir():
        if item.is_file() and item.suffix.lower() in ZIP_EXTENSIONS:
            return item
    return None


def safe_digest(path: Path | None, algorithm: str) -> str | None:
    if not path:
        return None
    try:
        return file_digest(path, algorithm)
    except OSError as exc:
        logging.warning("Nao foi possivel calcular %s de %s: %s", algorithm, path, exc)
        return None


def find_source_hint(source_dir: Path, malware_name: str) -> str | None:
    if not source_dir.exists():
        return None
    target = malware_name.lower()
    for item in source_dir.rglob("*"):
        if target in item.name.lower():
            return str(item)
    return None
