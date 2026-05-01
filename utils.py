"""Utilitarios pequenos para hashing, inferencia e output."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


TYPE_KEYWORDS = {
    "ransomware": ("ransom", "locker", "cryptolocker", "wannacry", "wcry"),
    "trojan": ("trojan", "rat", "backdoor", "banker"),
    "worm": ("worm", "conficker", "stuxnet"),
    "virus": ("virus", "fileinfector"),
    "rootkit": ("rootkit",),
    "spyware": ("spyware", "stealer", "keylogger"),
    "botnet": ("botnet", "bot"),
}

PLATFORM_KEYWORDS = {
    "windows": ("win32", "win64", "windows", ".exe", ".dll", ".scr"),
    "linux": ("linux", "elf"),
    "android": ("android", "apk"),
    "macos": ("macos", "osx", "darwin", "mach-o"),
    "dos": ("dos",),
}

ARCH_KEYWORDS = {
    "x64": ("x64", "x86_64", "amd64", "win64"),
    "x86": ("x86", "i386", "win32"),
    "arm": ("arm", "aarch64"),
}


def read_first_hash_file(folder: Path, patterns: tuple[str, ...]) -> str | None:
    for pattern in patterns:
        for candidate in folder.glob(pattern):
            if candidate.is_file():
                text = candidate.read_text(encoding="utf-8", errors="ignore")
                match = re.search(r"\b[a-fA-F0-9]{32,64}\b", text)
                if match:
                    return match.group(0).lower()
    return None


def file_digest(path: Path, algorithm: str) -> str:
    digest = hashlib.new(algorithm)
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def infer_from_keywords(value: str, mapping: dict[str, tuple[str, ...]], default: str = "unknown") -> str:
    normalized = value.lower()
    for label, keywords in mapping.items():
        if any(keyword in normalized for keyword in keywords):
            return label
    return default


def infer_tags(*values: str | None) -> list[str]:
    text = " ".join(value for value in values if value).lower()
    tags = set()
    for label, keywords in TYPE_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            tags.add(label)
    for label, keywords in PLATFORM_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            tags.add(label)
    return sorted(tags)


def highlight_text(text: str, needle: str | None) -> str:
    if not needle or not text:
        return text
    pattern = re.compile(re.escape(needle), re.IGNORECASE)
    return pattern.sub(lambda m: f"\033[1;33m{m.group(0)}\033[0m", text)


def print_table(rows: list[dict], highlight: str | None = None) -> None:
    if not rows:
        print("Nenhum resultado encontrado.")
        return

    columns = ["id", "name", "type", "platform", "architecture", "md5", "sha256", "tags", "path"]
    if any("score" in row for row in rows):
        columns.insert(2, "score")
    prepared = []
    for row in rows:
        prepared_row = {column: str(row.get(column) or "") for column in columns}
        prepared_row["name"] = highlight_text(prepared_row["name"], highlight)
        prepared.append(prepared_row)

    widths = {
        column: min(
            max(len(strip_ansi(column)), *(len(strip_ansi(row[column])) for row in prepared)),
            48 if column in {"path", "sha256", "tags"} else 24,
        )
        for column in columns
    }

    header = " | ".join(column.upper().ljust(widths[column]) for column in columns)
    separator = "-+-".join("-" * widths[column] for column in columns)
    print(header)
    print(separator)
    for row in prepared:
        print(" | ".join(pad_ansi(truncate_ansi(row[column], widths[column]), widths[column]) for column in columns))


def strip_ansi(value: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", value)


def truncate_ansi(value: str, width: int) -> str:
    plain = strip_ansi(value)
    if len(plain) <= width:
        return value
    return plain[: max(0, width - 1)] + "..."


def pad_ansi(value: str, width: int) -> str:
    return value + (" " * max(0, width - len(strip_ansi(value))))
