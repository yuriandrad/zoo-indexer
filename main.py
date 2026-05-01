#!/usr/bin/env python3
"""CLI principal do zoo-indexer."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from db import DEFAULT_DB_PATH, init_db
from indexer import index_thezoo
from search import list_malware, search_malware
from utils import print_table


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="zoo-indexer",
        description="Indexador e buscador seguro de metadados do theZoo.",
    )
    parser.add_argument(
        "--db",
        default=str(DEFAULT_DB_PATH),
        help=f"Caminho do banco SQLite. Padrao: {DEFAULT_DB_PATH}",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Exibe logs detalhados.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    index_cmd = subparsers.add_parser("index", help="Indexa um checkout local do theZoo.")
    index_cmd.add_argument("thezoo_path", help="Caminho para o diretorio raiz do theZoo.")

    search_cmd = subparsers.add_parser("search", help="Busca malwares indexados.")
    search_cmd.add_argument("--name", help="Filtra por nome.")
    search_cmd.add_argument("--type", help="Filtra por tipo, ex: ransomware, trojan, worm.")
    search_cmd.add_argument("--platform", help="Filtra por plataforma, ex: windows, linux.")
    search_cmd.add_argument("--tag", action="append", help="Filtra por tag. Pode ser usado varias vezes.")
    search_cmd.add_argument("--json", action="store_true", help="Exibe resultado como JSON.")
    search_cmd.add_argument("--fuzzy", action="store_true", help="Ativa busca aproximada por nome.")
    search_cmd.add_argument("--no-highlight", action="store_true", help="Desativa highlight no terminal.")

    list_cmd = subparsers.add_parser("list", help="Lista malwares indexados.")
    list_cmd.add_argument("--json", action="store_true", help="Exibe resultado como JSON.")
    list_cmd.add_argument("--limit", type=int, default=100, help="Limite de registros exibidos.")

    return parser


def configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(format="%(levelname)s: %(message)s", level=level)


def output_rows(rows: list[dict], *, as_json: bool, highlight: str | None = None) -> None:
    if as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return
    print_table(rows, highlight=highlight)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.verbose)

    db_path = Path(args.db)
    init_db(db_path)

    if args.command == "index":
        stats = index_thezoo(Path(args.thezoo_path), db_path)
        print(f"Indexacao concluida: {stats.indexed} novos, {stats.updated} atualizados, {stats.skipped} ignorados.")
        return 0

    if args.command == "search":
        rows = search_malware(
            db_path,
            name=args.name,
            malware_type=args.type,
            platform=args.platform,
            tags=args.tag,
            fuzzy=args.fuzzy,
        )
        output_rows(rows, as_json=args.json, highlight=None if args.no_highlight else args.name)
        return 0

    if args.command == "list":
        rows = list_malware(db_path, limit=args.limit)
        output_rows(rows, as_json=args.json)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
