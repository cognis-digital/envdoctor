"""Command-line interface for ENVDOCTOR.

Subcommands:
    lint    Structural + secret-hygiene checks on a .env file.
    drift   Compare a .env against an example template for config drift.
    check   Validate a .env against a JSON schema (required keys + types).

Global flags:
    --version            Print tool version and exit.
    --format {table,json}  Output format (default: table).

Exit code is non-zero when any ERROR-severity finding is present.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import Report, Severity, lint_file, diff_env, check_schema

_SEV_LABEL = {
    Severity.ERROR: "ERROR",
    Severity.WARNING: "WARN",
    Severity.INFO: "INFO",
}


def _render_table(report: Report) -> str:
    if not report.findings:
        return "OK  no problems found"
    lines: List[str] = []
    for f in report.findings:
        loc = ""
        if f.line is not None:
            loc = f"L{f.line} "
        elif f.key is not None:
            loc = f"{f.key} "
        lines.append(f"{_SEV_LABEL[f.severity]:5} {f.rule:18} {loc}{f.message}")
    counts = report.to_dict()["counts"]
    lines.append(
        f"\n{counts['error']} error(s), "
        f"{counts['warning']} warning(s), "
        f"{counts['info']} info"
    )
    return "\n".join(lines)


def _emit(report: Report, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render_table(report))


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=".env validator, secret-presence and config-drift checker.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p_lint = sub.add_parser("lint", help="lint a .env file for structure + secrets")
    p_lint.add_argument("path", help="path to the .env file")

    p_drift = sub.add_parser("drift", help="detect config drift vs an example file")
    p_drift.add_argument("--example", required=True, help="path to .env.example")
    p_drift.add_argument("--env", required=True, help="path to .env")

    p_check = sub.add_parser("check", help="validate a .env against a JSON schema")
    p_check.add_argument("--schema", required=True, help="path to schema JSON")
    p_check.add_argument("--env", required=True, help="path to .env")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "lint":
        report = lint_file(args.path)
    elif args.command == "drift":
        report = diff_env(args.example, args.env)
    elif args.command == "check":
        report = check_schema(args.schema, args.env)
    else:  # pragma: no cover - argparse enforces a valid command
        parser.error("unknown command")
        return 2

    _emit(report, args.format)
    return 0 if report.ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
