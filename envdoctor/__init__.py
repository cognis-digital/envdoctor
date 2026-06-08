"""ENVDOCTOR -- a .env validator, secret-presence and config-drift checker.

Standard library only. Zero install. Single-binary developer experience.

Typical use::

    envdoctor lint .env
    envdoctor drift --example .env.example --env .env
    envdoctor check --schema env.schema.json --env .env

The package exposes a small, importable engine (:mod:`envdoctor.core`) plus a
thin argparse front end (:mod:`envdoctor.cli`).
"""
from .core import (
    Finding,
    Report,
    Severity,
    parse_env,
    lint_file,
    diff_env,
    check_schema,
)

TOOL_NAME = "envdoctor"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Severity",
    "Finding",
    "Report",
    "parse_env",
    "lint_file",
    "diff_env",
    "check_schema",
]
