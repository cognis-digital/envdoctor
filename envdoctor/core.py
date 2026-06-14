"""Core engine for ENVDOCTOR.

Pure standard library. No I/O side effects except reading files in the helpers
that explicitly take a path. Everything returns plain dataclasses so the CLI and
tests can reason about results without parsing strings.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class Finding:
    """A single problem discovered during analysis."""

    rule: str
    severity: Severity
    message: str
    key: Optional[str] = None
    line: Optional[int] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Report:
    """Aggregate of findings for one command invocation."""

    findings: List[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def errors(self) -> List[Finding]:
        return [f for f in self.findings if f.severity is Severity.ERROR]

    @property
    def warnings(self) -> List[Finding]:
        return [f for f in self.findings if f.severity is Severity.WARNING]

    @property
    def ok(self) -> bool:
        """True when nothing rises to ERROR severity."""
        return not self.errors

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "counts": {
                "error": len(self.errors),
                "warning": len(self.warnings),
                "info": len([f for f in self.findings if f.severity is Severity.INFO]),
            },
            "findings": [f.to_dict() for f in self.findings],
        }


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #

_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_LINE_RE = re.compile(
    r"""^\s*
        (?:export\s+)?          # optional leading `export`
        (?P<key>[^=\s]+)
        \s*=\s*
        (?P<value>.*)$
    """,
    re.VERBOSE,
)


def _strip_value(raw: str) -> str:
    """Strip surrounding quotes and trailing inline comments from a value."""
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ("'", '"'):
        return raw[1:-1]
    # Drop unquoted inline comment: `FOO=bar  # note`
    if "#" in raw:
        before = raw.split("#", 1)[0]
        if before.rstrip() != raw:
            raw = before.rstrip()
    return raw


def parse_env(text: str) -> Tuple[Dict[str, str], List[Finding]]:
    """Parse dotenv text into an ordered dict plus structural findings.

    Findings cover malformed lines, duplicate keys, invalid key names and
    suspicious whitespace -- the same family of checks dotenv-linter ships.
    """
    values: Dict[str, str] = {}
    findings: List[Finding] = []
    seen_lines: Dict[str, int] = {}

    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        m = _LINE_RE.match(line)
        if not m:
            findings.append(
                Finding(
                    rule="malformed-line",
                    severity=Severity.ERROR,
                    message=f"Line is not a KEY=VALUE assignment: {stripped!r}",
                    line=lineno,
                )
            )
            continue

        key = m.group("key").strip()
        raw_value = m.group("value")
        value = _strip_value(raw_value)

        if not _KEY_RE.match(key):
            findings.append(
                Finding(
                    rule="invalid-key",
                    severity=Severity.ERROR,
                    message=(
                        f"Key {key!r} is not a valid identifier "
                        "(use A-Z, 0-9, underscore; cannot start with a digit)"
                    ),
                    key=key,
                    line=lineno,
                )
            )
            continue

        if key != key.upper():
            findings.append(
                Finding(
                    rule="lowercase-key",
                    severity=Severity.WARNING,
                    message=f"Key {key!r} should be UPPER_SNAKE_CASE by convention",
                    key=key,
                    line=lineno,
                )
            )

        if key in seen_lines:
            findings.append(
                Finding(
                    rule="duplicate-key",
                    severity=Severity.ERROR,
                    message=(
                        f"Key {key!r} is defined again "
                        f"(first seen on line {seen_lines[key]})"
                    ),
                    key=key,
                    line=lineno,
                )
            )
        seen_lines[key] = lineno
        values[key] = value

    return values, findings


# --------------------------------------------------------------------------- #
# Secret heuristics
# --------------------------------------------------------------------------- #

_SECRET_KEY_HINTS = (
    "SECRET",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "APIKEY",
    "API_KEY",
    "PRIVATE_KEY",
    "ACCESS_KEY",
    "CLIENT_SECRET",
    "AUTH",
    "CREDENTIAL",
)

_PLACEHOLDER_VALUES = {
    "",
    "changeme",
    "change-me",
    "your-secret-here",
    "todo",
    "xxx",
    "xxxx",
    "placeholder",
    "replace_me",
    "<your-key>",
    "example",
}


def looks_like_secret(key: str) -> bool:
    upper = key.upper()
    return any(hint in upper for hint in _SECRET_KEY_HINTS)


def _audit_secrets(values: Dict[str, str]) -> List[Finding]:
    """Flag secret-looking keys that are empty or hold obvious placeholders."""
    findings: List[Finding] = []
    for key, value in values.items():
        if not looks_like_secret(key):
            continue
        normalized = value.strip().lower()
        if value.strip() == "":
            findings.append(
                Finding(
                    rule="empty-secret",
                    severity=Severity.ERROR,
                    message=f"Secret {key!r} is present but empty",
                    key=key,
                )
            )
        elif normalized in _PLACEHOLDER_VALUES:
            findings.append(
                Finding(
                    rule="placeholder-secret",
                    severity=Severity.ERROR,
                    message=(
                        f"Secret {key!r} still holds a placeholder value "
                        f"({value!r})"
                    ),
                    key=key,
                )
            )
    return findings


# --------------------------------------------------------------------------- #
# Public operations
# --------------------------------------------------------------------------- #


def _read(path: str) -> str:
    """Read a file as UTF-8 text.

    Raises:
        FileNotFoundError: if the path does not exist.
        PermissionError: if the file cannot be read.
        UnicodeDecodeError: if the file is not valid UTF-8.
    """
    return Path(path).read_text(encoding="utf-8")


def lint_file(path: str) -> Report:
    """Lint a single .env file: structure + secret hygiene."""
    report = Report()
    try:
        text = _read(path)
    except FileNotFoundError:
        report.add(
            Finding(
                rule="file-not-found",
                severity=Severity.ERROR,
                message=f"File not found: {path}",
            )
        )
        return report
    except PermissionError:
        report.add(
            Finding(
                rule="permission-denied",
                severity=Severity.ERROR,
                message=f"Permission denied reading file: {path}",
            )
        )
        return report
    except UnicodeDecodeError:
        report.add(
            Finding(
                rule="not-utf8",
                severity=Severity.ERROR,
                message=f"File is not valid UTF-8 (is it binary?): {path}",
            )
        )
        return report

    values, structural = parse_env(text)
    for f in structural:
        report.add(f)
    for f in _audit_secrets(values):
        report.add(f)
    return report


def diff_env(example_path: str, env_path: str) -> Report:
    """Detect config drift between an example template and the real .env.

    Missing keys (in example, absent from env) are errors. Extra keys (in env,
    absent from example) are warnings -- they often signal stale config.
    """
    report = Report()
    try:
        example_vals, _ = parse_env(_read(example_path))
    except FileNotFoundError:
        report.add(
            Finding(
                rule="file-not-found",
                severity=Severity.ERROR,
                message=f"Example file not found: {example_path}",
            )
        )
        return report
    except (PermissionError, UnicodeDecodeError) as exc:
        report.add(
            Finding(
                rule="read-error",
                severity=Severity.ERROR,
                message=f"Cannot read example file {example_path}: {exc}",
            )
        )
        return report
    try:
        env_vals, _ = parse_env(_read(env_path))
    except FileNotFoundError:
        report.add(
            Finding(
                rule="file-not-found",
                severity=Severity.ERROR,
                message=f"Env file not found: {env_path}",
            )
        )
        return report
    except (PermissionError, UnicodeDecodeError) as exc:
        report.add(
            Finding(
                rule="read-error",
                severity=Severity.ERROR,
                message=f"Cannot read env file {env_path}: {exc}",
            )
        )
        return report

    for key in example_vals:
        if key not in env_vals:
            report.add(
                Finding(
                    rule="missing-key",
                    severity=Severity.ERROR,
                    message=(
                        f"Key {key!r} is declared in {example_path} "
                        f"but missing from {env_path}"
                    ),
                    key=key,
                )
            )
    for key in env_vals:
        if key not in example_vals:
            report.add(
                Finding(
                    rule="extra-key",
                    severity=Severity.WARNING,
                    message=(
                        f"Key {key!r} exists in {env_path} "
                        f"but is not documented in {example_path}"
                    ),
                    key=key,
                )
            )
    return report


_TYPE_VALIDATORS = {
    "string": lambda v: True,
    "int": lambda v: bool(re.fullmatch(r"[+-]?\d+", v)),
    "float": lambda v: bool(re.fullmatch(r"[+-]?\d+(?:\.\d+)?", v)),
    "bool": lambda v: v.lower() in ("true", "false", "1", "0", "yes", "no"),
    "url": lambda v: bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", v)),
    "port": lambda v: v.isdigit() and 0 < int(v) <= 65535,
}


def check_schema(schema_path: str, env_path: str) -> Report:
    """Validate a .env against a JSON schema describing required keys/types.

    Schema format::

        {
          "DATABASE_URL": {"required": true, "type": "url"},
          "PORT": {"required": true, "type": "port"},
          "DEBUG": {"type": "bool", "allowed": ["true", "false"]}
        }
    """
    report = Report()
    try:
        schema = json.loads(_read(schema_path))
    except FileNotFoundError:
        report.add(
            Finding(
                rule="file-not-found",
                severity=Severity.ERROR,
                message=f"Schema file not found: {schema_path}",
            )
        )
        return report
    except (PermissionError, UnicodeDecodeError) as exc:
        report.add(
            Finding(
                rule="read-error",
                severity=Severity.ERROR,
                message=f"Cannot read schema file {schema_path}: {exc}",
            )
        )
        return report
    except json.JSONDecodeError as exc:
        report.add(
            Finding(
                rule="invalid-schema",
                severity=Severity.ERROR,
                message=f"Schema is not valid JSON: {exc}",
            )
        )
        return report

    if not isinstance(schema, dict):
        report.add(
            Finding(
                rule="invalid-schema",
                severity=Severity.ERROR,
                message=(
                    f"Schema must be a JSON object (got {type(schema).__name__})"
                ),
            )
        )
        return report

    try:
        env_vals, _ = parse_env(_read(env_path))
    except FileNotFoundError:
        report.add(
            Finding(
                rule="file-not-found",
                severity=Severity.ERROR,
                message=f"Env file not found: {env_path}",
            )
        )
        return report
    except (PermissionError, UnicodeDecodeError) as exc:
        report.add(
            Finding(
                rule="read-error",
                severity=Severity.ERROR,
                message=f"Cannot read env file {env_path}: {exc}",
            )
        )
        return report

    for key, spec in schema.items():
        if not isinstance(spec, dict):
            report.add(
                Finding(
                    rule="invalid-schema",
                    severity=Severity.ERROR,
                    message=f"Schema entry for {key!r} must be an object",
                    key=key,
                )
            )
            continue

        required = bool(spec.get("required", False))
        present = key in env_vals

        if not present:
            if required:
                report.add(
                    Finding(
                        rule="required-missing",
                        severity=Severity.ERROR,
                        message=f"Required key {key!r} is missing from {env_path}",
                        key=key,
                    )
                )
            continue

        value = env_vals[key]
        expected_type = spec.get("type")
        if expected_type:
            validator = _TYPE_VALIDATORS.get(expected_type)
            if validator is None:
                report.add(
                    Finding(
                        rule="invalid-schema",
                        severity=Severity.ERROR,
                        message=f"Unknown type {expected_type!r} for key {key!r}",
                        key=key,
                    )
                )
            elif not validator(value):
                report.add(
                    Finding(
                        rule="type-mismatch",
                        severity=Severity.ERROR,
                        message=(
                            f"Key {key!r} value {value!r} "
                            f"is not a valid {expected_type}"
                        ),
                        key=key,
                    )
                )

        allowed = spec.get("allowed")
        if allowed and value not in allowed:
            report.add(
                Finding(
                    rule="value-not-allowed",
                    severity=Severity.ERROR,
                    message=(
                        f"Key {key!r} value {value!r} "
                        f"is not in allowed set {allowed}"
                    ),
                    key=key,
                )
            )

    return report
