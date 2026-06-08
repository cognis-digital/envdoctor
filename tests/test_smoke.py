"""Smoke tests for ENVDOCTOR. Standard library only; no network."""
import json
import unittest

from envdoctor import (
    TOOL_NAME,
    TOOL_VERSION,
    Severity,
    parse_env,
    lint_file,
    diff_env,
    check_schema,
)
from envdoctor.cli import main


def _write(tmpdir, name, text):
    p = tmpdir / name
    p.write_text(text, encoding="utf-8")
    return str(p)


class TestMetadata(unittest.TestCase):
    def test_exports(self):
        self.assertEqual(TOOL_NAME, "envdoctor")
        self.assertTrue(TOOL_VERSION)


class TestParse(unittest.TestCase):
    def test_parses_and_strips_quotes(self):
        vals, findings = parse_env('FOO="bar"\nexport BAZ=qux  # note\n')
        self.assertEqual(vals["FOO"], "bar")
        self.assertEqual(vals["BAZ"], "qux")
        self.assertEqual(findings, [])

    def test_duplicate_key_is_error(self):
        _, findings = parse_env("A=1\nA=2\n")
        rules = [f.rule for f in findings]
        self.assertIn("duplicate-key", rules)
        self.assertTrue(any(f.severity is Severity.ERROR for f in findings))

    def test_malformed_line(self):
        _, findings = parse_env("this is not valid\n")
        self.assertEqual(findings[0].rule, "malformed-line")

    def test_lowercase_key_warns(self):
        _, findings = parse_env("lower=1\n")
        self.assertEqual(findings[0].rule, "lowercase-key")
        self.assertIs(findings[0].severity, Severity.WARNING)


class TestLint(unittest.TestCase):
    def setUp(self):
        import tempfile
        import pathlib

        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_empty_secret_is_error(self):
        path = _write(self.tmp, ".env", "API_TOKEN=\n")
        report = lint_file(path)
        self.assertFalse(report.ok)
        self.assertIn("empty-secret", [f.rule for f in report.findings])

    def test_placeholder_secret_is_error(self):
        path = _write(self.tmp, ".env", "DB_PASSWORD=changeme\n")
        report = lint_file(path)
        self.assertFalse(report.ok)
        self.assertIn("placeholder-secret", [f.rule for f in report.findings])

    def test_clean_file_is_ok(self):
        path = _write(self.tmp, ".env", "API_TOKEN=sk-live-abc123\nPORT=8080\n")
        report = lint_file(path)
        self.assertTrue(report.ok)

    def test_missing_file(self):
        report = lint_file(str(self.tmp / "nope.env"))
        self.assertFalse(report.ok)
        self.assertEqual(report.findings[0].rule, "file-not-found")


class TestDrift(unittest.TestCase):
    def setUp(self):
        import tempfile
        import pathlib

        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_missing_and_extra_keys(self):
        example = _write(self.tmp, ".env.example", "A=1\nB=2\n")
        env = _write(self.tmp, ".env", "A=1\nC=3\n")
        report = diff_env(example, env)
        rules = {(f.rule, f.key) for f in report.findings}
        self.assertIn(("missing-key", "B"), rules)
        self.assertIn(("extra-key", "C"), rules)
        self.assertFalse(report.ok)  # missing key is an error

    def test_aligned_is_ok(self):
        example = _write(self.tmp, ".env.example", "A=1\n")
        env = _write(self.tmp, ".env", "A=9\n")
        self.assertTrue(diff_env(example, env).ok)


class TestSchema(unittest.TestCase):
    def setUp(self):
        import tempfile
        import pathlib

        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_required_missing_and_type_mismatch(self):
        schema = _write(
            self.tmp,
            "env.schema.json",
            json.dumps(
                {
                    "DATABASE_URL": {"required": True, "type": "url"},
                    "PORT": {"required": True, "type": "port"},
                }
            ),
        )
        env = _write(self.tmp, ".env", "PORT=not-a-number\n")
        report = check_schema(schema, env)
        rules = {f.rule for f in report.findings}
        self.assertIn("required-missing", rules)
        self.assertIn("type-mismatch", rules)
        self.assertFalse(report.ok)

    def test_allowed_set(self):
        schema = _write(
            self.tmp,
            "env.schema.json",
            json.dumps({"DEBUG": {"allowed": ["true", "false"]}}),
        )
        env = _write(self.tmp, ".env", "DEBUG=maybe\n")
        report = check_schema(schema, env)
        self.assertIn("value-not-allowed", [f.rule for f in report.findings])

    def test_valid_passes(self):
        schema = _write(
            self.tmp,
            "env.schema.json",
            json.dumps({"PORT": {"required": True, "type": "port"}}),
        )
        env = _write(self.tmp, ".env", "PORT=8080\n")
        self.assertTrue(check_schema(schema, env).ok)


class TestCli(unittest.TestCase):
    def setUp(self):
        import tempfile
        import pathlib

        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_lint_exit_codes(self):
        bad = _write(self.tmp, ".env", "API_TOKEN=changeme\n")
        good = _write(self.tmp, "good.env", "API_TOKEN=sk-real\n")
        self.assertEqual(main(["lint", bad]), 1)
        self.assertEqual(main(["lint", good]), 0)

    def test_json_format(self):
        good = _write(self.tmp, ".env", "PORT=8080\n")
        # Should not raise and should exit 0 on a clean file.
        self.assertEqual(main(["--format", "json", "lint", good]), 0)

    def test_version_exits_zero(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
