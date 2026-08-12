"""Tests for the console entry point.

Every test patches ``analyze_pc``: the console must be provable without measuring the
machine it runs on, and a test suite has no business reading the real TEMP folder. What is
checked here is the contract around the analysis - argument validation, exit codes, stream
discipline, and the promise that nothing is written or asked unless the user said so.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import main
from src import history
from src.analyzer import PROGRESS_LABELS, MissingDependencyError
from src.health_score import calculate_health_details
from src.i18n import get_translator, translation_keys
from src.models import AnalysisData, SCHEMA_VERSION
from src.utils import GIB
from tests.helpers import make_analysis

START = datetime(2026, 7, 16, 12, 30, tzinfo=timezone.utc)

#: Options every run needs so the tests never depend on the machine locale or terminal.
BASE_ARGUMENTS = ("--lang", "en", "--color", "never")


def parse(*argv: str) -> argparse.Namespace:
    return main.build_parser().parse_args([*BASE_ARGUMENTS, *argv])


def snapshot(offset_hours: int = 0, **fields: object) -> AnalysisData:
    return replace(
        make_analysis(**fields),  # type: ignore[arg-type]
        analyzed_at=START + timedelta(hours=offset_hours),
    )


class CliTestCase(unittest.TestCase):
    """Runs the console with a patched analysis and captured streams."""

    def run_cli(self, *argv: str, data: AnalysisData | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with patch("main.analyze_pc", return_value=data if data is not None else snapshot()):
            with redirect_stdout(out), redirect_stderr(err):
                code = main.run(parse(*argv))
        return code, out.getvalue(), err.getvalue()

    def temp_folder(self) -> Path:
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        return Path(folder.name)


class ParserTests(unittest.TestCase):
    def test_documented_options_are_accepted(self) -> None:
        args = parse(
            "--cpu-sample-seconds", "0",
            "--top", "3",
            "--no-temp-scan",
            "--temp-scan-seconds", "2",
            "--no-startup",
            "--no-gpu",
            "--format", "json",
            "--export", "report.json",
            "--output", "other.json",
            "--no-prompt",
            "--redact",
            "--quiet",
            "--fail-under", "50",
            "--save-history",
            "--history-path", "history.jsonl",
            "--compare",
        )
        self.assertEqual(args.cpu_sample_seconds, 0.0)
        self.assertEqual(args.top, 3)
        self.assertTrue(args.no_temp_scan)
        self.assertEqual(args.temp_scan_seconds, 2.0)
        self.assertTrue(args.no_startup)
        self.assertTrue(args.no_gpu)
        self.assertEqual(args.format, "json")
        self.assertEqual(args.export, "report.json")
        self.assertEqual(args.output, "other.json")
        self.assertTrue(args.no_prompt)
        self.assertTrue(args.redact)
        self.assertTrue(args.quiet)
        self.assertEqual(args.fail_under, 50)
        self.assertTrue(args.save_history)
        self.assertEqual(args.history_path, "history.jsonl")
        self.assertTrue(args.compare)

    def test_defaults_are_safe(self) -> None:
        args = parse()
        self.assertIsNone(args.export)
        self.assertIsNone(args.output)
        self.assertIsNone(args.format)
        self.assertIsNone(args.fail_under)
        self.assertIsNone(args.show_history)
        self.assertFalse(args.save_history)
        self.assertFalse(args.redact)
        self.assertFalse(args.quiet)
        self.assertEqual(args.cpu_sample_seconds, 1.0)

    def test_bare_export_flag_marks_auto_naming(self) -> None:
        self.assertEqual(parse("--export").export, main.AUTO_EXPORT)

    def test_bare_show_history_defaults_to_ten(self) -> None:
        self.assertEqual(parse("--show-history").show_history, 10)
        self.assertEqual(parse("--show-history", "3").show_history, 3)

    def test_unknown_values_are_rejected(self) -> None:
        for argv in (
            ("--format", "pdf"),
            ("--lang", "de"),
            ("--color", "rainbow"),
            ("--top", "many"),
            ("--cpu-sample-seconds", "fast"),
            ("--unknown-flag",),
        ):
            with self.subTest(argv=argv):
                with redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as caught:
                        parse(*argv)
                self.assertEqual(caught.exception.code, 2)

    def test_version_flag_exits_cleanly(self) -> None:
        with redirect_stdout(io.StringIO()) as out:
            with self.assertRaises(SystemExit) as caught:
                parse("--version")
        self.assertEqual(caught.exception.code, 0)
        self.assertIn(main.APP_VERSION, out.getvalue())


class ExitCodeTests(CliTestCase):
    def test_successful_run_returns_zero(self) -> None:
        code, out, _ = self.run_cli("--no-prompt")
        self.assertEqual(code, 0)
        self.assertIn("Apoliak Vitals", out)
        self.assertIn("Score: 100/100", out)

    def test_missing_dependency_returns_one(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        with patch("main.analyze_pc", side_effect=MissingDependencyError("psutil is required")):
            with redirect_stdout(out), redirect_stderr(err):
                code = main.run(parse("--no-prompt"))
        self.assertEqual(code, 1)
        self.assertIn("psutil is required", err.getvalue())
        self.assertEqual(out.getvalue(), "")

    def test_unexpected_failure_returns_one(self) -> None:
        err = io.StringIO()
        with patch("main.analyze_pc", side_effect=RuntimeError("driver exploded")):
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = main.run(parse("--no-prompt"))
        self.assertEqual(code, 1)
        self.assertIn("driver exploded", err.getvalue())

    def test_invalid_cpu_interval_returns_two(self) -> None:
        for value in ("6", "-1"):
            with self.subTest(value=value):
                err = io.StringIO()
                with redirect_stderr(err):
                    code = main.run(parse("--cpu-sample-seconds", value))
                self.assertEqual(code, 2)
                self.assertIn("between 0 and 5", err.getvalue())

    def test_invalid_cpu_interval_never_starts_the_analysis(self) -> None:
        with patch("main.analyze_pc") as analyze:
            with redirect_stderr(io.StringIO()):
                code = main.run(parse("--cpu-sample-seconds", "9"))
        self.assertEqual(code, 2)
        analyze.assert_not_called()

    def test_invalid_threshold_returns_two(self) -> None:
        err = io.StringIO()
        with redirect_stderr(err):
            code = main.run(parse("--fail-under", "150"))
        self.assertEqual(code, 2)
        self.assertIn("between 0 and 100", err.getvalue())

    def test_score_below_threshold_returns_three(self) -> None:
        data = snapshot(cpu_percent=99, ram_percent=97)
        code, _, err = self.run_cli("--no-prompt", "--fail-under", "90", data=data)
        self.assertEqual(code, 3)
        self.assertIn("below the required minimum", err)

    def test_score_at_the_threshold_returns_zero(self) -> None:
        code, _, _ = self.run_cli("--no-prompt", "--fail-under", "100")
        self.assertEqual(code, 0)

    def test_namespace_from_an_older_caller_still_runs(self) -> None:
        # main._get() tolerates a partial Namespace; the v1.0 call shape must keep working.
        args = argparse.Namespace(export=None, no_prompt=True, cpu_sample_seconds=0.0, lang="en")
        out = io.StringIO()
        with patch("main.analyze_pc", return_value=snapshot()), redirect_stdout(out):
            code = main.run(args)
        self.assertEqual(code, 0)
        self.assertIn("Apoliak Vitals", out.getvalue())


class OutputModeTests(CliTestCase):
    def test_quiet_prints_exactly_one_line(self) -> None:
        code, out, _ = self.run_cli("--no-prompt", "--quiet")
        self.assertEqual(code, 0)
        lines = out.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith("Score: 100/100"))
        self.assertIn("Excellent", lines[0])

    def test_quiet_stays_quiet_while_exporting(self) -> None:
        destination = self.temp_folder() / "report.txt"
        code, out, _ = self.run_cli("--no-prompt", "--quiet", "--export", str(destination))
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertTrue(destination.exists())

    def test_json_format_prints_valid_json_on_stdout(self) -> None:
        code, out, _ = self.run_cli("--no-prompt", "--format", "json")
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertEqual(payload["health"]["score"], 100)

    def test_markdown_format_prints_on_stdout(self) -> None:
        code, out, _ = self.run_cli("--no-prompt", "--format", "markdown")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("# Apoliak Vitals"))

    def test_machine_readable_output_keeps_notes_off_stdout(self) -> None:
        path = self.temp_folder() / "history.jsonl"
        code, out, err = self.run_cli(
            "--no-prompt", "--format", "json", "--compare", "--history-path", str(path)
        )
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out))
        self.assertIn("No previous analysis", err)

    def test_color_never_emits_no_escape_codes(self) -> None:
        for argv in (("--no-prompt",), ("--no-prompt", "--quiet")):
            with self.subTest(argv=argv):
                _, out, _ = self.run_cli(*argv)
                self.assertNotIn("\x1b", out)

    def test_color_always_emits_escape_codes(self) -> None:
        out = io.StringIO()
        args = main.build_parser().parse_args(
            ["--lang", "en", "--color", "always", "--no-prompt", "--quiet"]
        )
        with patch("main.analyze_pc", return_value=snapshot()), redirect_stdout(out):
            main.run(args)
        self.assertIn("\x1b", out.getvalue())

    def test_language_option_switches_the_report(self) -> None:
        out = io.StringIO()
        args = main.build_parser().parse_args(
            ["--lang", "sk", "--color", "never", "--no-prompt"]
        )
        with patch("main.analyze_pc", return_value=snapshot()), redirect_stdout(out):
            main.run(args)
        self.assertIn("--- SYSTÉM ---", out.getvalue())

    def test_redact_masks_the_account_name(self) -> None:
        account = "testaccount"
        data = replace(snapshot(), temp_path=rf"C:\Users\{account}\AppData\Local\Temp")
        with patch.dict(os.environ, {"USERNAME": account}):
            code, out, _ = self.run_cli("--no-prompt", "--redact", data=data)
        self.assertEqual(code, 0)
        self.assertNotIn(account, out)


class PromptTests(CliTestCase):
    def test_no_prompt_never_reads_stdin(self) -> None:
        with patch("main._isatty", return_value=True), patch("builtins.input") as ask:
            code, _, _ = self.run_cli("--no-prompt")
        self.assertEqual(code, 0)
        ask.assert_not_called()

    def test_declined_prompt_writes_nothing(self) -> None:
        folder = self.temp_folder()
        previous = Path.cwd()
        os.chdir(folder)
        self.addCleanup(os.chdir, previous)
        with patch("main._isatty", return_value=True), patch("builtins.input", return_value="n"):
            code, _, _ = self.run_cli()
        self.assertEqual(code, 0)
        self.assertEqual(list(folder.iterdir()), [])

    def test_cancelled_prompt_writes_nothing(self) -> None:
        folder = self.temp_folder()
        previous = Path.cwd()
        os.chdir(folder)
        self.addCleanup(os.chdir, previous)
        with patch("main._isatty", return_value=True):
            with patch("builtins.input", side_effect=EOFError):
                code, out, _ = self.run_cli()
        self.assertEqual(code, 0)
        self.assertIn("Cancelled", out)
        self.assertEqual(list(folder.iterdir()), [])

    def test_accepted_prompt_writes_into_the_working_folder(self) -> None:
        folder = self.temp_folder()
        previous = Path.cwd()
        os.chdir(folder)
        self.addCleanup(os.chdir, previous)
        with patch("main._isatty", return_value=True), patch("builtins.input", return_value="y"):
            code, out, _ = self.run_cli()
        self.assertEqual(code, 0)
        written = list(folder.iterdir())
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0].suffix, ".txt")
        self.assertIn("Report saved to:", out)


class ExportTests(CliTestCase):
    def test_export_writes_to_the_requested_file(self) -> None:
        destination = self.temp_folder() / "result.txt"
        code, out, _ = self.run_cli("--no-prompt", "--export", str(destination))
        self.assertEqual(code, 0)
        self.assertTrue(destination.exists())
        self.assertIn("Report saved to:", out)
        self.assertIn("Apoliak Vitals", destination.read_text(encoding="utf-8"))

    def test_export_infers_the_format_from_the_extension(self) -> None:
        destination = self.temp_folder() / "result.json"
        code, _, _ = self.run_cli("--no-prompt", "--export", str(destination))
        self.assertEqual(code, 0)
        payload = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)

    def test_output_option_implies_export(self) -> None:
        destination = self.temp_folder() / "explicit.md"
        code, _, _ = self.run_cli("--no-prompt", "--output", str(destination))
        self.assertEqual(code, 0)
        self.assertTrue(destination.read_text(encoding="utf-8").startswith("# Apoliak"))

    def test_export_into_a_folder_uses_an_automatic_name(self) -> None:
        folder = self.temp_folder()
        code, _, _ = self.run_cli("--no-prompt", "--export", str(folder), "--format", "html")
        self.assertEqual(code, 0)
        written = list(folder.iterdir())
        self.assertEqual(len(written), 1)
        self.assertEqual(written[0].suffix, ".html")

    def test_failed_export_returns_one(self) -> None:
        blocked = self.temp_folder() / "folder-in-the-way"
        blocked.mkdir()
        (blocked / "occupied.txt").write_text("busy", encoding="utf-8")
        err = io.StringIO()
        out = io.StringIO()
        with patch("main.analyze_pc", return_value=snapshot()):
            with patch("main.exporters.export", side_effect=OSError("permission denied")):
                with redirect_stdout(out), redirect_stderr(err):
                    code = main.run(parse("--no-prompt", "--export", str(blocked / "x.txt")))
        self.assertEqual(code, 1)
        self.assertIn("permission denied", err.getvalue())

    def test_export_honours_redaction(self) -> None:
        account = "testaccount"
        destination = self.temp_folder() / "masked.txt"
        data = replace(snapshot(), temp_path=rf"C:\Users\{account}\AppData\Local\Temp")
        with patch.dict(os.environ, {"USERNAME": account}):
            code, _, _ = self.run_cli(
                "--no-prompt", "--redact", "--export", str(destination), data=data
            )
        self.assertEqual(code, 0)
        self.assertNotIn(account, destination.read_text(encoding="utf-8"))


class HistoryOptionTests(CliTestCase):
    def setUp(self) -> None:
        self.path = self.temp_folder() / "history.jsonl"

    def store(self, data: AnalysisData) -> None:
        history.append_snapshot(data, calculate_health_details(data), path=self.path)

    def test_history_is_not_written_unless_requested(self) -> None:
        code, _, _ = self.run_cli("--no-prompt", "--history-path", str(self.path))
        self.assertEqual(code, 0)
        self.assertFalse(self.path.exists())

    def test_save_history_appends_one_run(self) -> None:
        code, out, _ = self.run_cli(
            "--no-prompt", "--save-history", "--history-path", str(self.path)
        )
        self.assertEqual(code, 0)
        self.assertIn("History updated:", out)
        self.assertEqual(len(history.load_history(path=self.path)), 1)

    def test_show_history_lists_stored_runs(self) -> None:
        self.store(snapshot(0, cpu_percent=11, ram_percent=22, disk_free=100 * GIB))
        self.store(snapshot(1, cpu_percent=33))
        out = io.StringIO()
        with patch("main.analyze_pc") as analyze:
            with redirect_stdout(out):
                code = main.run(parse("--show-history", "--history-path", str(self.path)))
        self.assertEqual(code, 0)
        analyze.assert_not_called()  # Listing history never measures the machine.
        text = out.getvalue()
        self.assertIn("History file:", text)
        self.assertIn("2026-07-16 12:30", text)
        self.assertIn("2026-07-16 13:30", text)
        self.assertIn("Excellent", text)

    def test_show_history_reports_an_empty_store(self) -> None:
        out = io.StringIO()
        with redirect_stdout(out):
            code = main.run(parse("--show-history", "--history-path", str(self.path)))
        self.assertEqual(code, 0)
        self.assertIn("No previous analysis", out.getvalue())
        self.assertFalse(self.path.exists())

    def test_show_history_honours_the_limit(self) -> None:
        for offset in range(4):
            self.store(snapshot(offset))
        out = io.StringIO()
        with redirect_stdout(out):
            main.run(parse("--show-history", "2", "--history-path", str(self.path)))
        rows = [line for line in out.getvalue().splitlines() if line.startswith("2026-")]
        self.assertEqual(len(rows), 2)

    def test_compare_reports_the_change(self) -> None:
        self.store(snapshot(0, cpu_percent=10, ram_percent=20, disk_free=100 * GIB))
        current = snapshot(1, cpu_percent=40, ram_percent=30, disk_free=90 * GIB)
        code, out, _ = self.run_cli(
            "--no-prompt", "--compare", "--history-path", str(self.path), data=current
        )
        self.assertEqual(code, 0)
        self.assertIn("Compared with the previous analysis (2026-07-16 12:30)", out)
        self.assertIn("CPU usage: +30.0 pp", out)
        self.assertIn("RAM usage: +10.0 pp", out)
        self.assertIn("Free disk space: -10.0 GB", out)

    def test_compare_without_history_says_so(self) -> None:
        code, out, _ = self.run_cli(
            "--no-prompt", "--compare", "--history-path", str(self.path)
        )
        self.assertEqual(code, 0)
        self.assertIn("No previous analysis", out)

    def test_compare_uses_the_run_before_this_one(self) -> None:
        # Saving and comparing in the same run must not compare a run with itself.
        self.store(snapshot(0, cpu_percent=10))
        current = snapshot(1, cpu_percent=10)
        code, out, _ = self.run_cli(
            "--no-prompt",
            "--compare",
            "--save-history",
            "--history-path",
            str(self.path),
            data=current,
        )
        self.assertEqual(code, 0)
        self.assertIn("Compared with the previous analysis (2026-07-16 12:30)", out)
        self.assertEqual(len(history.load_history(path=self.path)), 2)


class AnalysisArgumentTests(CliTestCase):
    def test_options_reach_the_collector(self) -> None:
        with patch("main.analyze_pc", return_value=snapshot()) as analyze:
            with redirect_stdout(io.StringIO()):
                main.run(
                    parse(
                        "--no-prompt",
                        "--cpu-sample-seconds", "0",
                        "--top", "3",
                        "--no-temp-scan",
                        "--temp-scan-seconds", "4",
                        "--no-startup",
                        "--no-gpu",
                    )
                )
        kwargs = analyze.call_args.kwargs
        self.assertEqual(kwargs["cpu_interval"], 0.0)
        self.assertEqual(kwargs["top_process_limit"], 3)
        self.assertFalse(kwargs["scan_temp"])
        self.assertEqual(kwargs["temp_scan_seconds"], 4.0)
        self.assertFalse(kwargs["include_startup"])
        self.assertFalse(kwargs["include_gpu"])
        self.assertTrue(callable(kwargs["progress"]))

    def test_progress_callback_is_harmless_when_disabled(self) -> None:
        captured: list[object] = []

        def collect(**kwargs: object) -> AnalysisData:
            progress = kwargs["progress"]
            assert callable(progress)
            progress("cpu", 0.5)  # A step key, which is what analyze_pc passes.
            captured.append(progress)
            return snapshot()

        with patch("main.analyze_pc", side_effect=collect):
            with redirect_stdout(io.StringIO()) as out:
                code = main.run(parse("--no-prompt", "--quiet"))
        self.assertEqual(code, 0)
        self.assertEqual(len(out.getvalue().splitlines()), 1)


class ConsoleLanguageTests(unittest.TestCase):
    """--lang has to reach the parts of the console argparse builds before run() exists."""

    def test_the_language_is_read_from_the_command_line_before_parsing(self) -> None:
        # argparse cannot answer this: it prints the help the parser was built with, so the
        # language must be known before the parser exists.
        for argv, expected in (
            (["--lang", "sk"], "sk"),
            (["--lang=sk"], "sk"),
            (["--no-prompt", "--lang", "en"], "en"),
            (["--lang", "sk", "--lang", "en"], "en"),  # Last wins, exactly like argparse.
            (["--lang", "de"], None),  # Not shipped: left for argparse to reject.
            (["--lang"], None),
            (["--no-prompt"], None),
        ):
            with self.subTest(argv=argv):
                self.assertEqual(main._requested_language(argv), expected)

    def test_slovak_help_is_actually_slovak(self) -> None:
        slovak = main.build_parser("sk").format_help()
        english = main.build_parser("en").format_help()
        self.assertNotEqual(slovak, english)
        self.assertIn("Bezpečne", slovak)  # Description.
        self.assertIn("analýza", slovak)  # Argument group.
        self.assertIn("výstup", slovak)
        self.assertIn("história", slovak)

    def test_slovak_help_translates_the_option_descriptions(self) -> None:
        slovak = main.build_parser("sk").format_help()
        for fragment in (
            "dĺžka merania procesora",  # --cpu-sample-seconds
            "skryť meno používateľa",  # --redact
            "vypísať verziu programu",  # --version
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, slovak)

    def test_the_command_line_language_reaches_the_help_text(self) -> None:
        with patch.object(main.sys, "argv", ["main.py", "--lang", "sk"]):
            self.assertIn("Bezpečne", main.build_parser().format_help())

    def test_english_help_stays_english(self) -> None:
        english = main.build_parser("en").format_help()
        self.assertIn("Safely analyze", english)
        self.assertIn("analysis", english)
        self.assertNotIn("Bezpečne", english)


class TranslatedProgressLineTests(unittest.TestCase):
    """The steps of a running analysis belong to the chosen language too.

    analyze_pc used to hand the callback English prose, so "--lang sk" printed Slovak help,
    a Slovak report - and English progress. It passes a step key now, and the console is
    where that key becomes a sentence.
    """

    def line(self, language: str, step_key: str, fraction: float = 0.25) -> str:
        stream = io.StringIO()
        indicator = main._ProgressLine(stream, get_translator(language), enabled=True)
        indicator.update(step_key, fraction)
        return stream.getvalue()

    def test_a_slovak_run_shows_slovak_steps(self) -> None:
        text = self.line("sk", "cpu")
        self.assertIn(get_translator("sk").t("progress.cpu"), text)
        self.assertNotIn(PROGRESS_LABELS["cpu"], text)
        self.assertIn("[ 25%]", text)

    def test_an_english_run_shows_the_english_label(self) -> None:
        self.assertIn(PROGRESS_LABELS["cpu"], self.line("en", "cpu"))

    def test_every_step_the_analyzer_reports_is_translated(self) -> None:
        slovak = get_translator("sk")
        for key, english in PROGRESS_LABELS.items():
            with self.subTest(step=key):
                text = self.line("sk", key)
                self.assertIn(slovak.t(f"progress.{key}"), text)
                self.assertNotIn(english, text)

    def test_the_catalogue_ships_no_step_that_is_never_reported(self) -> None:
        # Both directions, because a translated step nobody emits is dead weight and a step
        # nobody translated is an English line in a Slovak run.
        for language in ("en", "sk"):
            shipped = {
                key.split(".", 1)[1]
                for key in translation_keys(language)
                if key.startswith("progress.")
            }
            with self.subTest(language=language):
                self.assertEqual(shipped, set(PROGRESS_LABELS))

    def test_a_step_the_catalogue_does_not_know_still_reads_in_english(self) -> None:
        # PROGRESS_LABELS is the fallback, so a newer analyzer paired with an older
        # catalogue prints a readable English step instead of a bare key.
        with patch.dict(main.PROGRESS_LABELS, {"future_step": "Doing something new"}):
            self.assertIn("Doing something new", self.line("sk", "future_step"))

    def test_a_step_nobody_can_name_prints_the_key_rather_than_nothing(self) -> None:
        self.assertIn("mystery", self.line("sk", "mystery"))

    def test_a_slovak_run_prints_slovak_steps_end_to_end(self) -> None:
        # The unit assertions above prove the indicator translates a key. This one proves the
        # console really hands analyze_pc that indicator, and that a key travelling the whole
        # way out of the collector reaches the terminal in the language the user asked for.
        slovak = get_translator("sk")
        seen: list[tuple[str, float]] = []

        def analysis(**kwargs: object) -> AnalysisData:
            report = kwargs["progress"]
            assert callable(report)
            for key in PROGRESS_LABELS:
                seen.append((key, 0.5))
                report(key, 0.5)
            return snapshot()

        out = io.StringIO()
        args = main.build_parser().parse_args(["--lang", "sk", "--color", "never", "--no-prompt"])
        with patch("main.analyze_pc", side_effect=analysis):
            with patch("main._isatty", return_value=True):  # The indicator is for terminals.
                with redirect_stdout(out):
                    self.assertEqual(main.run(args), 0)

        printed = out.getvalue()
        self.assertEqual([key for key, _ in seen], list(PROGRESS_LABELS))
        for key, english in PROGRESS_LABELS.items():
            with self.subTest(step=key):
                self.assertIn(slovak.t(f"progress.{key}")[:40], printed)
                self.assertNotIn(english, printed)

    def test_a_progress_callback_that_raises_never_reaches_the_user(self) -> None:
        # main hands analyze_pc a bound method; a console that dies mid-write must cost the
        # indicator, not the run. The analyzer's own guard is tested in test_analyzer.
        class BrokenStream(io.StringIO):
            def write(self, text: str) -> int:
                raise OSError("the console went away")

        indicator = main._ProgressLine(BrokenStream(), get_translator("sk"), enabled=True)
        for key in PROGRESS_LABELS:
            indicator.update(key, 0.5)  # Must not raise, at any step.

    def test_a_console_that_rejects_the_write_disables_the_indicator(self) -> None:
        class BrokenStream(io.StringIO):
            def write(self, text: str) -> int:
                raise OSError("the console went away")

        indicator = main._ProgressLine(BrokenStream(), get_translator("en"), enabled=True)
        indicator.update("cpu", 0.5)  # Progress output is never worth a lost analysis.
        indicator.clear()


class TranslatedHistoryTableTests(CliTestCase):
    """--show-history prints a table; its header is part of the chosen language too."""

    def setUp(self) -> None:
        self.path = self.temp_folder() / "history.jsonl"
        data = snapshot(0, cpu_percent=11, ram_percent=22, disk_free=100 * GIB)
        history.append_snapshot(data, calculate_health_details(data), path=self.path)

    def show(self, language: str) -> str:
        out = io.StringIO()
        args = main.build_parser().parse_args(
            ["--lang", language, "--color", "never", "--show-history",
             "--history-path", str(self.path)]
        )
        with redirect_stdout(out):
            self.assertEqual(main.run(args), 0)
        return out.getvalue()

    def test_the_slovak_table_has_a_slovak_header(self) -> None:
        text = self.show("sk")
        for header in ("Dátum analýzy", "Skóre", "Stav", "Procesor", "Pamäť", "Voľné miesto"):
            with self.subTest(header=header):
                self.assertIn(header, text)

    def test_the_slovak_run_translates_the_surrounding_lines_too(self) -> None:
        text = self.show("sk")
        self.assertIn("Súbor histórie:", text)
        self.assertNotIn("History file:", text)
        # The stored status is translated as well, not printed as the raw English band.
        self.assertIn(get_translator("sk").t("status.excellent"), text)
        self.assertNotIn("Excellent", text)

    def test_the_english_table_keeps_the_english_header(self) -> None:
        text = self.show("en")
        self.assertIn("Analysis Date", text)
        self.assertIn("History file:", text)
        self.assertNotIn("Dátum analýzy", text)

    def test_an_empty_store_is_reported_in_the_chosen_language(self) -> None:
        empty = self.temp_folder() / "none.jsonl"
        out = io.StringIO()
        args = main.build_parser().parse_args(
            ["--lang", "sk", "--show-history", "--history-path", str(empty)]
        )
        with redirect_stdout(out):
            main.run(args)
        self.assertIn("Zatiaľ nie je uložená", out.getvalue())


class RendererFailureTests(CliTestCase):
    """A defect in a renderer is a failed run, never a traceback in the user's console."""

    STANDARD_MESSAGE = "Analysis failed safely"

    def failing_run(self, *argv: str, target: str, error: BaseException) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with patch("main.analyze_pc", return_value=snapshot()):
            with patch(target, side_effect=error):
                with redirect_stdout(out), redirect_stderr(err):
                    code = main.run(parse(*argv))
        return code, out.getvalue(), err.getvalue()

    def test_a_renderer_that_raises_type_error_ends_the_run_cleanly(self) -> None:
        code, _, err = self.failing_run(
            "--no-prompt", "--format", "json",
            target="src.exporters.render", error=TypeError("renderer defect"),
        )
        self.assertEqual(code, 1)
        self.assertIn(self.STANDARD_MESSAGE, err)
        self.assertNotIn("Traceback", err)

    def test_the_plain_text_builder_is_covered_the_same_way(self) -> None:
        code, _, err = self.failing_run(
            "--no-prompt", target="main.build_report", error=TypeError("renderer defect")
        )
        self.assertEqual(code, 1)
        self.assertIn(self.STANDARD_MESSAGE, err)

    def test_a_failing_export_writer_also_returns_one(self) -> None:
        folder = self.temp_folder()
        code, _, err = self.failing_run(
            "--no-prompt", "--output", str(folder / "report.html"),
            target="src.exporters.export", error=TypeError("renderer defect"),
        )
        self.assertEqual(code, 1)
        self.assertIn(self.STANDARD_MESSAGE, err)
        self.assertFalse(list(folder.iterdir()))

    def test_the_scoring_stage_is_covered_too(self) -> None:
        code, _, err = self.failing_run(
            "--no-prompt", target="main.generate_recommendations", error=TypeError("defect")
        )
        self.assertEqual(code, 1)
        self.assertIn(self.STANDARD_MESSAGE, err)

    def test_an_unknown_format_is_still_rejected_with_exit_code_two(self) -> None:
        # A bad format name is a user error, not a renderer defect, and never reaches run().
        args = parse("--no-prompt")
        args.format = "pdf"
        err = io.StringIO()
        with patch("main.analyze_pc", return_value=snapshot()) as analyze:
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                code = main.run(args)
        self.assertEqual(code, 2)
        analyze.assert_not_called()
        self.assertIn("unknown export format", err.getvalue())


class AutomaticExportNameTests(CliTestCase):
    """Two runs inside the same second must not overwrite each other's report."""

    def run_in(self, folder: Path, *argv: str) -> int:
        previous = Path.cwd()
        os.chdir(folder)
        try:
            with patch("main.analyze_pc", return_value=snapshot()):
                with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    return main.run(parse(*argv))
        finally:
            os.chdir(previous)

    def test_two_automatic_exports_produce_two_files(self) -> None:
        folder = self.temp_folder()
        with patch("src.exporters.default_filename", return_value="report.txt"):
            self.assertEqual(self.run_in(folder, "--no-prompt", "--export"), 0)
            self.assertEqual(self.run_in(folder, "--no-prompt", "--export"), 0)
        self.assertEqual(
            sorted(item.name for item in folder.iterdir()), ["report.txt", "report_2.txt"]
        )

    def test_the_accepted_prompt_uses_the_same_protection(self) -> None:
        # The interactive "Export this report?" path generates its own name too, so it
        # needs the same guard as --export.
        folder = self.temp_folder()
        with patch("src.exporters.default_filename", return_value="report.txt"):
            with patch("main._may_prompt", return_value=True), patch(
                "main._ask_to_export", return_value=True
            ):
                self.assertEqual(self.run_in(folder), 0)
                self.assertEqual(self.run_in(folder), 0)
        self.assertEqual(
            sorted(item.name for item in folder.iterdir()), ["report.txt", "report_2.txt"]
        )

    def test_an_explicit_output_path_still_overwrites(self) -> None:
        folder = self.temp_folder()
        target = folder / "chosen.txt"
        target.write_text("older content", encoding="utf-8")
        self.assertEqual(self.run_in(folder, "--no-prompt", "--output", str(target)), 0)
        self.assertEqual([item.name for item in folder.iterdir()], ["chosen.txt"])
        self.assertNotIn("older content", target.read_text(encoding="utf-8"))

    def test_an_explicit_export_path_is_not_renamed_either(self) -> None:
        folder = self.temp_folder()
        target = folder / "report.json"
        self.assertEqual(self.run_in(folder, "--no-prompt", "--export", str(target)), 0)
        self.assertEqual(self.run_in(folder, "--no-prompt", "--export", str(target)), 0)
        self.assertEqual([item.name for item in folder.iterdir()], ["report.json"])
        self.assertTrue(json.loads(target.read_text(encoding="utf-8")))


if __name__ == "__main__":
    unittest.main()
