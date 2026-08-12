"""Tests for the formatting, redaction, scanning and colour helpers in src/utils.py."""

from __future__ import annotations

import io
import os
import tempfile
import unittest
from pathlib import Path
from typing import Callable
from unittest.mock import patch

from src.utils import (
    DEFAULT_SCAN_SECONDS,
    GIB,
    KIB,
    MIB,
    TIB,
    Ansi,
    bytes_to_gb,
    format_bytes,
    format_count,
    format_duration,
    format_frequency,
    format_percent,
    format_uptime,
    redact_text,
    safe_get_folder_size,
    scan_folder,
    supports_color,
)


def make_clock(step: float = 1.0) -> Callable[[], float]:
    """A monotonic stand-in that advances by ``step`` on every call, starting at 0.0."""
    state = {"value": -step}

    def clock() -> float:
        state["value"] += step
        return state["value"]

    return clock


class FakeStream:
    """Minimal stdout stand-in; ``isatty`` can answer or blow up."""

    def __init__(self, tty: bool | Exception) -> None:
        self._tty = tty

    def isatty(self) -> bool:
        if isinstance(self._tty, Exception):
            raise self._tty
        return self._tty


class UnitConstantTests(unittest.TestCase):
    def test_binary_units_are_powers_of_1024(self) -> None:
        self.assertEqual((KIB, MIB, GIB, TIB), (1024, 1024**2, 1024**3, 1024**4))

    def test_default_scan_budget_is_positive(self) -> None:
        self.assertGreater(DEFAULT_SCAN_SECONDS, 0)


class FormatHelpersTests(unittest.TestCase):
    def test_bytes_to_gb(self) -> None:
        self.assertEqual(bytes_to_gb(2 * GIB), 2.0)
        self.assertEqual(bytes_to_gb(0), 0.0)
        self.assertEqual(bytes_to_gb(-GIB), -1.0)
        self.assertIsNone(bytes_to_gb(None))

    def test_format_bytes(self) -> None:
        cases = {
            None: "N/A",
            0: "0 B",
            -5: "0 B",  # A negative size is impossible; it is floored, never shown as "-5 B".
            1023: "1023 B",
            1024: "1.0 KB",
            1536: "1.5 KB",
            MIB: "1.0 MB",
            3 * GIB: "3.0 GB",
            TIB: "1.0 TB",
            5000 * TIB: "5000.0 TB",  # Beyond TB the unit stops growing, the number does not.
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(format_bytes(value), expected)

    def test_format_percent_is_clamped(self) -> None:
        cases = {None: "N/A", -10: "0%", 0: "0%", 42.4: "42%", 99.6: "100%", 110: "100%"}
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(format_percent(value), expected)

    def test_format_uptime(self) -> None:
        cases = {
            None: "N/A",
            0: "0m",
            -100: "0m",
            59: "0m",
            60: "1m",
            3600: "1h 0m",
            12 * 3600 + 45 * 60: "12h 45m",
            86400: "1d 0h 0m",
            2 * 86400 + 3 * 3600 + 4 * 60: "2d 3h 4m",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(format_uptime(value), expected)

    def test_format_frequency(self) -> None:
        cases = {
            None: "N/A",
            0: "N/A",  # A zero clock is "unknown", not "stopped".
            -100: "N/A",
            800: "800 MHz",
            999.4: "999 MHz",
            1000: "1.00 GHz",
            2400: "2.40 GHz",
            3600.0: "3.60 GHz",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(format_frequency(value), expected)

    def test_format_count(self) -> None:
        cases = {None: "N/A", 0: "0", 42: "42", 1000: "1 000", 1234567: "1 234 567", -5: "-5"}
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(format_count(value), expected)

    def test_format_duration(self) -> None:
        cases = {
            None: "N/A",
            0: "0.0 s",
            -3: "0.0 s",
            0.25: "0.2 s",
            12.34: "12.3 s",
            59.9: "59.9 s",
            60: "1m",
            3600: "1h 0m",
            3725: "1h 2m",
            7260: "2h 1m",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(format_duration(value), expected)


class RedactionTests(unittest.TestCase):
    def test_empty_values_pass_through(self) -> None:
        self.assertIsNone(redact_text(None, username="alexp"))
        self.assertEqual(redact_text("", username="alexp"), "")

    def test_profile_folder_is_masked(self) -> None:
        self.assertEqual(
            redact_text(r"C:\Users\alexp\AppData\Local\Temp", username="alexp"),
            r"C:\Users\<user>\AppData\Local\Temp",
        )

    def test_profile_folder_is_masked_without_a_known_username(self) -> None:
        # The path pattern alone is enough; no environment lookup is involved.
        self.assertEqual(
            redact_text(r"d:\users\someoneelse\Downloads", username=""),
            r"d:\users\<user>\Downloads",
        )

    def test_account_name_is_masked_anywhere_and_case_insensitively(self) -> None:
        self.assertEqual(
            redact_text("Owner: ALEXP (alexp)", username="alexp"), "Owner: <user> (<user>)"
        )

    def test_short_account_names_are_left_alone(self) -> None:
        # Masking a two-letter name would shred unrelated words.
        self.assertEqual(redact_text("an about ab", username="ab"), "an about ab")

    def test_regex_metacharacters_in_the_account_name_are_escaped(self) -> None:
        self.assertEqual(redact_text("x a.b+c y", username="a.b+c"), "x <user> y")

    def test_unrelated_text_is_untouched(self) -> None:
        self.assertEqual(redact_text("Windows 11 Pro", username="alexp"), "Windows 11 Pro")


class ScanFolderTests(unittest.TestCase):
    def test_nested_tree_is_measured_completely(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "one.bin").write_bytes(b"a" * 10)
            (root / "nested").mkdir()
            (root / "nested" / "two.bin").write_bytes(b"b" * 25)
            (root / "nested" / "deep").mkdir()
            (root / "nested" / "deep" / "three.bin").write_bytes(b"c" * 5)
            self.assertEqual(scan_folder(root), (40, 3, False))
            self.assertEqual(safe_get_folder_size(root), 40)

    def test_empty_and_missing_folders(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(scan_folder(folder), (0, 0, False))
            self.assertEqual(scan_folder(Path(folder) / "missing"), (0, 0, False))
            self.assertEqual(safe_get_folder_size(Path(folder) / "missing"), 0)

    def test_a_file_path_measures_that_single_file(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "single.bin"
            target.write_bytes(b"x" * 17)
            self.assertEqual(scan_folder(target), (17, 1, False))

    def test_time_budget_marks_the_result_truncated(self) -> None:
        # The clock is only consulted every 512th entry, so the tree has to be that big.
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index in range(600):
                (root / f"f{index:04d}.bin").write_bytes(b"z")
            total, files, truncated = scan_folder(root, max_seconds=0.0, monotonic=make_clock())
            self.assertTrue(truncated)
            self.assertLess(files, 600)
            self.assertEqual(total, files)

    def test_no_budget_never_truncates(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index in range(600):
                (root / f"f{index:04d}.bin").write_bytes(b"z")
            measured = scan_folder(root, max_seconds=None, monotonic=make_clock())
            self.assertEqual(measured, (600, 600, False))

    def test_non_callable_clock_falls_back_to_real_time(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "one.bin").write_bytes(b"a" * 4)
            self.assertEqual(scan_folder(folder, monotonic="not a clock"), (4, 1, False))

    def test_symlinks_are_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            outside = root / "outside.bin"
            outside.write_bytes(b"x" * 100)
            scan = root / "scan"
            scan.mkdir()
            (scan / "inside.bin").write_bytes(b"y" * 7)
            try:
                (scan / "link.bin").symlink_to(outside)
            except (OSError, NotImplementedError) as error:  # Windows without developer mode.
                self.skipTest(f"symlinks are not creatable here: {error}")
            self.assertEqual(scan_folder(scan), (7, 1, False))

    def test_directory_symlinks_are_not_walked(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            outside = root / "outside"
            outside.mkdir()
            (outside / "big.bin").write_bytes(b"x" * 100)
            scan = root / "scan"
            scan.mkdir()
            (scan / "inside.bin").write_bytes(b"y" * 3)
            try:
                (scan / "loop").symlink_to(outside, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlinks are not creatable here: {error}")
            self.assertEqual(scan_folder(scan), (3, 1, False))


class AnsiTests(unittest.TestCase):
    def test_enabled_ansi_wraps_text(self) -> None:
        ansi = Ansi(True)
        self.assertEqual(ansi.paint("hi", Ansi.RED), f"{Ansi.RED}hi{Ansi.RESET}")
        self.assertEqual(ansi.bold("hi"), f"{Ansi.BOLD}hi{Ansi.RESET}")
        self.assertEqual(ansi.dim("hi"), f"{Ansi.DIM}hi{Ansi.RESET}")
        self.assertEqual(
            ansi.paint("hi", Ansi.BOLD, Ansi.GREEN), f"{Ansi.BOLD}{Ansi.GREEN}hi{Ansi.RESET}"
        )

    def test_enabled_ansi_without_codes_is_a_no_op(self) -> None:
        self.assertEqual(Ansi(True).paint("hi"), "hi")

    def test_disabled_ansi_returns_plain_text(self) -> None:
        ansi = Ansi(False)
        for produced in (ansi.paint("hi", Ansi.RED), ansi.bold("hi"), ansi.dim("hi")):
            self.assertEqual(produced, "hi")

    def test_enabled_flag_is_coerced_to_bool(self) -> None:
        self.assertIs(Ansi(0).enabled, False)
        self.assertIs(Ansi("yes").enabled, True)


class SupportsColorTests(unittest.TestCase):
    def test_no_color_wins_over_everything(self) -> None:
        with patch.dict(os.environ, {"NO_COLOR": "1", "FORCE_COLOR": "1"}, clear=True):
            self.assertFalse(supports_color(FakeStream(True)))

    def test_force_color_skips_the_tty_check(self) -> None:
        with patch.dict(os.environ, {"FORCE_COLOR": "1"}, clear=True):
            self.assertTrue(supports_color(FakeStream(False)))

    def test_non_tty_stream_is_never_coloured(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(supports_color(FakeStream(False)))

    def test_a_stream_that_cannot_answer_is_treated_as_plain(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(supports_color(FakeStream(ValueError("closed"))))
            self.assertFalse(supports_color(io.StringIO()))

    def test_a_known_ansi_console_is_accepted_without_touching_the_real_one(self) -> None:
        with patch.dict(os.environ, {"WT_SESSION": "1"}, clear=True):
            self.assertTrue(supports_color(FakeStream(True)))

    def test_defaults_to_stdout_and_never_raises(self) -> None:
        # _enable_vt_mode is stubbed out: the probe changes this process's console mode,
        # which a test run has no business doing.
        with patch.dict(os.environ, {}, clear=True), patch(
            "src.utils._enable_vt_mode", return_value=False
        ):
            self.assertIsInstance(supports_color(), bool)


if __name__ == "__main__":
    unittest.main()
