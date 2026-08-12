"""Tests for the opt-in local history store.

History is the only file the application writes without an export request, so the tests
check both halves of that promise: it stores nothing until it is called, and what it does
store is numbers only - no paths, no process names, no machine identity.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from src import history
from src.health_score import calculate_health_details
from src.history import (
    HistoryDelta,
    HistoryEntry,
    append_snapshot,
    compare_to_previous,
    default_history_path,
    load_history,
)
from src.models import AnalysisData
from src.utils import GIB
from tests.helpers import make_analysis

START = datetime(2026, 7, 16, 12, 30, tzinfo=timezone.utc)


def snapshot(offset_hours: int = 0, **fields: object) -> AnalysisData:
    """One snapshot at a distinct moment, so stored runs stay distinguishable."""
    return replace(
        make_analysis(**fields),  # type: ignore[arg-type]
        analyzed_at=START + timedelta(hours=offset_hours),
    )


class HistoryPathTests(unittest.TestCase):
    def test_default_path_lives_under_local_appdata(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"LOCALAPPDATA": folder}):
                path = default_history_path()
            self.assertEqual(path.parts[-3:], ("Apoliak", "Vitals", "history.jsonl"))
            self.assertEqual(path.parent.parent.parent, Path(folder))

    def test_default_path_falls_back_to_the_home_folder(self) -> None:
        with patch.dict(os.environ, {"LOCALAPPDATA": ""}):
            path = default_history_path()
        self.assertEqual(path.name, "history.jsonl")

    def test_default_path_creates_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"LOCALAPPDATA": folder}):
                path = default_history_path()
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(folder).iterdir()), [])


class HistoryWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "history.jsonl"

    def store(self, data: AnalysisData) -> Path:
        return append_snapshot(data, calculate_health_details(data), path=self.path)

    def test_append_and_load_round_trip(self) -> None:
        data = snapshot()
        assessment = calculate_health_details(data)
        saved = self.store(data)
        self.assertTrue(saved.exists())

        entries = load_history(path=self.path)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.analyzed_at, data.analyzed_at)
        self.assertEqual(entry.score, assessment.score)
        self.assertEqual(entry.status, assessment.status)
        self.assertEqual(entry.cpu_percent, data.cpu.usage_percent)
        self.assertEqual(entry.ram_percent, data.ram.usage_percent)
        self.assertEqual(entry.disk_free_bytes, data.disk.free_bytes)
        self.assertEqual(entry.temp_size_bytes, data.temp_size_bytes)
        self.assertEqual(entry.process_count, data.process_count)
        self.assertEqual(entry.uptime_seconds, data.uptime_seconds)

    def test_entries_are_returned_oldest_first(self) -> None:
        for offset in range(3):
            self.store(snapshot(offset))
        moments = [entry.analyzed_at for entry in load_history(path=self.path)]
        self.assertEqual(moments, [START + timedelta(hours=offset) for offset in range(3)])
        self.assertEqual(moments, sorted(moments))

    def test_appending_keeps_previous_runs(self) -> None:
        for offset in range(3):
            self.store(snapshot(offset))
        self.assertEqual(len(load_history(path=self.path)), 3)
        self.assertEqual(len(self.path.read_text(encoding="utf-8").strip().splitlines()), 3)

    def test_max_entries_trims_the_oldest_runs(self) -> None:
        for offset in range(5):
            append_snapshot(
                snapshot(offset),
                calculate_health_details(snapshot(offset)),
                path=self.path,
                max_entries=3,
            )
        entries = load_history(path=self.path)
        self.assertEqual(len(entries), 3)
        self.assertEqual(
            [entry.analyzed_at for entry in entries],
            [START + timedelta(hours=offset) for offset in (2, 3, 4)],
        )

    def test_max_entries_of_one_keeps_only_the_newest_run(self) -> None:
        for offset in range(3):
            append_snapshot(
                snapshot(offset),
                calculate_health_details(snapshot(offset)),
                path=self.path,
                max_entries=1,
            )
        entries = load_history(path=self.path)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].analyzed_at, START + timedelta(hours=2))

    def test_missing_parent_folders_are_created(self) -> None:
        self.path = Path(self.folder.name) / "deep" / "nested" / "history.jsonl"
        self.store(snapshot())
        self.assertTrue(self.path.exists())

    def test_no_temporary_file_is_left_behind(self) -> None:
        self.store(snapshot())
        self.assertEqual([item.name for item in self.path.parent.iterdir()], ["history.jsonl"])

    def test_stored_lines_are_json_objects(self) -> None:
        self.store(snapshot())
        for line in self.path.read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            self.assertEqual(
                sorted(record),
                sorted(
                    (
                        "analyzed_at",
                        "score",
                        "status",
                        "cpu_percent",
                        "ram_percent",
                        "disk_free_bytes",
                        "temp_size_bytes",
                        "process_count",
                        "uptime_seconds",
                    )
                ),
            )

    def test_stored_file_carries_no_private_data(self) -> None:
        data = replace(
            snapshot(),
            temp_path=r"C:\Users\testaccount\AppData\Local\Temp",
            warnings=("Could not read the registry.",),
        )
        append_snapshot(data, calculate_health_details(data), path=self.path)
        content = self.path.read_text(encoding="utf-8")
        for secret in ("testaccount", "Temp", "Windows", "Test CPU", "registry"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, content)

    def test_unwritable_target_raises_oserror(self) -> None:
        # The store is opt-in, so a caller that asked for it must hear that it failed.
        blocked = Path(self.folder.name) / "blocked.jsonl"
        blocked.mkdir()
        (blocked / "keep.txt").write_text("occupied", encoding="utf-8")
        data = snapshot()
        with self.assertRaises(OSError):
            append_snapshot(data, calculate_health_details(data), path=blocked)
        self.assertFalse((blocked.parent / "blocked.jsonl.tmp").exists())


class HistoryReadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "history.jsonl"

    def write(self, *lines: str) -> None:
        self.path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    def record(self, offset: int, score: int) -> str:
        return json.dumps(
            {
                "analyzed_at": (START + timedelta(hours=offset)).isoformat(),
                "score": score,
                "status": "Good",
                "cpu_percent": 10.0,
                "ram_percent": 20.0,
                "disk_free_bytes": 100 * GIB,
            }
        )

    def test_missing_file_reads_as_no_history(self) -> None:
        self.assertEqual(load_history(path=self.path), [])
        self.assertFalse(self.path.exists())

    def test_corrupt_lines_are_skipped(self) -> None:
        self.write(
            self.record(0, 80),
            "this is not json",
            "",
            "   ",
            "[]",
            "{}",
            '{"score": 50}',
            '{"analyzed_at": "not-a-date", "score": 50}',
            "{truncated",
            self.record(1, 90),
        )
        entries = load_history(path=self.path)
        self.assertEqual([entry.score for entry in entries], [80, 90])

    def test_a_fully_corrupt_file_reads_as_no_history(self) -> None:
        self.write("garbage", "more garbage")
        self.assertEqual(load_history(path=self.path), [])

    def test_appending_drops_the_corrupt_lines(self) -> None:
        self.write(self.record(0, 80), "garbage")
        data = snapshot(1)
        append_snapshot(data, calculate_health_details(data), path=self.path)
        self.assertEqual(len(self.path.read_text(encoding="utf-8").strip().splitlines()), 2)
        self.assertEqual(len(load_history(path=self.path)), 2)

    def test_limit_keeps_the_newest_runs_oldest_first(self) -> None:
        self.write(*(self.record(offset, 70 + offset) for offset in range(5)))
        entries = load_history(path=self.path, limit=2)
        self.assertEqual([entry.score for entry in entries], [73, 74])

    def test_limit_of_zero_returns_everything(self) -> None:
        self.write(*(self.record(offset, 70) for offset in range(3)))
        self.assertEqual(len(load_history(path=self.path, limit=0)), 3)

    def test_a_directory_in_place_of_the_file_reads_as_no_history(self) -> None:
        self.path.mkdir()
        self.assertEqual(load_history(path=self.path), [])

    def test_reading_never_creates_the_file(self) -> None:
        load_history(path=self.path)
        load_history(path=self.path, limit=5)
        self.assertEqual(list(Path(self.folder.name).iterdir()), [])


class CompareToPreviousTests(unittest.TestCase):
    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name) / "history.jsonl"

    def store(self, data: AnalysisData) -> None:
        append_snapshot(data, calculate_health_details(data), path=self.path)

    def compare(self, data: AnalysisData) -> HistoryDelta | None:
        return compare_to_previous(data, calculate_health_details(data), path=self.path)

    def test_no_history_yields_no_comparison(self) -> None:
        self.assertIsNone(self.compare(snapshot()))
        self.assertFalse(self.path.exists())

    def test_the_current_run_is_not_compared_with_itself(self) -> None:
        data = snapshot()
        self.store(data)
        self.assertIsNone(self.compare(data))

    def test_one_stored_run_is_compared(self) -> None:
        self.store(snapshot(0, cpu_percent=10, ram_percent=30, disk_free=100 * GIB))
        current = snapshot(1, cpu_percent=40, ram_percent=50, disk_free=90 * GIB)
        delta = self.compare(current)
        assert delta is not None
        self.assertIsInstance(delta, HistoryDelta)
        self.assertIsInstance(delta.previous, HistoryEntry)
        self.assertEqual(delta.previous.analyzed_at, START)
        self.assertAlmostEqual(delta.cpu_delta or 0.0, 30.0)
        self.assertAlmostEqual(delta.ram_delta or 0.0, 20.0)
        self.assertEqual(delta.disk_free_delta, -10 * GIB)
        self.assertEqual(
            delta.score_delta,
            calculate_health_details(current).score - delta.previous.score,
        )

    def test_the_newest_stored_run_wins(self) -> None:
        for offset in range(3):
            self.store(snapshot(offset))
        delta = self.compare(snapshot(9))
        assert delta is not None
        self.assertEqual(delta.previous.analyzed_at, START + timedelta(hours=2))

    def test_supplied_history_is_used_instead_of_the_file(self) -> None:
        entries = [HistoryEntry(START, 60, "Needs Optimization", 5.0, 5.0, 10 * GIB)]
        data = snapshot(1)
        delta = compare_to_previous(
            data, calculate_health_details(data), path=self.path, history=entries
        )
        assert delta is not None
        self.assertEqual(delta.previous.score, 60)
        self.assertFalse(self.path.exists())

    def test_unknown_measurements_produce_no_invented_delta(self) -> None:
        entries = [HistoryEntry(START, 70, "Good", None, None, None)]
        data = snapshot(1)
        delta = compare_to_previous(data, calculate_health_details(data), history=entries)
        assert delta is not None
        self.assertIsNone(delta.cpu_delta)
        self.assertIsNone(delta.ram_delta)
        self.assertIsNone(delta.disk_free_delta)

    def test_comparison_never_creates_the_file(self) -> None:
        self.compare(snapshot())
        self.assertEqual(list(Path(self.folder.name).iterdir()), [])


class HistoryOptInTests(unittest.TestCase):
    def test_module_writes_nothing_on_import(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"LOCALAPPDATA": folder}):
                # Everything a run does when history was not requested.
                data = snapshot()
                assessment = calculate_health_details(data)
                compare_to_previous(data, assessment)
                load_history()
                history.default_history_path()
            self.assertEqual(list(Path(folder).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
