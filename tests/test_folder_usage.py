"""Tests for the well-known folder measurement in src/folder_usage.py.

The module answers one question - "which of your own folders is eating the disk" - and it
has to answer it without ever taking longer than the analysis is allowed to take. Three
properties carry that:

* one wall-clock budget is shared by every folder, so a 40 GB AppData cannot starve the five
  folders behind it and a folder that finishes early hands its unused time on;
* a folder that could not be measured reports ``None``, never ``0`` - "cannot look" and
  "spotlessly clean" are different facts, and only one of them is true;
* nothing raises, on any platform, whatever the disk does.

The disk itself is never touched: ``scan_folder`` and the folder list are replaced, so the
suite measures the sharing rule rather than the machine it happens to run on.
"""

from __future__ import annotations

import ctypes
import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from src import folder_usage
from src.folder_usage import (
    KNOWN_FOLDER_KEYS,
    _folder_candidates,
    _guid_fields,
    _identity,
    _is_listable_directory,
    _share,
    read_folder_usage,
)
from src.models import FolderUsage
from src.utils import DEFAULT_SCAN_SECONDS, GIB

PROFILE = r"C:\Users\Test"

#: (key, label, path) triples in the order the module measures them.
CANDIDATES: list[tuple[str, str, str]] = [
    ("downloads", "Downloads", rf"{PROFILE}\Downloads"),
    ("desktop", "Desktop", rf"{PROFILE}\Desktop"),
    ("documents", "Documents", rf"{PROFILE}\Documents"),
]


class FakeDisk:
    """A described set of folders, standing in for the walker and the filesystem."""

    def __init__(
        self,
        sizes: dict[str, tuple[int, int, bool]] | None = None,
        *,
        missing: tuple[str, ...] = (),
        hostile: tuple[str, ...] = (),
        cost: float = 0.0,
    ) -> None:
        self.sizes = sizes or {}
        self.missing = missing
        self.hostile = hostile
        self.cost = cost
        self.granted: dict[str, float | None] = {}
        self.order: list[str] = []
        self.clock = 0.0

    def listable(self, path: str) -> bool:
        return path not in self.missing

    def scan(self, path: object, *, max_seconds: float | None = None) -> tuple[int, int, bool]:
        name = str(path)
        self.order.append(name)
        self.granted[name] = max_seconds
        if name in self.hostile:
            raise OSError("the folder went away mid-scan")
        self.clock += self.cost  # A scan that takes time is what shrinks the shared budget.
        return self.sizes.get(name, (0, 0, False))

    def monotonic(self) -> float:
        return self.clock


def measure(disk: FakeDisk, candidates: list[tuple[str, str, str]] | None = None, **kwargs: object):
    """Run the collector against a described machine, with no real disk involved."""
    folders = CANDIDATES if candidates is None else candidates
    with patch.object(folder_usage.platform, "system", return_value="Windows"):
        with patch.object(folder_usage, "_folder_candidates", return_value=list(folders)):
            with patch.object(folder_usage, "_is_listable_directory", disk.listable):
                with patch.object(folder_usage, "scan_folder", disk.scan):
                    with patch.object(folder_usage.time, "monotonic", disk.monotonic):
                        return read_folder_usage(**kwargs)  # type: ignore[arg-type]


class VocabularyTests(unittest.TestCase):
    def test_the_published_keys_are_the_folders_the_module_measures(self) -> None:
        measured = tuple(key for key, _, _, _ in folder_usage._KNOWN_FOLDERS)
        self.assertEqual(KNOWN_FOLDER_KEYS, measured)

    def test_the_keys_are_unique_and_stable(self) -> None:
        self.assertEqual(len(set(KNOWN_FOLDER_KEYS)), len(KNOWN_FOLDER_KEYS))
        self.assertEqual(
            KNOWN_FOLDER_KEYS,
            (
                "downloads",
                "desktop",
                "documents",
                "pictures",
                "videos",
                "music",
                "local_appdata",
                "packages",
            ),
        )

    def test_downloads_is_measured_first(self) -> None:
        # It is the folder users act on most, and the first folder gets the fullest budget.
        self.assertEqual(KNOWN_FOLDER_KEYS[0], "downloads")

    def test_every_folder_carries_a_plain_english_label(self) -> None:
        for key, label, _guid, fallback in folder_usage._KNOWN_FOLDERS:
            with self.subTest(key=key):
                self.assertTrue(label.strip())
                self.assertTrue(fallback.strip())


class ReturnShapeTests(unittest.TestCase):
    def test_a_measured_folder_carries_its_size_and_its_count(self) -> None:
        disk = FakeDisk({rf"{PROFILE}\Downloads": (30 * GIB, 900, False)})
        rows = measure(disk)
        first = rows[0]
        self.assertIsInstance(first, FolderUsage)
        self.assertEqual(first.key, "downloads")
        self.assertEqual(first.label, "Downloads")
        self.assertEqual(first.path, rf"{PROFILE}\Downloads")
        self.assertEqual(first.size_bytes, 30 * GIB)
        self.assertEqual(first.file_count, 900)
        self.assertFalse(first.truncated)

    def test_the_biggest_folder_comes_first(self) -> None:
        disk = FakeDisk(
            {
                rf"{PROFILE}\Downloads": (2 * GIB, 10, False),
                rf"{PROFILE}\Desktop": (9 * GIB, 20, False),
                rf"{PROFILE}\Documents": (5 * GIB, 30, False),
            }
        )
        self.assertEqual([row.key for row in measure(disk)], ["desktop", "documents", "downloads"])

    def test_an_unmeasured_folder_sorts_last_because_unknown_is_not_small(self) -> None:
        disk = FakeDisk(
            {rf"{PROFILE}\Documents": (1, 1, False)}, missing=(rf"{PROFILE}\Downloads",)
        )
        rows = measure(disk)
        self.assertEqual(rows[-1].key, "downloads")
        self.assertIsNone(rows[-1].size_bytes)

    def test_ties_are_broken_by_label_then_key(self) -> None:
        disk = FakeDisk({path: (7 * GIB, 1, False) for _, _, path in CANDIDATES})
        self.assertEqual([row.key for row in measure(disk)], ["desktop", "documents", "downloads"])

    def test_a_folder_that_cannot_be_listed_is_unknown_and_never_zero(self) -> None:
        # Reporting 0 bytes would turn a folder this account may not open into a clean one.
        disk = FakeDisk(missing=(rf"{PROFILE}\Downloads",))
        row = next(item for item in measure(disk) if item.key == "downloads")
        self.assertIsNone(row.size_bytes)
        self.assertIsNone(row.file_count)
        self.assertFalse(row.truncated)
        self.assertNotIn(rf"{PROFILE}\Downloads", disk.granted)  # Never even attempted.

    def test_a_scan_that_ran_out_of_time_says_so(self) -> None:
        disk = FakeDisk({rf"{PROFILE}\Downloads": (12 * GIB, 400, True)})
        row = next(item for item in measure(disk) if item.key == "downloads")
        self.assertTrue(row.truncated)
        self.assertEqual(row.size_bytes, 12 * GIB)  # A floor, and the flag says so.

    def test_a_walker_that_explodes_costs_only_that_folder(self) -> None:
        disk = FakeDisk(
            {rf"{PROFILE}\Desktop": (3 * GIB, 5, False)}, hostile=(rf"{PROFILE}\Downloads",)
        )
        rows = {row.key: row for row in measure(disk)}
        self.assertIsNone(rows["downloads"].size_bytes)
        self.assertEqual(rows["desktop"].size_bytes, 3 * GIB)

    def test_an_empty_folder_is_a_real_measurement_of_zero(self) -> None:
        # The difference that matters: this folder was walked and holds nothing, which is
        # not the same as the folder above that could not be opened.
        disk = FakeDisk({path: (0, 0, False) for _, _, path in CANDIDATES})
        for row in measure(disk):
            with self.subTest(key=row.key):
                self.assertEqual(row.size_bytes, 0)
                self.assertEqual(row.file_count, 0)

    def test_no_path_is_ever_reported_twice(self) -> None:
        disk = FakeDisk({path: (GIB, 1, False) for _, _, path in CANDIDATES})
        rows = measure(disk)
        paths = [row.path for row in rows]
        self.assertEqual(len(paths), len(set(paths)))


class LimitTests(unittest.TestCase):
    def test_the_limit_caps_the_rows_after_ranking(self) -> None:
        disk = FakeDisk(
            {
                rf"{PROFILE}\Downloads": (2 * GIB, 1, False),
                rf"{PROFILE}\Desktop": (9 * GIB, 1, False),
                rf"{PROFILE}\Documents": (5 * GIB, 1, False),
            }
        )
        rows = measure(disk, limit=2)
        self.assertEqual([row.key for row in rows], ["desktop", "documents"])

    def test_a_limit_of_zero_measures_nothing_at_all(self) -> None:
        disk = FakeDisk()
        self.assertEqual(measure(disk, limit=0), [])
        self.assertEqual(disk.granted, {}, "a limit of zero must not cost a single scan")

    def test_a_negative_limit_is_treated_as_zero(self) -> None:
        self.assertEqual(measure(FakeDisk(), limit=-5), [])

    def test_a_limit_larger_than_the_folder_list_returns_everything(self) -> None:
        disk = FakeDisk({path: (GIB, 1, False) for _, _, path in CANDIDATES})
        self.assertEqual(len(measure(disk, limit=99)), len(CANDIDATES))


class BudgetTests(unittest.TestCase):
    """One budget, shared: this is what keeps a big disk from lengthening the analysis."""

    def test_the_default_budget_is_the_projects_own(self) -> None:
        disk = FakeDisk()
        measure(disk)
        granted = [value for value in disk.granted.values() if value is not None]
        self.assertLessEqual(max(granted), DEFAULT_SCAN_SECONDS)

    def test_every_folder_is_granted_a_share_of_one_budget(self) -> None:
        disk = FakeDisk()
        measure(disk, max_seconds=8.0)
        grants = [disk.granted[path] for _, _, path in CANDIDATES]
        self.assertEqual(len(grants), 3)
        for grant in grants:
            with self.subTest(grant=grant):
                assert grant is not None
                self.assertGreater(grant, 0.0)
                self.assertLessEqual(grant, 8.0)

    def test_a_folder_never_claims_the_reserve_held_back_for_the_ones_behind_it(self) -> None:
        disk = FakeDisk()
        measure(disk, max_seconds=8.0)
        first = disk.granted[rf"{PROFILE}\Downloads"]
        assert first is not None
        # Two folders still to come, each guaranteed half a second.
        self.assertLessEqual(first, 8.0 - 0.5 * 2)

    def test_time_a_folder_did_not_need_is_handed_to_the_next_one(self) -> None:
        disk = FakeDisk()  # Every scan is instant.
        measure(disk, max_seconds=8.0)
        grants = [disk.granted[path] for _, _, path in CANDIDATES]
        self.assertEqual(grants, sorted(grants), "an early finish must widen the next share")
        self.assertEqual(grants[-1], 8.0)

    def test_a_slow_folder_shrinks_the_ones_behind_it(self) -> None:
        disk = FakeDisk(cost=1.5)  # Each scan burns 1.5 s of the shared budget.
        measure(disk, max_seconds=4.0)
        grants = [disk.granted[path] for _, _, path in CANDIDATES]
        # 4.0 less two reserves; then 2.5 left less one reserve; then whatever remains.
        self.assertEqual(grants, [3.0, 2.0, 1.0])

    def test_the_whole_run_stays_inside_the_budget(self) -> None:
        for cost in (0.0, 0.5, 2.0, 10.0):
            with self.subTest(cost=cost):
                disk = FakeDisk(cost=cost)
                measure(disk, max_seconds=6.0)
                for grant in disk.granted.values():
                    assert grant is not None
                    self.assertLessEqual(grant, 6.0)

    def test_the_reserve_keeps_the_last_row_worth_printing(self) -> None:
        # A folder handed nothing reports "0 bytes, partial", which nobody can act on. While
        # any budget is left, the reserve guarantees each folder a real share of it.
        disk = FakeDisk(cost=0.2)
        measure(disk, max_seconds=1.0)
        for path, grant in disk.granted.items():
            with self.subTest(path=path):
                assert grant is not None
                self.assertGreaterEqual(grant, 0.3)

    def test_a_budget_spent_by_one_folder_leaves_the_rest_at_zero_not_below(self) -> None:
        # A scan can overrun its share, and once the whole budget is gone the folders behind
        # it get nothing. That is honest rather than harmful: a zero-second walk reports
        # truncated, which every consumer renders as a lower bound - see the walker below.
        disk = FakeDisk(cost=99.0)
        measure(disk, max_seconds=1.0)
        grants = [disk.granted[path] for _, _, path in CANDIDATES]
        self.assertEqual(grants[1:], [0.0, 0.0])
        for grant in grants:
            assert grant is not None
            self.assertGreaterEqual(grant, 0.0)

    def test_a_zero_second_walk_reports_a_floor_rather_than_an_empty_folder(self) -> None:
        # The claim the test above rests on, asserted against the real walker.
        from src.utils import scan_folder as real_scan_folder

        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "file.bin").write_bytes(b"x" * 32)
            size, files, truncated = real_scan_folder(folder, max_seconds=0.0)
        self.assertTrue(truncated)
        self.assertEqual((size, files), (0, 0))

    def test_a_budget_of_zero_is_accepted_rather_than_refused(self) -> None:
        disk = FakeDisk()
        rows = measure(disk, max_seconds=0.0)
        self.assertEqual(len(rows), len(CANDIDATES))
        for grant in disk.granted.values():
            self.assertEqual(grant, 0.0)

    def test_a_negative_budget_is_clamped(self) -> None:
        disk = FakeDisk()
        measure(disk, max_seconds=-4.0)
        for grant in disk.granted.values():
            self.assertEqual(grant, 0.0)

    def test_folders_are_measured_in_the_documented_order(self) -> None:
        # Ordering is the sharing rule: the application-data folders are measured last
        # because they are the slowest and gain the most from inherited time.
        disk = FakeDisk()
        measure(disk)
        self.assertEqual(disk.order, [path for _, _, path in CANDIDATES])


class ShareArithmeticTests(unittest.TestCase):
    """The sharing rule is pure arithmetic, so it is checked without touching a disk."""

    def test_the_last_folder_gets_everything_that_is_left(self) -> None:
        self.assertEqual(_share(3.0, 1), 3.0)
        self.assertEqual(_share(0.0, 1), 0.0)

    def test_a_reserve_is_held_back_for_each_folder_still_to_come(self) -> None:
        self.assertEqual(_share(8.0, 3), 7.0)  # 8 - 0.5 * 2
        self.assertEqual(_share(8.0, 8), 4.5)  # 8 - 0.5 * 7

    def test_a_budget_too_small_for_the_reserve_degrades_to_an_even_split(self) -> None:
        # Otherwise the first folder would take everything and the rest would report zero.
        self.assertAlmostEqual(_share(0.6, 4), 0.15)
        self.assertAlmostEqual(_share(0.0, 4), 0.0)

    def test_a_share_is_never_negative_and_never_exceeds_what_is_left(self) -> None:
        for remaining in (-5.0, 0.0, 0.1, 1.0, 12.0):
            for left in (1, 2, 5, 8):
                with self.subTest(remaining=remaining, left=left):
                    share = _share(remaining, left)
                    self.assertGreaterEqual(share, 0.0)
                    self.assertLessEqual(share, max(0.0, remaining))


class PlatformTests(unittest.TestCase):
    def test_a_machine_that_is_not_windows_measures_nothing(self) -> None:
        for system in ("Linux", "Darwin", "", "Java"):
            with self.subTest(system=system):
                with patch.object(folder_usage.platform, "system", return_value=system):
                    self.assertEqual(read_folder_usage(), [])

    def test_the_platform_is_checked_before_a_single_folder_is_resolved(self) -> None:
        with patch.object(folder_usage.platform, "system", return_value="Linux"):
            with patch.object(folder_usage, "_folder_candidates") as resolver:
                with patch.object(folder_usage, "scan_folder") as walker:
                    self.assertEqual(read_folder_usage(), [])
        resolver.assert_not_called()
        walker.assert_not_called()

    def test_a_resolver_that_explodes_never_reaches_the_caller(self) -> None:
        with patch.object(folder_usage.platform, "system", return_value="Windows"):
            with patch.object(
                folder_usage, "_folder_candidates", side_effect=OSError("the shell is gone")
            ):
                self.assertEqual(read_folder_usage(), [])

    def test_a_nonsense_budget_never_reaches_the_caller_as_an_exception(self) -> None:
        disk = FakeDisk()
        with patch.object(folder_usage.platform, "system", return_value="Windows"):
            with patch.object(folder_usage, "_folder_candidates", return_value=list(CANDIDATES)):
                with patch.object(folder_usage, "_is_listable_directory", disk.listable):
                    with patch.object(folder_usage, "scan_folder", disk.scan):
                        nonsense = read_folder_usage(max_seconds="soon")  # type: ignore[arg-type]
                        self.assertEqual(nonsense, [])


class CandidateResolutionTests(unittest.TestCase):
    """Where the folders are looked for when the shell will not say."""

    def candidates(self, **environment: str) -> list[tuple[str, str, str]]:
        with patch.dict(os.environ, environment, clear=False):
            for name in ("USERPROFILE", "LOCALAPPDATA"):
                if name not in environment:
                    os.environ.pop(name, None)
            with patch.object(folder_usage, "_load_shell_api", return_value=None):
                return _folder_candidates()

    def test_the_profile_join_is_the_fallback(self) -> None:
        found = dict((key, path) for key, _, path in self.candidates(USERPROFILE=PROFILE))
        self.assertEqual(found["downloads"], os.path.join(PROFILE, "Downloads"))
        self.assertEqual(found["local_appdata"], os.path.join(PROFILE, "AppData", "Local"))

    def test_store_app_data_is_derived_from_wherever_app_data_turned_out_to_be(self) -> None:
        # A redirected AppData must not leave this pointing at an empty default location.
        moved = r"D:\AppData\Local"
        found = dict(
            (key, path) for key, _, path in self.candidates(USERPROFILE=PROFILE, LOCALAPPDATA=moved)
        )
        self.assertEqual(found["local_appdata"], moved)
        self.assertEqual(found["packages"], os.path.join(moved, "Packages"))

    def test_a_machine_with_no_profile_at_all_resolves_nothing(self) -> None:
        self.assertEqual(self.candidates(), [])

    def test_two_keys_pointing_at_one_folder_are_measured_once(self) -> None:
        # Videos redirected into Documents is a real configuration; measuring it twice would
        # report one pile of files as two.
        shared = rf"{PROFILE}\Documents"

        def resolve(api: object, guid: str) -> str:
            return shared

        with patch.dict(os.environ, {"USERPROFILE": PROFILE}, clear=False):
            with patch.object(folder_usage, "_load_shell_api", return_value=object()):
                with patch.object(folder_usage, "_known_folder_path", resolve):
                    candidates = _folder_candidates()
        paths = [path for _, _, path in candidates]
        self.assertEqual(len(paths), len(set(paths)))
        self.assertEqual(paths.count(shared), 1)

    def test_the_shell_answer_wins_over_the_profile_join(self) -> None:
        redirected = r"D:\OneDrive\Documents"

        def resolve(api: object, guid: str) -> str | None:
            return redirected if guid.lower().startswith("fdd39ad0") else None

        with patch.dict(os.environ, {"USERPROFILE": PROFILE}, clear=False):
            with patch.object(folder_usage, "_load_shell_api", return_value=object()):
                with patch.object(folder_usage, "_known_folder_path", resolve):
                    found = dict((key, path) for key, _, path in _folder_candidates())
        self.assertEqual(found["documents"], redirected)
        self.assertEqual(found["downloads"], os.path.join(PROFILE, "Downloads"))


class GuidTests(unittest.TestCase):
    def test_a_known_folder_id_splits_into_the_four_win32_members(self) -> None:
        fields = _guid_fields("374DE290-123F-4565-9164-39C4925E467B")
        assert fields is not None
        data1, data2, data3, data4 = fields
        self.assertEqual(data1, 0x374DE290)
        self.assertEqual(data2, 0x123F)
        self.assertEqual(data3, 0x4565)
        self.assertEqual(data4, bytes.fromhex("916439C4925E467B"))

    def test_braces_and_whitespace_are_accepted(self) -> None:
        with_braces = _guid_fields(" {374DE290-123F-4565-9164-39C4925E467B} ")
        self.assertEqual(with_braces, _guid_fields("374DE290-123F-4565-9164-39C4925E467B"))

    def test_every_shipped_identifier_parses(self) -> None:
        for key, _label, guid, _fallback in folder_usage._KNOWN_FOLDERS:
            with self.subTest(key=key):
                if guid is None:
                    continue  # "packages" is derived, not a known folder of its own.
                self.assertIsNotNone(_guid_fields(guid))

    def test_something_that_is_not_a_guid_is_refused(self) -> None:
        for text in ("", "nope", "1-2-3-4", "374DE290-123F-4565-9164-39C4925E467", None, 7):
            with self.subTest(text=text):
                self.assertIsNone(_guid_fields(text))  # type: ignore[arg-type]


class ListableDirectoryTests(unittest.TestCase):
    """The one check that turns "cannot look" back into "unknown"."""

    def test_a_real_folder_is_listable(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            self.assertTrue(_is_listable_directory(folder))

    def test_a_folder_that_is_not_there_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            self.assertFalse(_is_listable_directory(os.path.join(folder, "nope")))

    def test_a_file_is_not_a_folder(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder, "file.txt")
            path.write_text("x", encoding="utf-8")
            self.assertFalse(_is_listable_directory(str(path)))

    def test_nonsense_never_raises(self) -> None:
        for value in ("", "   ", "\x00bad", "Z:\\nowhere\\at\\all"):
            with self.subTest(value=value):
                self.assertFalse(_is_listable_directory(value))

    def test_two_names_for_one_folder_compare_equal(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(_identity(folder), _identity(folder.upper()))

    def test_identity_never_raises_on_a_path_that_cannot_be_resolved(self) -> None:
        self.assertTrue(_identity("\x00bad"))


class _Guid(ctypes.Structure):
    """The Win32 GUID the shell call takes a pointer to."""

    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class NoWriteTests(unittest.TestCase):
    """The shell is asked where a folder is, never asked to make one."""

    class FakeShell:
        """Records the flags handed to SHGetKnownFolderPath, and frees nothing real."""

        def __init__(self) -> None:
            self.flags: list[int] = []
            self.freed = 0
            # A real ctypes structure, because the caller takes a byref() of it.
            self.guid_type = _Guid
            self.shell32 = self
            self.ole32 = self

        def SHGetKnownFolderPath(  # noqa: N802 - the Win32 name is the contract
            self, guid: object, flags: int, token: object, pointer: object
        ) -> int:
            self.flags.append(int(flags))
            return 1  # E_FAIL: the caller must fall back rather than dereference anything.

        def CoTaskMemFree(self, pointer: object) -> None:  # noqa: N802
            self.freed += 1

    def test_the_shell_is_asked_with_the_default_flag_and_never_with_create(self) -> None:
        # KF_FLAG_CREATE would have Windows create a missing known folder on our behalf.
        # This application creates nothing, not even a folder Windows would happily create.
        shell = self.FakeShell()
        self.assertIsNone(
            folder_usage._known_folder_path(shell, "374DE290-123F-4565-9164-39C4925E467B")
        )
        self.assertEqual(shell.flags, [0])
        self.assertEqual(folder_usage._KF_FLAG_DEFAULT, 0)

    def test_a_folder_the_shell_will_not_name_is_simply_not_resolved(self) -> None:
        downloads = "374DE290-123F-4565-9164-39C4925E467B"
        self.assertIsNone(folder_usage._known_folder_path(None, downloads))

    def test_the_module_never_writes_to_the_disk(self) -> None:
        with open(folder_usage.__file__, "r", encoding="utf-8") as handle:
            source = handle.read()
        for forbidden in ("makedirs", "mkdir(", "rmtree", "unlink", "os.remove", "shutil"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
