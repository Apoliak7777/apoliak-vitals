"""Tests for the read-only collectors: src/analyzer.py, src/processes.py, src/win_registry.py.

Everything is driven through fakes so the suite behaves identically on a laptop with a
battery, a desktop without one, and a non-Windows machine. The few genuinely
platform-specific assertions are guarded with ``skipUnless``.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import exporters, win_registry
from src.analyzer import (
    PROGRESS_LABELS,
    TOTAL_SCAN_SECONDS,
    MissingDependencyError,
    _MEDIA_TYPE_CACHE,
    _default_temp_path,
    _edition_label,
    _folder_budget,
    _processor_name,
    _temp_budget,
    _windows_release,
    analyze_pc,
    detect_media_type,
    get_battery,
    get_cpu_info,
    get_disk_info,
    get_drive_health,
    get_folder_usage,
    get_network,
    get_partitions,
    get_process_count,
    get_ram_info,
    get_security,
    get_system_drive,
    get_system_info,
    get_temp_locations,
    get_temp_size,
    get_uptime,
)
from src.health_score import calculate_health_details
from src.models import (
    DriveHealth,
    FolderUsage,
    GPUInfo,
    ProcessInfo,
    SCHEMA_VERSION,
    STATE_GOOD,
    STATE_WEAK,
    SecurityInfo,
    StartupItem,
)
from src.processes import CPU_SAMPLE_SECONDS, top_processes
from src.recommendations import TOP_CPU_PERCENT, generate_recommendations
from src.utils import GIB

IS_WINDOWS = sys.platform.startswith("win")

#: Environment variables the temp-folder resolver is allowed to read, most wanted first.
TEMP_VARIABLES = ("TMP", "TEMP", "TMPDIR")


@contextmanager
def temp_environment(**values: str | None) -> Iterator[None]:
    """Run a block with exactly the given temp variables set; ``None`` removes one."""
    with patch.dict(os.environ, {}, clear=False):
        for name in TEMP_VARIABLES:
            os.environ.pop(name, None)
        for name, value in values.items():
            if value is not None:
                os.environ[name] = value
        yield

DEFAULT_USAGE = SimpleNamespace(total=512 * GIB, used=400 * GIB, free=112 * GIB, percent=78.125)


class FakeProcess:
    """One entry of a fake process table, including the two-sample CPU protocol."""

    def __init__(
        self,
        pid: int,
        name: str,
        *,
        rss: int | None = 0,
        memory_percent: float | None = None,
        cpu_samples: Sequence[float] = (),
        cpu_error: bool = False,
        info: object = None,
    ) -> None:
        self.pid = pid
        self._cpu = list(cpu_samples)
        self.cpu_error = cpu_error
        self.info = (
            info
            if info is not None
            else {
                "pid": pid,
                "name": name,
                "memory_info": None if rss is None else SimpleNamespace(rss=rss),
                "memory_percent": memory_percent,
            }
        )

    def cpu_percent(self) -> float:
        if self.cpu_error:
            raise RuntimeError("process vanished")
        return self._cpu.pop(0) if self._cpu else 0.0


class VanishedProcess:
    """A handle that dies exactly when psutil hands it over; it must simply be skipped."""

    pid = 4242

    @property
    def info(self) -> dict[str, object]:
        raise RuntimeError("no such process")

    def cpu_percent(self) -> float:
        return 0.0


class FakePsutil:
    """Stand-in for psutil covering every call the collectors make.

    ``fail`` names the calls that must raise, which is how the warning path of each
    collector is exercised without breaking anything on the real machine. Every returned
    value is a plain attribute, so a test can reshape one reading and leave the rest alone.
    """

    POWER_TIME_UNLIMITED = -2
    POWER_TIME_UNKNOWN = -1

    def __init__(self, *, disk_error: bool = False, fail: Iterable[str] = ()) -> None:
        self.failures = set(fail)
        if disk_error:  # v1.0 keyword, kept so older call sites stay readable.
            self.failures.add("disk_usage")

        self.cpu_interval: float | None = None
        self.percpu_requested = False
        self.physical = 6
        self.logical = 12
        self.per_core: list[float] = [10.0, 20.0, 30.0, 40.0]
        self.overall = 12.5
        self.frequency: object | None = SimpleNamespace(current=2400.0, max=3600.0)

        self.memory = SimpleNamespace(
            total=16 * GIB, available=6 * GIB, used=10 * GIB, percent=62.5
        )
        self.swap = SimpleNamespace(total=8 * GIB, used=GIB, percent=12.5)

        self.default_usage = DEFAULT_USAGE
        self.usage: dict[str, object] = {}
        self.partitions: list[object] = [
            SimpleNamespace(device="C:\\", mountpoint="C:\\", fstype="NTFS", opts="rw,fixed")
        ]

        self.pid_list = list(range(164))
        self.boot = 100_000.0
        self.battery: object | None = None
        self.net_counters: object | None = SimpleNamespace(
            bytes_sent=12 * GIB, bytes_recv=48 * GIB
        )
        self.if_stats: dict[str, object] = {
            "Ethernet": SimpleNamespace(isup=True, speed=1000),
            "Loopback Pseudo-Interface 1": SimpleNamespace(isup=True, speed=1000),
        }
        self.processes: list[object] = []

    def _check(self, name: str) -> None:
        if name in self.failures:
            raise OSError(f"{name} is unavailable")

    def cpu_count(self, logical: bool = True) -> int | None:
        self._check("cpu_count")
        return self.logical if logical else self.physical

    def cpu_percent(self, interval: float = 0.0, percpu: bool = False) -> object:
        self._check("cpu_percent")
        self.cpu_interval = interval
        if percpu:
            self.percpu_requested = True
            return list(self.per_core)
        return self.overall

    def cpu_freq(self) -> object | None:
        self._check("cpu_freq")
        return self.frequency

    def virtual_memory(self) -> object:
        self._check("virtual_memory")
        return self.memory

    def swap_memory(self) -> object:
        self._check("swap_memory")
        return self.swap

    def disk_usage(self, path: str) -> object:
        self._check("disk_usage")
        entry = self.usage.get(os.path.normcase(path), self.default_usage)
        if isinstance(entry, Exception):
            raise entry
        return entry

    def disk_partitions(self, all: bool = False) -> list[object]:  # noqa: A002 - psutil's name
        self._check("disk_partitions")
        return list(self.partitions)

    def pids(self) -> list[int]:
        self._check("pids")
        return list(self.pid_list)

    def boot_time(self) -> float:
        self._check("boot_time")
        return self.boot

    def sensors_battery(self) -> object | None:
        self._check("sensors_battery")
        return self.battery

    def net_io_counters(self) -> object | None:
        self._check("net_io_counters")
        return self.net_counters

    def net_if_stats(self) -> dict[str, object]:
        self._check("net_if_stats")
        return dict(self.if_stats)

    def process_iter(self, attrs: object = None, ad_value: object = None) -> object:
        self._check("process_iter")
        return iter(self.processes)


class NoPercpuPsutil(FakePsutil):
    """An older psutil whose cpu_percent has no ``percpu`` parameter."""

    def cpu_percent(self, interval: float = 0.0) -> object:  # type: ignore[override]
        self.cpu_interval = interval
        return self.overall


class CpuCollectorTests(unittest.TestCase):
    def test_topology_interval_and_percpu_average(self) -> None:
        fake = FakePsutil()
        cpu = get_cpu_info(fake, interval=0.25)
        self.assertEqual((cpu.physical_cores, cpu.logical_cores), (6, 12))
        self.assertEqual(fake.cpu_interval, 0.25)
        self.assertTrue(fake.percpu_requested)
        self.assertEqual(cpu.per_core_percent, (10.0, 20.0, 30.0, 40.0))
        self.assertEqual(cpu.usage_percent, 25.0)  # The mean of the per-core sample.
        self.assertEqual((cpu.frequency_mhz, cpu.max_frequency_mhz), (2400.0, 3600.0))

    def test_negative_interval_is_clamped(self) -> None:
        fake = FakePsutil()
        get_cpu_info(fake, interval=-5.0)
        self.assertEqual(fake.cpu_interval, 0.0)

    def test_falls_back_when_percpu_is_unsupported(self) -> None:
        fake = NoPercpuPsutil()
        cpu = get_cpu_info(fake, interval=0)
        self.assertEqual(cpu.per_core_percent, ())
        self.assertEqual(cpu.usage_percent, 12.5)

    def test_empty_percpu_reading_leaves_usage_unknown(self) -> None:
        fake = FakePsutil()
        fake.per_core = []
        cpu = get_cpu_info(fake, interval=0)
        self.assertEqual(cpu.per_core_percent, ())
        self.assertIsNone(cpu.usage_percent)

    def test_missing_or_failing_frequency_is_not_invented(self) -> None:
        failing = get_cpu_info(FakePsutil(fail=("cpu_freq",)), interval=0)
        self.assertIsNone(failing.frequency_mhz)
        self.assertIsNone(failing.max_frequency_mhz)

        absent = FakePsutil()
        absent.frequency = None
        cpu = get_cpu_info(absent, interval=0)
        self.assertIsNone(cpu.frequency_mhz)
        self.assertIsNone(cpu.max_frequency_mhz)

    def test_zero_frequency_is_reported_as_unknown(self) -> None:
        fake = FakePsutil()
        fake.frequency = SimpleNamespace(current=0.0, max=0.0)
        cpu = get_cpu_info(fake, interval=0)
        self.assertIsNone(cpu.frequency_mhz)
        self.assertIsNone(cpu.max_frequency_mhz)


class MemoryCollectorTests(unittest.TestCase):
    def test_physical_and_swap_are_reported(self) -> None:
        ram = get_ram_info(FakePsutil())
        self.assertEqual(ram.total_bytes, 16 * GIB)
        self.assertEqual(ram.usage_percent, 62.5)
        self.assertEqual(ram.swap_total_bytes, 8 * GIB)
        self.assertEqual(ram.swap_used_bytes, GIB)
        self.assertEqual(ram.swap_percent, 12.5)

    def test_swap_failure_leaves_swap_unknown_but_keeps_ram(self) -> None:
        ram = get_ram_info(FakePsutil(fail=("swap_memory",)))
        self.assertEqual(ram.usage_percent, 62.5)
        self.assertIsNone(ram.swap_total_bytes)
        self.assertIsNone(ram.swap_used_bytes)
        self.assertIsNone(ram.swap_percent)


class DiskCollectorTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch("src.analyzer.detect_media_type", return_value="SSD")
        self.media_type = patcher.start()
        self.addCleanup(patcher.stop)

    def test_disk_info_labels_the_volume(self) -> None:
        fake = FakePsutil()
        disk = get_disk_info(fake, "C:\\")
        self.assertEqual(disk.free_bytes, 112 * GIB)
        self.assertEqual(disk.total_bytes, 512 * GIB)
        self.assertEqual(disk.usage_percent, 78.125)
        self.assertEqual(disk.filesystem, "NTFS")
        self.assertEqual(disk.media_type, "SSD")

    def test_unlisted_volume_has_no_filesystem(self) -> None:
        fake = FakePsutil()
        fake.partitions = []
        self.assertIsNone(get_disk_info(fake, "C:\\").filesystem)

    def test_partition_lookup_survives_a_failing_partition_table(self) -> None:
        fake = FakePsutil(fail=("disk_partitions",))
        self.assertIsNone(get_disk_info(fake, "C:\\").filesystem)

    def test_partitions_skip_optical_empty_and_unreadable_drives(self) -> None:
        fake = FakePsutil()
        fake.partitions = [
            SimpleNamespace(mountpoint="C:\\", fstype="NTFS", opts="rw,fixed"),
            SimpleNamespace(mountpoint="D:\\", fstype="NTFS", opts="rw,fixed"),
            SimpleNamespace(mountpoint="E:\\", fstype="CDFS", opts="ro,cdrom"),
            SimpleNamespace(mountpoint="F:\\", fstype="FAT32", opts="rw,removable"),
            SimpleNamespace(mountpoint="", fstype="", opts=""),
            SimpleNamespace(mountpoint="G:\\", fstype="exFAT", opts="rw,fixed"),
        ]
        fake.usage = {
            os.path.normcase("D:\\"): OSError("device not ready"),
            os.path.normcase("F:\\"): SimpleNamespace(total=0, used=0, free=0, percent=0.0),
            os.path.normcase("G:\\"): SimpleNamespace(
                total=256 * GIB, used=56 * GIB, free=200 * GIB, percent=21.875
            ),
        }
        with patch("src.analyzer.get_system_drive", return_value="C:\\"):
            partitions = get_partitions(fake)
        self.assertEqual([item.drive for item in partitions], ["C:\\", "G:\\"])
        self.assertTrue(partitions[0].is_system)
        self.assertFalse(partitions[1].is_system)
        self.assertEqual(partitions[1].filesystem, "exFAT")

    def test_partition_list_is_capped(self) -> None:
        fake = FakePsutil()
        fake.partitions = [
            SimpleNamespace(mountpoint=f"{chr(ord('A') + index)}:\\", fstype="NTFS", opts="rw")
            for index in range(20)
        ]
        self.assertEqual(len(get_partitions(fake)), 12)

    def test_failing_partition_table_returns_no_drives(self) -> None:
        self.assertEqual(get_partitions(FakePsutil(fail=("disk_partitions",))), [])


class SystemDriveTests(unittest.TestCase):
    @unittest.skipUnless(IS_WINDOWS, "SystemDrive only exists on Windows")
    def test_windows_uses_the_system_drive_variable(self) -> None:
        with patch.dict(os.environ, {"SystemDrive": "D:"}, clear=False):
            self.assertEqual(get_system_drive(), "D:\\")

    @unittest.skipUnless(IS_WINDOWS, "SystemDrive only exists on Windows")
    def test_windows_falls_back_to_c(self) -> None:
        environment = {key: value for key, value in os.environ.items() if key != "SystemDrive"}
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(get_system_drive(), "C:\\")

    def test_non_windows_branch_uses_the_home_anchor(self) -> None:
        with patch("src.analyzer.os.name", "posix"), patch("src.analyzer.Path") as path_class:
            path_class.home.return_value = SimpleNamespace(anchor="/")
            self.assertEqual(get_system_drive(), "/")

    def test_non_windows_branch_falls_back_to_the_path_separator(self) -> None:
        with patch("src.analyzer.os.name", "posix"), patch("src.analyzer.Path") as path_class:
            path_class.home.return_value = SimpleNamespace(anchor="")
            self.assertEqual(get_system_drive(), os.sep)


class ProcessCountTests(unittest.TestCase):
    def test_counts_pids(self) -> None:
        self.assertEqual(get_process_count(FakePsutil()), 164)

    def test_failure_propagates_to_the_orchestrator(self) -> None:
        with self.assertRaises(OSError):
            get_process_count(FakePsutil(fail=("pids",)))


class BatteryTests(unittest.TestCase):
    def setUp(self) -> None:
        # The wear figures come from the machine running the suite otherwise, and a laptop
        # would then produce different assertions from a desktop.
        patcher = patch("src.analyzer.read_battery_health", return_value={})
        patcher.start()
        self.addCleanup(patcher.stop)

    def charging(self, **overrides: object) -> FakePsutil:
        fake = FakePsutil()
        fields: dict[str, object] = {"percent": 55.0, "power_plugged": False, "secsleft": 3600}
        fields.update(overrides)
        fake.battery = SimpleNamespace(**fields)
        return fake

    def test_desktop_without_a_battery(self) -> None:
        self.assertIsNone(get_battery(FakePsutil()))

    def test_platform_without_the_sensor_api(self) -> None:
        fake = FakePsutil()
        fake.sensors_battery = None  # type: ignore[assignment]
        self.assertIsNone(get_battery(fake))

    def test_battery_is_reported(self) -> None:
        fake = FakePsutil()
        fake.battery = SimpleNamespace(percent=55.0, power_plugged=False, secsleft=3600)
        battery = get_battery(fake)
        assert battery is not None
        self.assertEqual(battery.percent, 55.0)
        self.assertIs(battery.plugged_in, False)
        self.assertEqual(battery.seconds_left, 3600)

    def test_sentinel_and_negative_time_left_become_unknown(self) -> None:
        for secsleft in (FakePsutil.POWER_TIME_UNLIMITED, FakePsutil.POWER_TIME_UNKNOWN, None, -9):
            with self.subTest(secsleft=secsleft):
                fake = FakePsutil()
                fake.battery = SimpleNamespace(percent=90.0, power_plugged=True, secsleft=secsleft)
                battery = get_battery(fake)
                assert battery is not None
                self.assertIsNone(battery.seconds_left)
                self.assertIs(battery.plugged_in, True)

    def test_unknown_readings_stay_unknown(self) -> None:
        fake = FakePsutil()
        fake.battery = SimpleNamespace(percent=None, power_plugged=None, secsleft=None)
        battery = get_battery(fake)
        assert battery is not None
        self.assertIsNone(battery.percent)
        self.assertIsNone(battery.plugged_in)

    # -- wear: psutil says what the battery is doing, win_battery what it has become --------

    def test_wear_figures_enrich_the_live_reading(self) -> None:
        wear = {
            "design_capacity_mwh": 99_000,
            "full_charge_capacity_mwh": 74_250,
            "cycle_count": 231,
            "chemistry": "LION",
        }
        battery = get_battery(self.charging(), battery_health=lambda: wear)
        assert battery is not None
        self.assertEqual(battery.percent, 55.0)  # psutil still owns the live figures.
        self.assertEqual(battery.seconds_left, 3600)
        self.assertEqual(battery.design_capacity_mwh, 99_000)
        self.assertEqual(battery.full_charge_capacity_mwh, 74_250)
        self.assertEqual(battery.cycle_count, 231)
        self.assertEqual(battery.chemistry, "LION")
        self.assertEqual(battery.health_percent, 75.0)

    def test_a_battery_that_reports_no_wear_at_all_still_reports_its_charge(self) -> None:
        battery = get_battery(self.charging(), battery_health=dict)
        assert battery is not None
        self.assertEqual(battery.percent, 55.0)
        self.assertIsNone(battery.design_capacity_mwh)
        self.assertIsNone(battery.cycle_count)
        self.assertIsNone(battery.health_percent)  # Never estimated from the charge.

    def test_a_wear_reader_that_fails_costs_only_the_wear_figures(self) -> None:
        def broken() -> dict[str, object]:
            raise OSError("no ACPI battery device")

        battery = get_battery(self.charging(), battery_health=broken)
        assert battery is not None
        self.assertEqual(battery.percent, 55.0)
        self.assertIsNone(battery.full_charge_capacity_mwh)

    def test_figures_that_are_not_numbers_stay_unknown(self) -> None:
        nonsense = {
            "design_capacity_mwh": "plenty",
            "full_charge_capacity_mwh": True,  # bool is an int; a True capacity is a bug.
            "cycle_count": -4,
            "chemistry": 7,
        }
        battery = get_battery(self.charging(), battery_health=lambda: nonsense)
        assert battery is not None
        self.assertIsNone(battery.design_capacity_mwh)
        self.assertIsNone(battery.full_charge_capacity_mwh)
        self.assertIsNone(battery.cycle_count)
        self.assertIsNone(battery.chemistry)

    def test_a_capacity_of_zero_is_a_placeholder_not_an_empty_pack(self) -> None:
        # Firmware that does not track capacity reports zero, and "0 mWh" in the report would
        # read as a measurement. A cycle count of zero, on the other hand, is a new battery.
        wear = {"design_capacity_mwh": 0, "full_charge_capacity_mwh": 0, "cycle_count": 0}
        battery = get_battery(self.charging(), battery_health=lambda: wear)
        assert battery is not None
        self.assertIsNone(battery.design_capacity_mwh)
        self.assertIsNone(battery.full_charge_capacity_mwh)
        self.assertEqual(battery.cycle_count, 0)
        self.assertIsNone(battery.health_percent)

    def test_a_reader_that_answers_with_something_other_than_a_mapping_is_ignored(self) -> None:
        battery = get_battery(self.charging(), battery_health=lambda: "unavailable")
        assert battery is not None
        self.assertIsNone(battery.chemistry)

    def test_a_machine_with_no_battery_is_never_asked_about_wear(self) -> None:
        with patch("src.analyzer.read_battery_health") as reader:
            self.assertIsNone(get_battery(FakePsutil()))
        reader.assert_not_called()


class SecurityCollectorTests(unittest.TestCase):
    """The analyzer only forwards; win_security is where the verdicts are formed."""

    def test_the_state_is_forwarded_untouched(self) -> None:
        state = SecurityInfo(antivirus=STATE_GOOD, firewall=STATE_WEAK, secure_boot=STATE_GOOD)
        self.assertIs(get_security(lambda: state), state)

    def test_the_real_reader_is_used_by_default(self) -> None:
        with patch("src.analyzer.read_security_state", return_value=SecurityInfo()) as reader:
            self.assertIsNotNone(get_security())
        reader.assert_called_once_with()

    def test_an_answer_that_is_not_a_security_state_is_no_answer(self) -> None:
        self.assertIsNone(get_security(lambda: None))  # type: ignore[arg-type,return-value]

    def test_a_reader_that_raises_reaches_the_orchestrator(self) -> None:
        # analyze_pc turns this into a warning; swallowing it here would hide the failure.
        def broken() -> SecurityInfo:
            raise OSError("wscapi refused")

        with self.assertRaises(OSError):
            get_security(broken)


class DriveHealthCollectorTests(unittest.TestCase):
    """Which drives are asked about, and the single source of the media type."""

    def setUp(self) -> None:
        _MEDIA_TYPE_CACHE.clear()  # The cache outlives a test; the next one must not inherit it.
        self.addCleanup(_MEDIA_TYPE_CACHE.clear)

    def test_the_requested_drives_are_passed_through(self) -> None:
        with patch("src.analyzer.read_drive_health", return_value=[]) as reader:
            get_drive_health(FakePsutil(), drives=["C:\\", "D:\\"])
        reader.assert_called_once_with(["C:\\", "D:\\"])

    def test_without_a_list_the_drives_psutil_reports_are_used(self) -> None:
        with patch("src.analyzer.read_drive_health", return_value=[]) as reader:
            get_drive_health(FakePsutil())
        reader.assert_called_once_with(["C:\\"])

    def test_optical_drives_are_never_asked_about(self) -> None:
        fake = FakePsutil()
        fake.partitions = [
            SimpleNamespace(device="C:\\", mountpoint="C:\\", fstype="NTFS", opts="rw,fixed"),
            SimpleNamespace(device="E:\\", mountpoint="E:\\", fstype="CDFS", opts="ro,cdrom"),
        ]
        with patch("src.analyzer.read_drive_health", return_value=[]) as reader:
            get_drive_health(fake)
        reader.assert_called_once_with(["C:\\"])

    def test_a_psutil_that_cannot_list_drives_lets_win_storage_enumerate(self) -> None:
        with patch("src.analyzer.read_drive_health", return_value=[]) as reader:
            get_drive_health(FakePsutil(fail=("disk_partitions",)))
        reader.assert_called_once_with(None)

    @unittest.skipUnless(IS_WINDOWS, "the media type is a Windows query")
    def test_the_media_type_has_exactly_one_source(self) -> None:
        # Until v2.1 the seek-penalty IOCTL lived in two places, so one drive could read
        # "SSD" beside its free space and something else beside its wear figures.
        entry = DriveHealth(drive="C:\\", media_type="HDD")
        with patch("src.analyzer.read_drive_health", return_value=[entry]) as reader:
            self.assertEqual(detect_media_type("C:\\"), "HDD")
        reader.assert_called_once_with(["C:\\"])

    @unittest.skipUnless(IS_WINDOWS, "the media type is a Windows query")
    def test_a_drive_win_storage_cannot_describe_is_unknown_not_a_guess(self) -> None:
        with patch("src.analyzer.read_drive_health", return_value=[]):
            self.assertIsNone(detect_media_type("C:\\"))

    @unittest.skipUnless(IS_WINDOWS, "the media type is a Windows query")
    def test_a_failing_query_never_reaches_the_caller(self) -> None:
        with patch("src.analyzer.read_drive_health", side_effect=OSError("device gone")):
            self.assertIsNone(detect_media_type("C:\\"))

    @unittest.skipUnless(IS_WINDOWS, "the media type is a Windows query")
    def test_the_answer_is_read_once_per_drive(self) -> None:
        entry = DriveHealth(drive="C:\\", media_type="SSD")
        with patch("src.analyzer.read_drive_health", return_value=[entry]) as reader:
            for _ in range(3):
                self.assertEqual(detect_media_type("c:\\"), "SSD")
        self.assertEqual(reader.call_count, 1)

    def test_a_path_that_is_not_a_lettered_drive_is_never_queried(self) -> None:
        with patch("src.analyzer.read_drive_health") as reader:
            self.assertIsNone(detect_media_type(r"\\server\share"))
        reader.assert_not_called()


class FolderUsageCollectorTests(unittest.TestCase):
    def test_the_budget_and_the_limit_are_forwarded(self) -> None:
        folders = [FolderUsage("downloads", "Downloads", r"C:\Users\Test\Downloads", 3 * GIB, 9)]
        with patch("src.analyzer.read_folder_usage", return_value=folders) as reader:
            self.assertEqual(get_folder_usage(max_seconds=2.0, limit=3), folders)
        reader.assert_called_once_with(max_seconds=2.0, limit=3)

    def test_the_defaults_match_the_documented_contract(self) -> None:
        with patch("src.analyzer.read_folder_usage", return_value=[]) as reader:
            get_folder_usage()
        reader.assert_called_once_with(max_seconds=None, limit=8)


class ScanBudgetTests(unittest.TestCase):
    """One budget for all folder measuring, so v2.1 cannot double the length of a run."""

    def test_temp_takes_its_share_unless_the_caller_says_otherwise(self) -> None:
        self.assertEqual(_temp_budget(None), TOTAL_SCAN_SECONDS * 0.5)
        self.assertEqual(_temp_budget(3.0), 3.0)
        self.assertEqual(_temp_budget(-1.0), 0.0)

    def test_the_folder_scan_inherits_whatever_temp_did_not_need(self) -> None:
        self.assertEqual(_folder_budget(None, 0.0), TOTAL_SCAN_SECONDS)
        self.assertEqual(_folder_budget(None, 3.0), TOTAL_SCAN_SECONDS - 3.0)

    def test_the_folder_scan_always_gets_a_real_chance(self) -> None:
        # A caller who spends the whole budget on TEMP would otherwise leave the folders a
        # zero-second scan, which reports "0 bytes, truncated" - a number nobody can act on.
        self.assertGreaterEqual(_folder_budget(None, 99.0), 1.0)

    def test_an_explicit_budget_wins(self) -> None:
        self.assertEqual(_folder_budget(2.5, 3.0), 2.5)
        self.assertEqual(_folder_budget(-2.0, 0.0), 0.0)

    def test_the_two_scans_cannot_outlast_the_shared_budget(self) -> None:
        for elapsed in (0.0, 0.5, 2.0, 4.0, TOTAL_SCAN_SECONDS):
            with self.subTest(temp_seconds=elapsed):
                self.assertLessEqual(
                    elapsed + _folder_budget(None, elapsed),
                    TOTAL_SCAN_SECONDS + 1.0,  # the floor is the only permitted overrun
                )


class NetworkTests(unittest.TestCase):
    def test_counters_and_interface_ordering(self) -> None:
        fake = FakePsutil()
        fake.if_stats = {
            "Bluetooth": SimpleNamespace(isup=False, speed=3),
            "Wi-Fi": SimpleNamespace(isup=True, speed=0),
            "Ethernet": SimpleNamespace(isup=True, speed=1000),
            "lo": SimpleNamespace(isup=True, speed=0),
            "Loopback Pseudo-Interface 1": SimpleNamespace(isup=True, speed=1000),
        }
        network = get_network(fake)
        self.assertEqual(network.bytes_sent, 12 * GIB)
        self.assertEqual(network.bytes_received, 48 * GIB)
        # Up first, then fastest, then alphabetical; loopback adapters are never listed.
        names = [item.name for item in network.interfaces]
        self.assertEqual(names, ["Ethernet", "Wi-Fi", "Bluetooth"])
        self.assertEqual(network.interfaces[0].speed_mbps, 1000)
        self.assertIsNone(network.interfaces[1].speed_mbps)  # A 0 Mbps link speed means unknown.

    def test_interface_list_is_capped(self) -> None:
        fake = FakePsutil()
        fake.if_stats = {
            f"Adapter {index:02d}": SimpleNamespace(isup=True, speed=100) for index in range(12)
        }
        self.assertEqual(len(get_network(fake).interfaces), 8)

    def test_failing_counters_still_return_interfaces(self) -> None:
        network = get_network(FakePsutil(fail=("net_io_counters",)))
        self.assertIsNone(network.bytes_sent)
        self.assertIsNone(network.bytes_received)
        self.assertEqual([item.name for item in network.interfaces], ["Ethernet"])

    def test_failing_interface_stats_still_return_counters(self) -> None:
        network = get_network(FakePsutil(fail=("net_if_stats",)))
        self.assertEqual(network.bytes_sent, 12 * GIB)
        self.assertEqual(network.interfaces, ())

    def test_platform_without_network_apis(self) -> None:
        fake = FakePsutil()
        fake.net_io_counters = None  # type: ignore[assignment]
        fake.net_if_stats = None  # type: ignore[assignment]
        network = get_network(fake)
        self.assertIsNone(network.bytes_sent)
        self.assertEqual(network.interfaces, ())

    def test_missing_counter_object_is_not_invented(self) -> None:
        fake = FakePsutil()
        fake.net_counters = None
        self.assertIsNone(get_network(fake).bytes_received)


class UptimeTests(unittest.TestCase):
    def test_uptime_is_now_minus_boot_time(self) -> None:
        self.assertEqual(get_uptime(FakePsutil(), now=250_000.0), 150_000.0)

    def test_clock_skew_never_produces_a_negative_uptime(self) -> None:
        self.assertEqual(get_uptime(FakePsutil(), now=1.0), 0.0)

    def test_default_now_uses_the_wall_clock(self) -> None:
        with patch("src.analyzer.time.time", return_value=200_000.0):
            self.assertEqual(get_uptime(FakePsutil()), 100_000.0)


class TempFolderTests(unittest.TestCase):
    def test_get_temp_size_measures_the_given_folder(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "temp.bin").write_bytes(b"x" * 23)
            path, size = get_temp_size(folder)
        self.assertEqual(path, folder)
        self.assertEqual(size, 23)

    def test_get_temp_size_defaults_to_the_resolved_temp_folder(self) -> None:
        # Was asserted against tempfile.gettempdir() until v2.0. That call creates, writes
        # and deletes a probe file, which a read-only analyzer may not do, so the collector
        # now reads the environment and the test follows it there.
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "temp.bin").write_bytes(b"x" * 11)
            with temp_environment(TMP=folder):
                path, size = get_temp_size()
        self.assertEqual(path, folder)
        self.assertEqual(size, 11)

    def test_user_temp_is_always_first(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "a.bin").write_bytes(b"x" * 9)
            with patch("src.analyzer._windows_temp_folder", return_value=None):
                locations = get_temp_locations(temp_path=folder)
        self.assertEqual(len(locations), 1)
        self.assertEqual(locations[0].label, "User TEMP")
        self.assertEqual(locations[0].path, folder)
        self.assertEqual(locations[0].size_bytes, 9)
        self.assertEqual(locations[0].file_count, 1)
        self.assertFalse(locations[0].truncated)

    def test_machine_wide_temp_is_added_when_readable(self) -> None:
        with tempfile.TemporaryDirectory() as user, tempfile.TemporaryDirectory() as machine:
            Path(user, "a.bin").write_bytes(b"x" * 4)
            Path(machine, "b.bin").write_bytes(b"y" * 6)
            with patch("src.analyzer._windows_temp_folder", return_value=machine):
                locations = get_temp_locations(temp_path=user)
        self.assertEqual([item.label for item in locations], ["User TEMP", "Windows TEMP"])
        self.assertEqual([item.size_bytes for item in locations], [4, 6])

    def test_the_same_folder_is_not_measured_twice(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with patch("src.analyzer._windows_temp_folder", return_value=folder):
                locations = get_temp_locations(temp_path=folder)
        self.assertEqual(len(locations), 1)

    def test_time_budget_is_split_between_locations(self) -> None:
        recorded: list[float | None] = []

        def fake_scan(path: object, *, max_seconds: float | None = None) -> tuple[int, int, bool]:
            recorded.append(max_seconds)
            return 0, 0, False

        with tempfile.TemporaryDirectory() as user, tempfile.TemporaryDirectory() as machine:
            with patch("src.analyzer._windows_temp_folder", return_value=machine), patch(
                "src.analyzer.scan_folder", side_effect=fake_scan
            ):
                get_temp_locations(temp_path=user, max_seconds=4.0)
        self.assertEqual(recorded, [2.0, 2.0])

    def test_unreadable_folder_reports_no_size_instead_of_zero(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with patch("src.analyzer._windows_temp_folder", return_value=None), patch(
                "src.analyzer.scan_folder", side_effect=OSError("denied")
            ):
                locations = get_temp_locations(temp_path=folder)
        self.assertEqual(len(locations), 1)
        self.assertIsNone(locations[0].size_bytes)
        self.assertIsNone(locations[0].file_count)

    def test_a_missing_folder_is_unknown_rather_than_empty(self) -> None:
        # scan_folder answers (0, 0, False) for a path that is not there, which would score
        # a broken TMP as a spotlessly clean TEMP - the one place the app used to invent a
        # measurement. The folder is never scanned at all now.
        missing = os.path.join("Z:" + os.sep, "nonexistent", "apoliak-temp-probe")
        with patch("src.analyzer._windows_temp_folder", return_value=None), patch(
            "src.analyzer.scan_folder"
        ) as scan:
            locations = get_temp_locations(temp_path=missing)
        scan.assert_not_called()
        self.assertEqual(len(locations), 1)
        self.assertEqual(locations[0].path, missing)
        self.assertIsNone(locations[0].size_bytes)
        self.assertIsNone(locations[0].file_count)
        self.assertFalse(locations[0].truncated)

    def test_a_path_that_is_not_a_folder_is_unknown_too(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder, "temp.bin")
            target.write_bytes(b"x" * 23)
            with patch("src.analyzer._windows_temp_folder", return_value=None):
                locations = get_temp_locations(temp_path=str(target))
        # A TMP variable pointing at a file is broken, and 23 bytes would be the size of the
        # file rather than of a temp folder.
        self.assertIsNone(locations[0].size_bytes)

    def test_a_folder_that_cannot_be_listed_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with patch("src.analyzer._windows_temp_folder", return_value=None), patch(
                "src.analyzer.os.scandir", side_effect=PermissionError("access denied")
            ):
                locations = get_temp_locations(temp_path=folder)
        self.assertIsNone(locations[0].size_bytes)

    def test_an_empty_but_readable_folder_is_still_measured_as_zero(self) -> None:
        # The opposite mistake would be just as bad: an empty TEMP really is 0 bytes.
        with tempfile.TemporaryDirectory() as folder:
            with patch("src.analyzer._windows_temp_folder", return_value=None):
                locations = get_temp_locations(temp_path=folder)
        self.assertEqual(locations[0].size_bytes, 0)
        self.assertEqual(locations[0].file_count, 0)


class TempPathResolutionTests(unittest.TestCase):
    """Resolving TEMP must read the environment, never probe the folder by writing to it.

    ``tempfile.gettempdir()`` proves a candidate works by creating, writing and deleting a
    file inside it. The app promises it writes nothing, so the variables come first and the
    standard library is only the last resort. The assertions below are made through the
    environment on purpose: watching the file system would pass just as happily on a machine
    whose TEMP folder is read-only.
    """

    FAKE = os.path.join("Z:" + os.sep, "nonexistent", "apoliak-temp-probe")

    def test_tmp_is_preferred(self) -> None:
        with temp_environment(TMP=self.FAKE, TEMP="ignored-temp", TMPDIR="ignored-tmpdir"):
            self.assertEqual(_default_temp_path(), self.FAKE)

    def test_temp_is_used_when_tmp_is_absent(self) -> None:
        with temp_environment(TEMP=self.FAKE, TMPDIR="ignored-tmpdir"):
            self.assertEqual(_default_temp_path(), self.FAKE)

    def test_tmpdir_is_the_last_variable_tried(self) -> None:
        with temp_environment(TMPDIR=self.FAKE):
            self.assertEqual(_default_temp_path(), self.FAKE)

    def test_a_blank_variable_is_skipped_instead_of_returned(self) -> None:
        with temp_environment(TMP="   ", TEMP="", TMPDIR=self.FAKE):
            self.assertEqual(_default_temp_path(), self.FAKE)

    def test_the_standard_library_is_never_asked_when_a_variable_is_set(self) -> None:
        with temp_environment(TMP=self.FAKE):
            with patch("src.analyzer.tempfile.gettempdir") as probe:
                resolved = _default_temp_path()
        self.assertEqual(resolved, self.FAKE)
        probe.assert_not_called()  # Calling it would write a probe file into TEMP.

    def test_an_environment_without_any_variable_falls_back_to_the_library(self) -> None:
        with temp_environment():
            with patch("src.analyzer.tempfile.gettempdir", return_value=self.FAKE) as probe:
                resolved = _default_temp_path()
        self.assertEqual(resolved, self.FAKE)
        probe.assert_called_once_with()

    def test_the_folder_named_by_the_environment_is_the_one_measured(self) -> None:
        # End to end: the value read from the environment is what the collector scans, so
        # the reported size can never belong to a folder the user does not use.
        with tempfile.TemporaryDirectory() as folder:
            Path(folder, "a.bin").write_bytes(b"x" * 7)
            with temp_environment(TMP=folder):
                with patch("src.analyzer._windows_temp_folder", return_value=None):
                    locations = get_temp_locations()
        self.assertEqual([item.path for item in locations], [folder])
        self.assertEqual(locations[0].size_bytes, 7)


class SystemInfoTests(unittest.TestCase):
    WINDOWS_DETAILS = {
        "product_name": "Windows 10 Pro",  # Windows 11 still reports "10" here.
        "edition": "Professional",
        "display_version": "24H2",
        "build": "26100.4652",
        "install_date": datetime(2025, 1, 5, 9, 0, tzinfo=timezone.utc),
    }
    FIRMWARE = {"manufacturer": "ASUS", "model": "ROG STRIX", "bios_version": "1.24"}

    def test_windows_marketing_name_comes_from_the_build_number(self) -> None:
        cases = {
            "10.0.26100": "11",
            "10.0.22000": "11",
            "10.0.21999": "10",
            "10.0.19045": "10",
            "10.0.10240": "10",
            "6.1.7601": "fallback",
            "not-a-version": "fallback",
        }
        for version, expected in cases.items():
            with self.subTest(version=version):
                self.assertEqual(_windows_release(version, "fallback"), expected)

    def test_windows_marketing_name_without_a_usable_fallback(self) -> None:
        self.assertEqual(_windows_release("", ""), "Unknown")
        self.assertEqual(_windows_release("6.1.7601", ""), "Unknown")

    def test_edition_label_prefers_the_product_name(self) -> None:
        cases = {
            ("Windows 10 Pro", "Professional"): "Pro",
            ("Windows 11 Home Single Language", None): "Home Single Language",
            ("Windows Vista Ultimate", None): "Ultimate",
            (None, "Professional"): "Pro",
            (None, "CoreSingleLanguage"): "Home Single Language",
            (None, "SomethingNew"): "SomethingNew",
            ("Microsoft Windows", "Enterprise"): "Enterprise",
            (None, None): None,
        }
        for (product_name, edition_id), expected in cases.items():
            with self.subTest(product_name=product_name, edition_id=edition_id):
                self.assertEqual(_edition_label(product_name, edition_id), expected)

    def test_windows_system_info(self) -> None:
        with patch("src.analyzer.platform.system", return_value="Windows"), patch(
            "src.analyzer.platform.version", return_value="10.0.26100"
        ), patch("src.analyzer.platform.release", return_value="10"), patch(
            "src.analyzer.platform.machine", return_value="AMD64"
        ), patch(
            "src.win_registry.windows_edition_details", return_value=dict(self.WINDOWS_DETAILS)
        ), patch(
            "src.win_registry.read_firmware", return_value=dict(self.FIRMWARE)
        ), patch(
            "src.win_registry.read_processor_name", return_value="Intel Core i7-1165G7"
        ):
            info = get_system_info()
        self.assertEqual(info.os_name, "Windows 11 Pro")
        self.assertEqual(info.release, "11")
        self.assertEqual(info.edition, "Pro")
        self.assertEqual(info.display_version, "24H2")
        self.assertEqual(info.build, "26100.4652")
        self.assertEqual(info.architecture, "AMD64")
        self.assertEqual(info.processor, "Intel Core i7-1165G7")
        self.assertEqual(info.manufacturer, "ASUS")
        self.assertEqual(info.model, "ROG STRIX")
        self.assertEqual(info.bios_version, "1.24")
        self.assertIsNone(info.boot_time)  # analyze_pc fills this in.

    def test_non_windows_system_info_has_no_registry_fields(self) -> None:
        with patch("src.analyzer.platform.system", return_value="Linux"), patch(
            "src.analyzer.platform.release", return_value="6.1.0"
        ), patch("src.analyzer.platform.version", return_value="#1 SMP"), patch(
            "src.analyzer.platform.machine", return_value="x86_64"
        ), patch(
            "src.win_registry.read_processor_name", return_value=None
        ):
            info = get_system_info()
        self.assertEqual(info.os_name, "Linux 6.1.0")
        self.assertIsNone(info.edition)
        self.assertIsNone(info.build)
        self.assertIsNone(info.manufacturer)

    def test_architecture_falls_back_when_machine_is_empty(self) -> None:
        with patch("src.analyzer.platform.system", return_value="Linux"), patch(
            "src.analyzer.platform.machine", return_value=""
        ), patch("src.analyzer.platform.architecture", return_value=("64bit", "ELF")), patch(
            "src.win_registry.read_processor_name", return_value=None
        ):
            self.assertEqual(get_system_info().architecture, "64bit")

    def test_processor_name_prefers_the_registry(self) -> None:
        # The registry lookup already normalises whitespace, so the value is used verbatim.
        with patch("src.win_registry.read_processor_name", return_value="AMD Ryzen 7 5800X"):
            self.assertEqual(_processor_name(), "AMD Ryzen 7 5800X")

    def test_processor_name_falls_back_to_platform_then_environment(self) -> None:
        with patch("src.win_registry.read_processor_name", return_value=None), patch(
            "src.analyzer.platform.processor", return_value="  Intel64   Family 6  "
        ):
            self.assertEqual(_processor_name(), "Intel64 Family 6")

        with patch("src.win_registry.read_processor_name", return_value=None), patch(
            "src.analyzer.platform.processor", return_value=""
        ), patch(
            "src.analyzer.platform.uname",
            return_value=SimpleNamespace(processor="", machine="AMD64"),
        ), patch.dict(
            os.environ, {"PROCESSOR_IDENTIFIER": "Intel64 Family 6 Model 140"}, clear=True
        ):
            self.assertEqual(_processor_name(), "Intel64 Family 6 Model 140")

    def test_processor_name_is_unknown_when_nothing_answers(self) -> None:
        with patch("src.win_registry.read_processor_name", return_value=None), patch(
            "src.analyzer.platform.processor", return_value=""
        ), patch(
            "src.analyzer.platform.uname", return_value=SimpleNamespace(processor="")
        ), patch(
            "src.analyzer.platform.machine", return_value=""
        ), patch.dict(
            os.environ, {}, clear=True
        ):
            self.assertEqual(_processor_name(), "Unknown")


class TopProcessesTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch("src.processes.time.sleep")  # The CPU ranking sleeps between samples.
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_memory_ranking_is_descending_with_alphabetical_ties(self) -> None:
        fake = FakePsutil()
        fake.processes = [
            FakeProcess(11, "small.exe", rss=100, memory_percent=0.1),
            FakeProcess(12, "beta.exe", rss=900, memory_percent=5.0),
            FakeProcess(13, "alpha.exe", rss=900, memory_percent=5.0),
            FakeProcess(14, "huge.exe", rss=4000, memory_percent=25.0),
        ]
        ranked = top_processes(fake, limit=4, sort_by="memory")
        names = [item.name for item in ranked]
        self.assertEqual(names, ["huge.exe", "alpha.exe", "beta.exe", "small.exe"])
        self.assertEqual(ranked[0].memory_bytes, 4000)
        self.assertEqual(ranked[0].memory_percent, 25.0)
        self.assertIsNone(ranked[0].cpu_percent)  # A memory ranking never samples the CPU.

    def test_limit_truncates_the_ranking(self) -> None:
        fake = FakePsutil()
        fake.processes = [FakeProcess(index, f"p{index}.exe", rss=index) for index in range(1, 9)]
        self.assertEqual(len(top_processes(fake, limit=3)), 3)

    def test_zero_or_negative_limit_returns_nothing(self) -> None:
        fake = FakePsutil()
        fake.processes = [FakeProcess(1, "a.exe", rss=10)]
        self.assertEqual(top_processes(fake, limit=0), [])
        self.assertEqual(top_processes(fake, limit=-3), [])

    def test_cpu_ranking_uses_a_second_sample_scaled_by_core_count(self) -> None:
        fake = FakePsutil()
        fake.logical = 4
        fake.processes = [
            FakeProcess(21, "idle.exe", rss=10, cpu_samples=[0.0, 0.0]),
            FakeProcess(22, "busy.exe", rss=20, cpu_samples=[0.0, 200.0]),
            FakeProcess(23, "medium.exe", rss=30, cpu_samples=[0.0, 100.0]),
        ]
        ranked = top_processes(fake, limit=3, sort_by="cpu")
        self.assertEqual([item.name for item in ranked], ["busy.exe", "medium.exe", "idle.exe"])
        self.assertEqual([item.cpu_percent for item in ranked], [50.0, 25.0, 0.0])

    def test_cpu_percentages_are_clamped_to_one_hundred(self) -> None:
        fake = FakePsutil()
        fake.logical = 4
        fake.processes = [FakeProcess(31, "runaway.exe", rss=1, cpu_samples=[0.0, 8000.0])]
        self.assertEqual(top_processes(fake, limit=1, sort_by="cpu")[0].cpu_percent, 100.0)

    def test_unknown_core_count_scales_by_one(self) -> None:
        fake = FakePsutil(fail=("cpu_count",))
        fake.processes = [FakeProcess(41, "busy.exe", rss=1, cpu_samples=[0.0, 30.0])]
        self.assertEqual(top_processes(fake, limit=1, sort_by="cpu")[0].cpu_percent, 30.0)

    def test_a_process_that_dies_during_sampling_keeps_an_unknown_cpu_share(self) -> None:
        fake = FakePsutil()
        fake.logical = 1
        fake.processes = [
            FakeProcess(51, "gone.exe", rss=10),
            FakeProcess(52, "alive.exe", rss=20, cpu_samples=[0.0, 40.0]),
        ]
        # The priming call succeeds, the second sample raises - exactly how a process that
        # exits between the two readings behaves.
        calls = {"count": 0}

        def flaky() -> float:
            calls["count"] += 1
            if calls["count"] > 1:
                raise RuntimeError("process vanished")
            return 0.0

        fake.processes[0].cpu_percent = flaky  # type: ignore[assignment]
        ranked = top_processes(fake, limit=2, sort_by="cpu")
        by_name = {item.name: item for item in ranked}
        self.assertEqual(by_name["alive.exe"].cpu_percent, 40.0)
        self.assertIsNone(by_name["gone.exe"].cpu_percent)

    def test_denied_dead_and_synthetic_processes_are_skipped(self) -> None:
        fake = FakePsutil()
        fake.processes = [
            VanishedProcess(),
            FakeProcess(0, "System Idle Process", rss=0),  # PID 0 is not a real program.
            FakeProcess(61, "denied.exe", rss=None, memory_percent=None),  # ad_value=None fields.
            FakeProcess(62, "good.exe", rss=500, memory_percent=3.0),
            FakeProcess(63, "broken.exe", info={"pid": None, "name": "broken.exe"}),
        ]
        ranked = top_processes(fake, limit=10)
        self.assertEqual([item.name for item in ranked], ["good.exe", "denied.exe"])
        self.assertIsNone(ranked[1].memory_bytes)

    def test_a_nameless_process_is_labelled_by_pid(self) -> None:
        fake = FakePsutil()
        fake.processes = [FakeProcess(71, "", rss=5)]
        self.assertEqual(top_processes(fake, limit=1)[0].name, "PID 71")

    def test_an_iterator_that_fails_midway_keeps_what_it_found(self) -> None:
        fake = FakePsutil()
        collected = [FakeProcess(81, "first.exe", rss=10), FakeProcess(82, "second.exe", rss=20)]

        def exploding_iter(attrs: object = None, ad_value: object = None) -> object:
            def generator() -> object:
                yield from collected
                raise RuntimeError("process table changed")

            return generator()

        fake.process_iter = exploding_iter  # type: ignore[assignment]
        ranked = top_processes(fake, limit=5)
        self.assertEqual([item.name for item in ranked], ["second.exe", "first.exe"])

    def test_unusable_modules_yield_an_empty_ranking(self) -> None:
        no_iter = FakePsutil()
        no_iter.process_iter = None  # type: ignore[assignment]
        self.assertEqual(top_processes(no_iter), [])
        self.assertEqual(top_processes(FakePsutil(fail=("process_iter",))), [])
        with patch("src.processes._psutil", None):
            self.assertEqual(top_processes(), [])

    def test_unknown_sort_key_falls_back_to_memory(self) -> None:
        fake = FakePsutil()
        fake.processes = [
            FakeProcess(91, "small.exe", rss=10),
            FakeProcess(92, "large.exe", rss=99),
        ]
        for sort_by in ("nonsense", "MEMORY", None, 7):
            with self.subTest(sort_by=sort_by):
                ranked = top_processes(fake, limit=2, sort_by=sort_by)  # type: ignore[arg-type]
                self.assertEqual(ranked[0].name, "large.exe")

    def test_result_items_are_process_info_records(self) -> None:
        fake = FakePsutil()
        fake.processes = [FakeProcess(101, "a.exe", rss=1)]
        self.assertIsInstance(top_processes(fake, limit=1)[0], ProcessInfo)


class WinRegistryTests(unittest.TestCase):
    """The module must return its documented shapes on every platform, and never raise."""

    def assert_edition_shape(self, details: object) -> None:
        self.assertIsInstance(details, dict)
        assert isinstance(details, dict)
        self.assertEqual(
            set(details),
            {"product_name", "edition", "display_version", "build", "install_date"},
        )
        for name in ("product_name", "edition", "display_version", "build"):
            self.assertIsInstance(details[name], (str, type(None)), name)
        self.assertIsInstance(details["install_date"], (datetime, type(None)))

    @unittest.skipUnless(IS_WINDOWS, "Reads the real Windows registry")
    def test_real_reads_return_documented_shapes(self) -> None:
        self.assert_edition_shape(win_registry.windows_edition_details())

        gpus = win_registry.read_gpus()
        self.assertIsInstance(gpus, list)
        self.assertLessEqual(len(gpus), 4)
        for gpu in gpus:
            self.assertIsInstance(gpu, GPUInfo)
            self.assertTrue(gpu.name)

        items = win_registry.read_startup_items()
        self.assertIsInstance(items, list)
        self.assertLessEqual(len(items), 60)
        for item in items:
            self.assertIsInstance(item, StartupItem)
            self.assertTrue(item.name and item.source)

        firmware = win_registry.read_firmware()
        self.assertEqual(set(firmware), {"manufacturer", "model", "bios_version"})
        for value in firmware.values():
            self.assertIsInstance(value, (str, type(None)))

        self.assertIsInstance(win_registry.read_processor_name(), (str, type(None)))

    def test_non_windows_returns_empty_results(self) -> None:
        with patch("src.win_registry.platform.system", return_value="Linux"), patch.dict(
            os.environ, {}, clear=True
        ):
            details = win_registry.windows_edition_details()
            self.assert_edition_shape(details)
            self.assertTrue(all(value is None for value in details.values()))
            self.assertEqual(win_registry.read_gpus(), [])
            self.assertEqual(win_registry.read_startup_items(), [])
            self.assertEqual(
                win_registry.read_firmware(),
                {"manufacturer": None, "model": None, "bios_version": None},
            )
            self.assertIsNone(win_registry.read_processor_name())

    def test_startup_folder_entries_are_listed_without_the_registry(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            startup = os.path.join(folder, win_registry._STARTUP_SUBPATH)
            os.makedirs(startup)
            Path(startup, "Sync Client.lnk").write_bytes(b"")
            Path(startup, "desktop.ini").write_bytes(b"")
            with patch("src.win_registry.platform.system", return_value="Linux"), patch.dict(
                os.environ, {"APPDATA": folder}, clear=True
            ):
                items = win_registry.read_startup_items()
        self.assertEqual([item.name for item in items], ["Sync Client"])
        self.assertEqual(items[0].source, "Startup folder (user)")

    def test_value_cleaning(self) -> None:
        self.assertIsNone(win_registry._clean(None))
        self.assertIsNone(win_registry._clean("   "))
        self.assertEqual(win_registry._clean("  a   b "), "a b")
        self.assertEqual(win_registry._clean(["x", "", "y"]), "x y")
        self.assertEqual(win_registry._clean(123), "123")

    def test_oem_placeholders_are_dropped(self) -> None:
        placeholders = ("Default string", "To Be Filled By O.E.M.", "System Product Name", "None")
        for placeholder in placeholders:
            with self.subTest(placeholder=placeholder):
                self.assertIsNone(win_registry._meaningful(placeholder))
        self.assertEqual(win_registry._meaningful("  ASUS  "), "ASUS")

    def test_build_composition(self) -> None:
        self.assertEqual(win_registry._compose_build("26100", 4652), "26100.4652")
        self.assertEqual(win_registry._compose_build("26100", None), "26100")
        self.assertEqual(win_registry._compose_build("26100", "not a number"), "26100")
        self.assertIsNone(win_registry._compose_build(None, 4652))

    def test_install_date_conversion(self) -> None:
        for invalid in (None, 0, -1, "not a timestamp"):
            with self.subTest(value=invalid):
                self.assertIsNone(win_registry._to_local_datetime(invalid))
        converted = win_registry._to_local_datetime(1_700_000_000)
        self.assertIsInstance(converted, datetime)
        assert converted is not None
        self.assertIsNotNone(converted.tzinfo)

    def test_driver_date_normalisation(self) -> None:
        self.assertEqual(win_registry._normalise_driver_date("6-21-2006"), "2006-06-21")
        self.assertEqual(win_registry._normalise_driver_date("12-31-1999 00:00:00"), "1999-12-31")
        self.assertEqual(win_registry._normalise_driver_date("a-b-c"), "a-b-c")
        self.assertEqual(win_registry._normalise_driver_date("whenever"), "whenever")
        self.assertIsNone(win_registry._normalise_driver_date(None))


class AnalyzePcTests(unittest.TestCase):
    """End-to-end orchestration: warnings instead of exceptions, always a full snapshot."""

    GPUS = [GPUInfo("Test Graphics 700", "31.0.0.1", "2025-03-14", 8 * GIB)]
    STARTUP = [StartupItem("Autostart 1", "HKCU Run", "app.exe")]

    def setUp(self) -> None:
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        Path(self.folder.name, "temp.bin").write_bytes(b"x" * 23)

        # The v2.1 collectors are stood in for here for the same reason psutil is faked: a
        # test describes a machine rather than the one it happens to run on. The folder scan
        # is the pressing one - measuring a real user profile would put seconds on every test
        # in this class - but a real Security Center answer would make the assertions below
        # depend on whether the machine running them has an antivirus installed.
        for target, value in (
            ("src.analyzer.detect_media_type", "SSD"),
            ("src.analyzer._windows_temp_folder", None),
            ("src.analyzer.read_security_state", SecurityInfo()),
            ("src.analyzer.read_drive_health", []),
            ("src.analyzer.read_folder_usage", []),
            ("src.analyzer.read_battery_health", {}),
            ("src.win_registry.read_gpus", list(self.GPUS)),
            ("src.win_registry.read_startup_items", list(self.STARTUP)),
        ):
            patcher = patch(target, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def analyze(self, fake: object, **overrides: object) -> object:
        arguments: dict[str, object] = {
            "psutil_module": fake,
            "cpu_interval": 0,
            "drive": "C:\\",
            "temp_path": self.folder.name,
        }
        arguments.update(overrides)
        return analyze_pc(**arguments)  # type: ignore[arg-type]

    def test_complete_analysis(self) -> None:
        fake = FakePsutil()
        fake.battery = SimpleNamespace(percent=88.0, power_plugged=True, secsleft=-2)
        fake.processes = [FakeProcess(200, "chrome.exe", rss=2 * GIB, memory_percent=12.5)]
        analyzed_at = datetime(2026, 7, 16, 10, 0, tzinfo=timezone.utc)
        with patch("src.analyzer.time.time", return_value=200_000.0):
            result = self.analyze(fake, analyzed_at=analyzed_at)

        self.assertEqual(result.analyzed_at, analyzed_at)
        self.assertEqual(result.schema_version, SCHEMA_VERSION)
        self.assertEqual(result.process_count, 164)
        self.assertEqual(result.temp_size_bytes, 23)
        self.assertEqual(result.temp_path, self.folder.name)
        self.assertEqual(result.uptime_seconds, 100_000.0)
        self.assertEqual(result.warnings, ())
        self.assertEqual(result.cpu.usage_percent, 25.0)
        self.assertEqual(result.ram.swap_percent, 12.5)
        self.assertEqual(result.disk.free_bytes, 112 * GIB)
        self.assertEqual([item.drive for item in result.partitions], ["C:\\"])
        self.assertEqual([item.name for item in result.top_processes], ["chrome.exe"])
        self.assertIsNotNone(result.battery)
        self.assertIsNotNone(result.network)
        self.assertEqual(result.gpus, tuple(self.GPUS))
        self.assertEqual(result.startup_items, tuple(self.STARTUP))
        self.assertEqual([item.label for item in result.temp_locations], ["User TEMP"])
        self.assertIsNotNone(result.system.boot_time)

    def test_duration_is_measured(self) -> None:
        result = self.analyze(FakePsutil())
        self.assertIsNotNone(result.duration_seconds)
        self.assertGreaterEqual(result.duration_seconds, 0.0)
        self.assertLess(result.duration_seconds, 60.0)

    def test_every_collector_failure_becomes_a_readable_warning(self) -> None:
        cases: tuple[tuple[str, dict[str, object], str], ...] = (
            ("system", {"target": "src.analyzer.get_system_info"}, "System information"),
            ("cpu", {"fail": "cpu_percent"}, "CPU information"),
            ("ram", {"fail": "virtual_memory"}, "RAM information"),
            ("disk", {"fail": "disk_usage"}, "Disk information"),
            ("partitions", {"target": "src.analyzer.get_partitions"}, "Drive list"),
            ("process_count", {"fail": "pids"}, "Running processes"),
            ("top_processes", {"target": "src.analyzer.top_processes"}, "Process details"),
            ("temp", {"target": "src.analyzer.get_temp_locations"}, "Temporary files"),
            ("uptime", {"fail": "boot_time"}, "System uptime"),
            ("battery", {"fail": "sensors_battery"}, "Battery status"),
            ("network", {"target": "src.analyzer.get_network"}, "Network information"),
            ("gpus", {"target": "src.win_registry.read_gpus"}, "Graphics adapters"),
            ("startup", {"target": "src.win_registry.read_startup_items"}, "Startup programs"),
            ("drive_health", {"target": "src.analyzer.get_drive_health"}, "Drive health"),
            ("folders", {"target": "src.analyzer.get_folder_usage"}, "Folder sizes"),
            ("security", {"target": "src.analyzer.get_security"}, "protection status"),
        )
        for name, setup, fragment in cases:
            with self.subTest(collector=name):
                failure = RuntimeError("collector exploded")
                fake = FakePsutil(fail=(setup["fail"],) if "fail" in setup else ())
                if "target" in setup:
                    with patch(str(setup["target"]), side_effect=failure):
                        result = self.analyze(fake)
                else:
                    result = self.analyze(fake)
                matching = [warning for warning in result.warnings if fragment in warning]
                self.assertEqual(len(matching), 1, result.warnings)
                self.assertIn("could not be", matching[0])
                self.assertGreater(len(matching[0]), len(fragment) + 10)

    def test_a_failed_collector_leaves_an_unknown_value_not_a_wrong_one(self) -> None:
        result = self.analyze(FakePsutil(disk_error=True))
        self.assertIsNone(result.disk.free_bytes)
        self.assertIsNone(result.disk.total_bytes)
        self.assertEqual(result.disk.drive, "C:\\")
        self.assertTrue(any("Disk information" in warning for warning in result.warnings))

    def test_analysis_survives_a_total_psutil_meltdown(self) -> None:
        fake = FakePsutil(
            fail=(
                "cpu_percent",
                "virtual_memory",
                "disk_usage",
                "disk_partitions",
                "pids",
                "boot_time",
                "sensors_battery",
                "net_io_counters",
                "net_if_stats",
                "process_iter",
            )
        )
        result = self.analyze(fake)
        self.assertIsNone(result.cpu.usage_percent)
        self.assertIsNone(result.ram.usage_percent)
        self.assertIsNone(result.process_count)
        self.assertIsNone(result.uptime_seconds)
        self.assertGreaterEqual(len(result.warnings), 6)
        self.assertTrue(all(isinstance(warning, str) and warning for warning in result.warnings))

    def test_optional_features_can_all_be_disabled(self) -> None:
        result = self.analyze(
            FakePsutil(),
            scan_temp=False,
            include_startup=False,
            include_gpu=False,
            include_security=False,
            include_drive_health=False,
            scan_folders=False,
            top_process_limit=0,
        )
        self.assertIsNone(result.temp_size_bytes)
        self.assertEqual(result.temp_locations, ())
        self.assertEqual(result.gpus, ())
        self.assertEqual(result.startup_items, ())
        self.assertEqual(result.top_processes, ())
        self.assertIsNone(result.security)
        self.assertEqual(result.drive_health, ())
        self.assertEqual(result.folder_usage, ())
        self.assertEqual(result.warnings, ())
        self.assertEqual(result.temp_path, self.folder.name)  # Still reported, just not measured.

    def test_a_disabled_step_does_no_work_at_all(self) -> None:
        # A flag that only hides the result would still cost the seconds it takes to read it.
        with patch("src.analyzer.read_security_state") as security:
            with patch("src.analyzer.read_drive_health") as drives:
                with patch("src.analyzer.read_folder_usage") as folders:
                    self.analyze(
                        FakePsutil(),
                        include_security=False,
                        include_drive_health=False,
                        scan_folders=False,
                    )
        security.assert_not_called()
        drives.assert_not_called()
        folders.assert_not_called()

    def test_the_snapshot_carries_the_protection_state(self) -> None:
        state = SecurityInfo(antivirus=STATE_GOOD, firewall=STATE_WEAK, reboot_pending=True)
        with patch("src.analyzer.read_security_state", return_value=state):
            result = self.analyze(FakePsutil())
        self.assertEqual(result.security, state)
        self.assertEqual(result.warnings, ())

    def test_the_snapshot_carries_the_wear_figures_of_the_drives_it_lists(self) -> None:
        entry = DriveHealth(drive="C:\\", model="Test NVMe", media_type="SSD", percentage_used=7)
        asked: list[object] = []

        def fake_health(drives: object = None) -> list[DriveHealth]:
            asked.append(drives)
            return [entry]

        with patch("src.analyzer.read_drive_health", side_effect=fake_health):
            result = self.analyze(FakePsutil())

        self.assertEqual(result.drive_health, (entry,))
        # Exactly the drives the partition table lists, so the two tables cannot disagree.
        self.assertEqual(asked, [[item.drive for item in result.partitions]])
        self.assertEqual(result.drive_health[0].life_left_percent, 93)

    def test_a_machine_with_no_listable_partitions_still_reports_its_drives(self) -> None:
        # An empty list would mean "ask about nothing"; None lets win_storage enumerate.
        asked: list[object] = []

        def fake_health(drives: object = None) -> list[DriveHealth]:
            asked.append(drives)
            return []

        fake = FakePsutil()
        fake.partitions = []
        with patch("src.analyzer.read_drive_health", side_effect=fake_health):
            self.analyze(fake)
        self.assertEqual(asked, [None])

    def test_the_snapshot_carries_the_folder_sizes(self) -> None:
        folders = [FolderUsage("downloads", "Downloads", r"C:\Users\Test\Downloads", 4 * GIB, 20)]
        with patch("src.analyzer.read_folder_usage", return_value=folders) as reader:
            result = self.analyze(FakePsutil())
        self.assertEqual(result.folder_usage, tuple(folders))
        self.assertEqual(reader.call_args.kwargs["limit"], 8)

    def test_the_media_type_never_disagrees_with_itself_inside_one_snapshot(self) -> None:
        # Until v2.1 the seek-penalty IOCTL was implemented twice, so one drive could read
        # "SSD" beside its free space and "HDD" beside its wear figures - in the same report.
        # Both now come from win_storage, and this asserts they still do end to end.
        entry = DriveHealth(drive="C:\\", model="Test HDD", media_type="HDD")
        _MEDIA_TYPE_CACHE.clear()
        self.addCleanup(_MEDIA_TYPE_CACHE.clear)
        with patch("src.analyzer.detect_media_type", return_value="HDD"):
            with patch("src.analyzer.read_drive_health", return_value=[entry]):
                result = self.analyze(FakePsutil())

        self.assertEqual(result.disk.media_type, "HDD")
        health = {item.drive: item.media_type for item in result.drive_health}
        self.assertEqual(health, {"C:\\": "HDD"})
        for partition in result.partitions:
            with self.subTest(drive=partition.drive):
                reported = health.get(partition.drive)
                if reported is not None:
                    self.assertEqual(partition.media_type, reported)

    @unittest.skipUnless(IS_WINDOWS, "the media type is a Windows query")
    def test_both_media_type_readings_come_from_the_one_collector(self) -> None:
        # The real detect_media_type runs here - only win_storage is replaced - so a second
        # implementation of the seek-penalty query anywhere would produce a media type this
        # fake never supplied, and the two columns would disagree again.
        _MEDIA_TYPE_CACHE.clear()
        self.addCleanup(_MEDIA_TYPE_CACHE.clear)
        asked: list[object] = []

        def one_source(drives: object = None) -> list[DriveHealth]:
            asked.append(drives)
            return [DriveHealth(drive="C:\\", model="Test HDD", media_type="HDD")]

        with patch("src.analyzer.detect_media_type", detect_media_type):
            with patch("src.analyzer.read_drive_health", side_effect=one_source):
                result = self.analyze(FakePsutil())

        self.assertEqual(result.disk.media_type, "HDD")
        self.assertEqual(result.drive_health[0].media_type, "HDD")
        self.assertEqual([item.media_type for item in result.partitions], ["HDD"])
        # Asked once per drive letter for the media type, and once for the health table.
        self.assertIn(["C:\\"], asked)
        self.assertGreaterEqual(len(asked), 2)

    def test_the_two_folder_scans_share_one_budget(self) -> None:
        # TEMP is measured first with its share; the folder scan gets what TEMP left behind,
        # which is what keeps a run with both scans from taking twice as long as one.
        budgets: dict[str, float | None] = {}

        def fake_scan(path: object, *, max_seconds: float | None = None) -> tuple[int, int, bool]:
            budgets["temp"] = max_seconds
            return 5, 1, False

        def fake_folders(*, max_seconds: float | None = None, limit: int = 8) -> list[FolderUsage]:
            budgets["folders"] = max_seconds
            return []

        with patch("src.analyzer.scan_folder", side_effect=fake_scan):
            with patch("src.analyzer.read_folder_usage", side_effect=fake_folders):
                self.analyze(FakePsutil())

        self.assertEqual(budgets["temp"], TOTAL_SCAN_SECONDS * 0.5)
        self.assertGreater(budgets["folders"], 0.0)
        # The folder scan may use the rest of the shared budget, never more than all of it.
        self.assertLessEqual(budgets["folders"], TOTAL_SCAN_SECONDS)

    def test_an_explicit_folder_budget_is_forwarded_unchanged(self) -> None:
        with patch("src.analyzer.read_folder_usage", return_value=[]) as reader:
            self.analyze(FakePsutil(), folder_scan_seconds=2.5)
        self.assertEqual(reader.call_args.kwargs["max_seconds"], 2.5)

    def test_temp_scan_budget_is_forwarded(self) -> None:
        recorded: list[float | None] = []

        def fake_scan(path: object, *, max_seconds: float | None = None) -> tuple[int, int, bool]:
            recorded.append(max_seconds)
            return 5, 1, True

        with patch("src.analyzer.scan_folder", side_effect=fake_scan):
            result = self.analyze(FakePsutil(), temp_scan_seconds=3.0)
        self.assertEqual(recorded, [3.0])
        self.assertTrue(result.temp_locations[0].truncated)

    def test_a_truncated_user_temp_scan_is_flagged_on_the_snapshot(self) -> None:
        # The size is a floor once the scan ran out of time, and every consumer - the score,
        # the advice, all four exporters - reads that fact from this one flag.
        def fake_scan(path: object, *, max_seconds: float | None = None) -> tuple[int, int, bool]:
            return 5 * GIB, 400, True

        with patch("src.analyzer.scan_folder", side_effect=fake_scan):
            result = self.analyze(FakePsutil())
        self.assertTrue(result.temp_truncated)
        self.assertEqual(result.temp_size_bytes, 5 * GIB)

    def test_a_completed_scan_is_not_flagged(self) -> None:
        result = self.analyze(FakePsutil())
        self.assertFalse(result.temp_truncated)
        self.assertEqual(result.temp_size_bytes, 23)

    def test_a_skipped_scan_is_not_flagged_either(self) -> None:
        # No measurement at all is "unknown", never "a lower bound of nothing".
        result = self.analyze(FakePsutil(), scan_temp=False)
        self.assertFalse(result.temp_truncated)
        self.assertIsNone(result.temp_size_bytes)

    def test_a_temp_folder_that_is_not_there_is_unknown_and_costs_no_points(self) -> None:
        # End to end for the one place the app used to invent a measurement: a TMP that does
        # not exist was scanned as 0 bytes and scored as a spotlessly clean TEMP folder.
        missing = os.path.join("Z:" + os.sep, "nonexistent", "apoliak-temp-probe")
        result = self.analyze(FakePsutil(), temp_path=missing)

        self.assertIsNone(result.temp_size_bytes)
        self.assertFalse(result.temp_truncated)
        self.assertEqual([item.size_bytes for item in result.temp_locations], [None])
        naming_it = [warning for warning in result.warnings if missing in warning]
        self.assertEqual(len(naming_it), 1, result.warnings)
        self.assertIn("could not be measured", naming_it[0])

        assessment = calculate_health_details(result)
        self.assertNotIn("large_temp", [item.key for item in assessment.deductions])
        self.assertFalse(assessment.data_complete)

    def test_a_measured_temp_folder_leaves_no_warning_behind(self) -> None:
        result = self.analyze(FakePsutil())
        self.assertEqual(result.warnings, ())
        self.assertEqual(result.temp_size_bytes, 23)

    def test_a_missing_temp_folder_is_never_rendered_as_zero_bytes(self) -> None:
        # The last mile of the same defect: an unknown size that prints as "0 B" tells the
        # reader the folder is clean. It has to read as "not measured" in every format, and
        # the warning naming the folder has to travel with it.
        missing = os.path.join("Z:" + os.sep, "nonexistent", "apoliak-temp-probe")
        result = self.analyze(FakePsutil(), temp_path=missing)
        assessment = calculate_health_details(result)
        advice = generate_recommendations(result)

        payload = json.loads(exporters.render("json", result, advice, assessment))
        self.assertIsNone(payload["temp"]["size_bytes"])
        self.assertIsNone(payload["temp"]["locations"][0]["size_bytes"])
        self.assertFalse(payload["temp"]["truncated"])
        self.assertFalse(payload["health"]["data_complete"])
        self.assertTrue(payload["warnings"])

        for fmt in ("text", "markdown", "html"):
            with self.subTest(fmt=fmt):
                content = exporters.render(fmt, result, advice, assessment)
                self.assertIn("N/A", content)
                # No line about the temp folder may quote a size at all, least of all zero.
                for line in content.splitlines():
                    if "apoliak-temp-probe" in line or "TEMP Folder Size" in line:
                        self.assertNotIn("0 B", line)
                self.assertNotIn("large_temp", content)

    # -- top processes: the CPU column has to hold real numbers ---------------------------

    def busy_machine(self) -> FakePsutil:
        """Four logical cores and three processes whose second CPU sample is known."""
        fake = FakePsutil()
        fake.logical = 4
        fake.processes = [
            FakeProcess(200, "big.exe", rss=4 * GIB, cpu_samples=[0.0, 200.0]),
            FakeProcess(201, "runaway.exe", rss=2 * GIB, cpu_samples=[0.0, 800.0]),
            FakeProcess(202, "small.exe", rss=GIB, cpu_samples=[0.0, 10.0]),
        ]
        return fake

    def test_top_processes_carry_a_measured_cpu_share(self) -> None:
        # Until v2.0 the analysis collected the list without sampling, so the CPU column of
        # every real report read "N/A" and the busiest-process advice could never fire.
        with patch("src.processes.time.sleep") as sleep:
            result = self.analyze(self.busy_machine(), top_process_limit=3)

        measured = {item.name: item.cpu_percent for item in result.top_processes}
        self.assertEqual(measured, {"big.exe": 50.0, "runaway.exe": 100.0, "small.exe": 2.5})
        for item in result.top_processes:
            with self.subTest(process=item.name):
                self.assertIsNotNone(item.cpu_percent)
                self.assertGreaterEqual(item.cpu_percent, 0.0)
                self.assertLessEqual(item.cpu_percent, 100.0)  # 800% of one core is not 800%.
        # One shared pause for the whole list, not one per process.
        self.assertEqual(sleep.call_count, 1)
        self.assertLessEqual(float(sleep.call_args[0][0]), 0.3)

    def test_the_whole_cpu_sample_costs_a_fraction_of_a_second(self) -> None:
        self.assertLessEqual(CPU_SAMPLE_SECONDS, 0.3)

    def test_a_disabled_list_costs_no_sampling_pause_at_all(self) -> None:
        with patch("src.processes.time.sleep") as sleep:
            result = self.analyze(self.busy_machine(), top_process_limit=0)
        self.assertEqual(result.top_processes, ())
        sleep.assert_not_called()

    def test_the_busiest_process_advice_can_actually_fire_now(self) -> None:
        with patch("src.processes.time.sleep"):
            result = self.analyze(self.busy_machine(), top_process_limit=3)
        advice = {item.key: item for item in generate_recommendations(result)}
        self.assertIn("top_cpu_process", advice)
        self.assertEqual(advice["top_cpu_process"].values["name"], "runaway.exe")
        leader = max(item.cpu_percent or 0.0 for item in result.top_processes)
        self.assertGreater(leader, TOP_CPU_PERCENT)

    def test_the_ranking_stays_memory_based_even_though_the_cpu_is_sampled(self) -> None:
        with patch("src.processes.time.sleep"):
            result = self.analyze(self.busy_machine(), top_process_limit=3)
        self.assertEqual(
            [item.name for item in result.top_processes],
            ["big.exe", "runaway.exe", "small.exe"],
        )

    def steps_of_one_run(self) -> list[tuple[str, float]]:
        steps: list[tuple[str, float]] = []
        self.analyze(FakePsutil(), progress=lambda key, fraction: steps.append((key, fraction)))
        return steps

    def test_the_callback_receives_step_keys_the_caller_can_translate(self) -> None:
        # Until v2.0 the callback was handed English prose, so a Slovak run printed English
        # steps in both the console and the GUI. The key is the contract now; the English
        # label lives in PROGRESS_LABELS for consumers whose catalogue lacks the step.
        keys = [key for key, _ in self.steps_of_one_run()]
        self.assertTrue(keys)
        for key in keys:
            with self.subTest(step=key):
                self.assertIn(key, PROGRESS_LABELS)
        self.assertEqual(keys[-1], "done")

    def test_every_documented_step_is_actually_reported(self) -> None:
        # A label nobody emits is as much dead weight as a translation nobody asks for.
        keys = {key for key, _ in self.steps_of_one_run()}
        self.assertEqual(keys, set(PROGRESS_LABELS))

    def test_progress_callback_reports_ordered_steps(self) -> None:
        steps: list[tuple[str, float]] = []

        def record(message: str, fraction: float) -> None:
            steps.append((message, fraction))

        self.analyze(FakePsutil(), progress=record)

        self.assertGreaterEqual(len(steps), 5)
        self.assertTrue(all(message.strip() for message, _ in steps))
        fractions = [fraction for _, fraction in steps]
        self.assertTrue(all(0.0 <= fraction <= 1.0 for fraction in fractions))
        self.assertEqual(fractions, sorted(fractions))
        self.assertEqual(fractions[-1], 1.0)

    def test_a_failing_progress_callback_never_breaks_the_analysis(self) -> None:
        calls = {"count": 0}

        def hostile(message: str, fraction: float) -> None:
            calls["count"] += 1
            raise RuntimeError("the GUI went away")

        result = self.analyze(FakePsutil(), progress=hostile)
        self.assertGreater(calls["count"], 1)  # Every step was still attempted.
        self.assertEqual(result.warnings, ())
        self.assertEqual(result.process_count, 164)

    def test_missing_psutil_is_reported_clearly(self) -> None:
        with patch("src.analyzer._psutil", None):
            with self.assertRaises(MissingDependencyError) as caught:
                analyze_pc()
            self.assertIn("psutil", str(caught.exception))
            with self.assertRaises(MissingDependencyError):
                get_cpu_info()
            with self.assertRaises(MissingDependencyError):
                get_ram_info()


if __name__ == "__main__":
    unittest.main()
