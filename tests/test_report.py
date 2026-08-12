"""Tests for the plain-text renderer and its file export.

The renderer is the one module every interface shares, so the rules it must obey are checked
here directly: no section is printed empty, no unknown value is invented, no escape sequence
reaches a file, and the v1.0 call signature still works.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from src.health_score import calculate_health_details
from src.i18n import get_translator
from src.models import (
    STATE_BAD,
    STATE_GOOD,
    STATE_UNKNOWN,
    STATE_WEAK,
    AnalysisData,
    BatteryInfo,
    CPUInfo,
    DiskInfo,
    DriveHealth,
    FolderUsage,
    GPUInfo,
    NetworkInfo,
    NetworkInterface,
    ProcessInfo,
    RAMInfo,
    SecurityInfo,
    StartupItem,
    SystemInfo,
    TempLocation,
)
from src.recommendations import generate_recommendations
from src.report import build_report, export_report
from src.utils import GIB, Ansi
from tests.helpers import make_analysis

#: Injected on purpose so the redaction test cannot accidentally pass on this machine.
ACCOUNT = "testaccount"
TEMP_PATH = rf"C:\Users\{ACCOUNT}\AppData\Local\Temp"

#: Every optional section of the report, with the heading that must appear for it.
OPTIONAL_SECTIONS = (
    "--- PARTITIONS ---",
    "--- TOP PROCESSES ---",
    "--- BATTERY ---",
    "--- NETWORK ---",
    "--- GRAPHICS ---",
    "--- STARTUP ITEMS ---",
    "--- ANALYSIS WARNINGS ---",
)

#: The v2.1 sections. They report durable state rather than momentary load, so they are held
#: to the same rule as the list above: present with data, absent without it.
STATE_SECTIONS = (
    "--- SECURITY ---",
    "--- DRIVE HEALTH ---",
    "--- BIGGEST FOLDERS ---",
)


def bare() -> AnalysisData:
    """A v1.0-shaped snapshot: every optional v2.0 field explicitly empty."""
    return replace(
        make_analysis(),
        temp_path=TEMP_PATH,
        partitions=(),
        top_processes=(),
        battery=None,
        network=None,
        gpus=(),
        startup_items=(),
        temp_locations=(),
        duration_seconds=None,
        warnings=(),
    )


def rich() -> AnalysisData:
    """A snapshot in which every optional section carries data."""
    return replace(
        bare(),
        cpu=CPUInfo(6, 12, 42.0, (10.0, 20.0, 30.0, 40.0), 2400.0, 4200.0),
        ram=RAMInfo(16 * GIB, 6 * GIB, 10 * GIB, 62.5, 8 * GIB, 2 * GIB, 25.0),
        system=SystemInfo(
            "Windows 11",
            "11",
            "10.0.26100",
            "AMD64",
            "Test CPU",
            edition="Pro",
            display_version="24H2",
            build="26100.4652",
            install_date=datetime(2025, 3, 1, 9, 0, tzinfo=timezone.utc),
            boot_time=datetime(2026, 7, 15, 8, 0, tzinfo=timezone.utc),
            manufacturer="Test Manufacturer",
            model="Test Model",
            bios_version="F.42",
        ),
        disk=DiskInfo("C:\\", 512 * GIB, 412 * GIB, 100 * GIB, 80.0, "NTFS", "SSD", True),
        partitions=(
            DiskInfo("C:\\", 512 * GIB, 412 * GIB, 100 * GIB, 80.0, "NTFS", "SSD", True),
            DiskInfo("D:\\", 1024 * GIB, 100 * GIB, 924 * GIB, 9.8, "NTFS", "HDD", False),
        ),
        top_processes=(
            ProcessInfo(1000, "browser.exe", 12.5, 2 * GIB, 12.5),
            ProcessInfo(1001, "editor.exe", 1.5, GIB // 2, 3.1),
        ),
        battery=BatteryInfo(64.0, False, 5400),
        network=NetworkInfo(
            5 * GIB,
            9 * GIB,
            (NetworkInterface("Ethernet", True, 1000), NetworkInterface("Wi-Fi", False)),
        ),
        gpus=(GPUInfo("Test Graphics 4000", "32.0.101", "2026-01-05", 8 * GIB),),
        startup_items=(
            StartupItem("Updater", "HKCU Run", r"C:\Program Files\Updater\updater.exe"),
            StartupItem("Sync", "Startup folder"),
        ),
        temp_locations=(
            TempLocation("User TEMP", TEMP_PATH, 512 * GIB // 1024, 1200, False),
            TempLocation("Windows TEMP", r"C:\Windows\Temp", 64 * GIB // 1024, 90, True),
        ),
        duration_seconds=3.5,
        warnings=(f"Could not read {TEMP_PATH} completely.",),
    )


def stateful() -> AnalysisData:
    """A snapshot carrying every v2.1 measurement the three new sections can print."""
    return replace(
        bare(),
        battery=BatteryInfo(
            percent=64.0,
            plugged_in=True,
            design_capacity_mwh=80_000,
            full_charge_capacity_mwh=36_000,  # 45% of the pack's original capacity.
            cycle_count=642,
            chemistry="LION",
        ),
        security=SecurityInfo(
            antivirus=STATE_GOOD,
            antivirus_name="Windows Defender",
            firewall=STATE_BAD,
            secure_boot=STATE_WEAK,
            reboot_pending=True,
            defender_last_scan=datetime(2026, 6, 1, 8, 15, tzinfo=timezone.utc),
            signature_age_days=1,  # Singular on purpose: "1 day", never "1 days".
        ),
        drive_health=(
            DriveHealth(
                drive="C:\\",
                model="Test NVMe 2TB",
                bus_type="NVMe",
                media_type="SSD",
                percentage_used=5,
                temperature_celsius=42,
                power_on_hours=1,
                data_written_bytes=180 * GIB,
                critical_warning=False,
                source="nvme",
            ),
            # Only a letter: nothing was readable, so this drive is not worth a paragraph.
            DriveHealth(drive="E:\\"),
        ),
        folder_usage=(
            # Deliberately not in size order: the table, not the collector, sorts them.
            FolderUsage("documents", "Documents", rf"C:\Users\{ACCOUNT}\Documents", 3 * GIB, 812),
            FolderUsage("onedrive", "OneDrive", rf"C:\Users\{ACCOUNT}\OneDrive"),
            FolderUsage(
                "downloads", "Downloads", rf"C:\Users\{ACCOUNT}\Downloads", 62 * GIB, 12_004, True
            ),
        ),
    )


def empty() -> AnalysisData:
    """A snapshot in which nothing at all could be measured."""
    return AnalysisData(
        analyzed_at=None,
        system=SystemInfo(None, None, None, None, None),
        cpu=CPUInfo(None, None, None),
        ram=RAMInfo(None, None, None, None),
        disk=DiskInfo(None, None, None, None, None),
        process_count=None,
        temp_path=None,
        temp_size_bytes=None,
        uptime_seconds=None,
    )


def render(data: AnalysisData, **kwargs: object) -> str:
    """Render one snapshot together with its own score and advice."""
    return build_report(
        data,
        generate_recommendations(data),
        calculate_health_details(data),
        **kwargs,  # type: ignore[arg-type]
    )


class ReportCompatibilityTests(unittest.TestCase):
    """The v1.0 signature and the v1.0 output are still part of the contract."""

    def setUp(self) -> None:
        self.data = make_analysis()
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)

    def test_three_positional_arguments_still_work(self) -> None:
        report = build_report(self.data, self.recommendations, self.assessment)
        self.assertIsInstance(report, str)
        self.assertIn("Apoliak Vitals", report)

    def test_report_contains_required_sections(self) -> None:
        report = build_report(self.data, self.recommendations, self.assessment)
        for expected in (
            "--- SYSTEM ---",
            "--- CPU ---",
            "--- RAM ---",
            "--- DISK (C:\\) ---",
            "Running Processes: 100",
            "TEMP Folder Size",
            "System Uptime",
            "Score: 100/100",
            "Status: Excellent",
            "--- RECOMMENDATIONS ---",
            "did not modify your PC",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)

    def test_report_ends_with_a_single_newline(self) -> None:
        report = build_report(self.data, self.recommendations, self.assessment)
        self.assertTrue(report.endswith("\n"))
        self.assertFalse(report.endswith("\n\n"))

    def test_plain_string_advice_is_accepted(self) -> None:
        # v1.0 handed the renderer plain strings instead of Recommendation objects.
        report = build_report(self.data, ["Restart the PC."], self.assessment)
        self.assertIn("- Restart the PC.", report)

    def test_no_section_reports_a_rendering_failure(self) -> None:
        self.assertNotIn("could not be rendered", render(rich()))


class ReportSectionTests(unittest.TestCase):
    """Every v2.0 section appears with data and disappears without it."""

    def test_optional_sections_appear_when_data_is_present(self) -> None:
        report = render(rich())
        for heading in OPTIONAL_SECTIONS:
            with self.subTest(heading=heading):
                self.assertIn(heading, report)

    def test_optional_sections_are_omitted_when_data_is_absent(self) -> None:
        report = render(bare())
        for heading in OPTIONAL_SECTIONS:
            with self.subTest(heading=heading):
                self.assertNotIn(heading, report)

    def test_new_fields_are_rendered(self) -> None:
        report = render(rich())
        for expected in (
            "Edition: Pro",
            "Windows Version: 24H2",
            "Build: 26100.4652",
            "Manufacturer: Test Manufacturer",
            "Model: Test Model",
            "BIOS Version: F.42",
            "Windows Installed: 2025-03-01",
            "Last Boot: 2026-07-15 08:00",
            "CPU Frequency: 2.40 GHz (max. 4.20 GHz)",
            "Per-core Usage: min 10% / avg 25% / max 40%",
            "Page File: 2.0 GB of 8.0 GB (25%)",
            "File System: NTFS",
            "Media Type: SSD",
            "Analysis Duration: 3.5 s",
            "browser.exe",
            "Battery: 64%",
            "Plugged In: No",
            "Test Graphics 4000",
            "Driver: 32.0.101 (2026-01-05)",
            "Updater (HKCU Run)",
            "partial scan",
            "Ethernet: up",
            "Wi-Fi: down",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)

    def test_empty_network_object_is_omitted(self) -> None:
        data = replace(bare(), network=NetworkInfo())
        self.assertNotIn("--- NETWORK ---", render(data))

    def test_duration_line_is_omitted_when_unknown(self) -> None:
        self.assertNotIn("Analysis Duration", render(bare()))

    def test_temp_locations_table_is_omitted_when_empty(self) -> None:
        self.assertNotIn("Windows TEMP", render(bare()))


class ReportStateSectionTests(unittest.TestCase):
    """The v2.1 sections: protection, drive wear, battery wear and folder sizes."""

    def test_state_sections_appear_when_data_is_present(self) -> None:
        report = render(stateful())
        for heading in STATE_SECTIONS:
            with self.subTest(heading=heading):
                self.assertIn(heading, report)

    def test_state_sections_are_omitted_when_data_is_absent(self) -> None:
        report = render(bare())
        for heading in STATE_SECTIONS:
            with self.subTest(heading=heading):
                self.assertNotIn(heading, report)

    def test_security_reports_each_setting_it_could_read(self) -> None:
        report = render(stateful())
        for expected in (
            "Antivirus: On (Windows Defender)",
            "Firewall: Off",
            "Secure Boot: Needs attention",
            "Restart Pending: Yes",
            "Definitions Age: 1 day",
            "Last Scan: 2026-06-01 08:15",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)

    def test_an_unreadable_setting_is_unknown_and_never_off(self) -> None:
        # The whole point of the state labels: a query that failed must not be reported as a
        # switch the user turned off, because the analyser never made that measurement.
        data = replace(
            bare(),
            security=SecurityInfo(
                antivirus=STATE_UNKNOWN, firewall=STATE_UNKNOWN, reboot_pending=False
            ),
        )
        report = render(data)
        self.assertIn("Antivirus: Unknown", report)
        self.assertIn("Firewall: Unknown", report)
        self.assertNotIn(": Off", report)

    def test_a_verdict_outside_the_known_set_falls_back_to_unknown(self) -> None:
        data = replace(bare(), security=SecurityInfo(antivirus="banana", reboot_pending=False))
        self.assertIn("Antivirus: Unknown", render(data))

    def test_three_unknown_verdicts_alone_do_not_earn_a_section(self) -> None:
        # Printing "Unknown / Unknown / Unknown" would suggest the analyser looked and found
        # trouble. It looked and found nothing readable, which is not the same news.
        self.assertNotIn("--- SECURITY ---", render(replace(bare(), security=SecurityInfo())))

    def test_a_silent_security_center_explains_itself(self) -> None:
        data = replace(
            bare(),
            security=SecurityInfo(details=(("security_center", "no answer"),)),
        )
        report = render(data)
        self.assertIn("--- SECURITY ---", report)
        self.assertIn("unknown rather than off", report)

    def test_drive_health_prints_only_the_fields_the_drive_reported(self) -> None:
        report = render(stateful())
        for expected in (
            "Model: Test NVMe 2TB",
            "Bus: NVMe",
            "Life Left: 95%",
            "Temperature: 42 °C",
            "Power-on Hours: 1 hour",
            "Data Written: 180.0 GB",
            "Critical Warning: No",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)

    def test_a_drive_that_answered_nothing_is_left_out(self) -> None:
        self.assertNotIn("E:\\", render(stateful()))

    def test_a_drive_list_of_empty_entries_drops_the_section(self) -> None:
        data = replace(bare(), drive_health=(DriveHealth(drive="C:\\"),))
        self.assertNotIn("--- DRIVE HEALTH ---", render(data))

    def test_folders_are_listed_biggest_first_with_unknown_sizes_last(self) -> None:
        report = render(stateful())
        order = [
            report.index(name) for name in ("Downloads", "Documents", "OneDrive")
        ]
        self.assertEqual(order, sorted(order))

    def test_a_folder_cut_short_carries_the_partial_scan_qualifier(self) -> None:
        report = render(stateful())
        self.assertIn("62.0 GB (partial scan)", report)
        self.assertIn("3.0 GB", report)

    def test_an_unmeasured_folder_is_listed_as_na_rather_than_zero(self) -> None:
        report = render(stateful())
        row = next(line for line in report.splitlines() if line.startswith("OneDrive"))
        self.assertIn("N/A", row)
        self.assertNotIn("0 B", row)

    def test_battery_wear_lines_appear_next_to_the_charge(self) -> None:
        report = render(stateful())
        for expected in (
            "Battery: 64%",
            "Battery Health: 45%",
            "Design Capacity: 80 000 mWh",
            "Full Charge Capacity: 36 000 mWh",
            "Charge Cycles: 642",
            "Cell Chemistry: LION",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)

    def test_a_battery_that_hides_its_capacity_gets_no_invented_health(self) -> None:
        data = replace(bare(), battery=BatteryInfo(64.0, True))
        report = render(data)
        self.assertIn("--- BATTERY ---", report)
        for absent in ("Battery Health", "Design Capacity", "Charge Cycles"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, report)

    def test_folder_paths_honour_redaction(self) -> None:
        report = render(stateful(), redact=True)
        self.assertNotIn(ACCOUNT, report)
        self.assertIn(r"C:\Users\<user>\Downloads", report)

    def test_the_new_sections_render_in_slovak_without_english(self) -> None:
        report = render(stateful(), translator=get_translator("sk"))
        for expected in (
            "--- ZABEZPEČENIE ---",
            "--- STAV DISKOV ---",
            "--- NAJVÄČŠIE PRIEČINKY ---",
            "Antivírus: Zapnuté (Windows Defender)",
            "Brána firewall: Vypnuté",
            "Secure Boot: Vyžaduje pozornosť",
            "Vek definícií: 1 deň",  # 1 declines differently from 2-4 and 5+.
            "Hodiny v prevádzke: 1 hodina",
            "Kondícia batérie: 45%",
            "62.0 GB (čiastočný sken)",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)
        # The qualifiers and labels must come from the catalogue, not from an English default.
        for absent in ("partial scan", "Life Left", "Restart Pending", "Battery Health"):
            with self.subTest(absent=absent):
                self.assertNotIn(absent, report)

    def test_no_placeholder_survives_in_either_language(self) -> None:
        for language in ("en", "sk"):
            report = render(stateful(), translator=get_translator(language))
            with self.subTest(language=language):
                self.assertNotIn("{", report)
                self.assertNotIn("}", report)
                self.assertNotIn("could not be rendered", report)


class ReportUnknownValueTests(unittest.TestCase):
    """An unmeasured value is written as N/A and never guessed."""

    def test_all_none_snapshot_renders_without_raising(self) -> None:
        report = render(empty())
        self.assertIn("N/A", report)
        self.assertNotIn("could not be rendered", report)
        self.assertNotIn("None", report)

    def test_all_none_snapshot_keeps_the_mandatory_sections(self) -> None:
        report = render(empty())
        for expected in (
            "--- SYSTEM ---",
            "System: N/A",
            "CPU Usage: N/A",
            "Total RAM: N/A",
            "Running Processes: N/A",
            "TEMP Folder: N/A",
            "System Uptime: N/A",
            "Data Complete: No",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, report)

    def test_unknown_values_are_not_penalised(self) -> None:
        # The documented principle: missing data lowers coverage, never the score.
        self.assertEqual(calculate_health_details(empty()).score, 100)


class ReportPresentationTests(unittest.TestCase):
    """Redaction, colour, translation, and width behave as documented."""

    def test_redact_masks_the_profile_segment_of_a_path(self) -> None:
        data = rich()
        self.assertIn(TEMP_PATH, render(data))

        masked = render(data, redact=True)
        self.assertIn(r"C:\Users\<user>\AppData\Local\Temp", masked)

    def test_redact_removes_the_account_name(self) -> None:
        data = rich()
        # redact_text() masks the live Windows account name wherever it appears, so the
        # test account has to be the live one for the check to mean anything.
        with patch.dict(os.environ, {"USERNAME": ACCOUNT}):
            masked = render(data, redact=True)
        self.assertNotIn(ACCOUNT, masked)
        self.assertIn("<user>", masked)

    def test_disabled_colors_emit_no_escape_sequences(self) -> None:
        self.assertNotIn("\x1b", render(rich(), colors=Ansi(False)))

    def test_default_colors_emit_no_escape_sequences(self) -> None:
        self.assertNotIn("\x1b", render(rich()))

    def test_enabled_colors_emit_escape_sequences(self) -> None:
        self.assertIn("\x1b", render(rich(), colors=Ansi(True)))

    def test_translator_switches_the_language(self) -> None:
        report = render(rich(), translator=get_translator("sk"))
        self.assertIn("--- SYSTÉM ---", report)
        self.assertNotIn("--- SYSTEM ---", report)

    def test_width_controls_the_header_rule(self) -> None:
        report = render(bare(), width=40)
        self.assertIn("=" * 40, report)
        self.assertNotIn("=" * 41, report)

    def test_broken_translator_falls_back_to_english(self) -> None:
        class Exploding:
            def t(self, *args: object, **kwargs: object) -> str:
                raise RuntimeError("translation backend is down")

        report = render(bare(), translator=Exploding())
        self.assertIn("--- SYSTEM ---", report)


class ExportReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.data = rich()
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)

    def export(self, destination: Path, **kwargs: object) -> Path:
        return export_report(
            self.data,
            self.recommendations,
            self.assessment,
            destination,
            **kwargs,  # type: ignore[arg-type]
        )

    def test_export_writes_utf8_text_file(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            saved = self.export(Path(folder) / "pc_report.txt")
            self.assertTrue(saved.exists())
            self.assertEqual(
                saved.read_text(encoding="utf-8"),
                build_report(self.data, self.recommendations, self.assessment),
            )

    def test_export_writes_real_utf8_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            saved = self.export(Path(folder) / "sk.txt", translator=get_translator("sk"))
            self.assertIn("SYSTÉM".encode("utf-8"), saved.read_bytes())

    def test_export_creates_missing_parent_folders(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            saved = self.export(Path(folder) / "deep" / "nested" / "report.txt")
            self.assertTrue(saved.exists())
            self.assertEqual(saved.name, "report.txt")

    def test_export_to_a_directory_appends_the_default_name(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            saved = self.export(Path(folder))
            self.assertEqual(saved.name, "pc_report.txt")
            self.assertEqual(saved.parent, Path(folder).resolve())

    def test_exported_file_never_contains_escape_sequences(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            saved = self.export(Path(folder) / "report.txt")
            self.assertNotIn("\x1b", saved.read_text(encoding="utf-8"))

    def test_export_honours_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"USERNAME": ACCOUNT}):
                saved = self.export(Path(folder) / "report.txt", redact=True)
            self.assertNotIn(ACCOUNT, saved.read_text(encoding="utf-8"))

    def test_export_returns_a_resolved_absolute_path(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            saved = self.export(Path(folder) / "report.txt")
            self.assertTrue(saved.is_absolute())
            self.assertEqual(saved, saved.resolve())


if __name__ == "__main__":
    unittest.main()
