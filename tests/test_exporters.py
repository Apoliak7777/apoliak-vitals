"""Tests for the four shipped export formats.

The exports are what leaves the machine, so the guarantees checked here are the ones a user
relies on when e-mailing a report: the JSON layout is stable and machine-readable, the HTML
document is self-contained and cannot execute injected markup, and redaction is honoured by
every format rather than only by the one that happened to be tested.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from unittest.mock import patch

from src import exporters
from src.health_score import calculate_health_details
from src.i18n import get_translator
from src.models import (
    SCHEMA_VERSION,
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
    Recommendation,
    SecurityInfo,
    StartupItem,
    SystemInfo,
    TempLocation,
)
from src.recommendations import generate_recommendations
from src.report import _text as render_label
from src.report import build_report
from src.utils import GIB
from tests.helpers import make_analysis

ACCOUNT = "testaccount"
TEMP_PATH = rf"C:\Users\{ACCOUNT}\AppData\Local\Temp"

#: Documented top-level keys of the JSON snapshot. Stored exports depend on them.
JSON_KEYS = (
    "schema_version",
    "generated_by",
    "analyzed_at",
    "system",
    "cpu",
    "ram",
    "disk",
    "partitions",
    # v2.1: wear of the physical drives behind the partitions.
    "drive_health",
    "processes",
    "temp",
    # v2.1: the well-known folders that actually take up the space.
    "folder_usage",
    "uptime_seconds",
    "battery",
    "network",
    "gpus",
    "startup_items",
    # v2.1: null when protection was never inspected, which is not the same as inspected
    # and unknown.
    "security",
    "health",
    "recommendations",
    "warnings",
    # v2.0: empty on a healthy export, one entry per section that could not be written.
    "export_errors",
)

_HTTP_REFERENCE = re.compile(r"https?://", re.IGNORECASE)


def rich() -> AnalysisData:
    """A snapshot that reaches every branch of every renderer."""
    return replace(
        make_analysis(),
        analyzed_at=datetime(2026, 7, 16, 12, 30, tzinfo=timezone.utc),
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
        cpu=CPUInfo(6, 12, 42.0, (10.0, 40.0), 2400.0, 4200.0),
        ram=RAMInfo(16 * GIB, 6 * GIB, 10 * GIB, 62.5, 8 * GIB, 2 * GIB, 25.0),
        disk=DiskInfo("C:\\", 512 * GIB, 412 * GIB, 100 * GIB, 80.0, "NTFS", "SSD", True),
        partitions=(
            DiskInfo("C:\\", 512 * GIB, 412 * GIB, 100 * GIB, 80.0, "NTFS", "SSD", True),
            DiskInfo("D:\\", 1024 * GIB, 100 * GIB, 924 * GIB, 9.8, "NTFS", "HDD", False),
        ),
        top_processes=(
            ProcessInfo(1000, "browser.exe", 12.5, 2 * GIB, 12.5),
            ProcessInfo(1001, "editor.exe", 1.5, GIB // 2, 3.1),
        ),
        battery=BatteryInfo(
            64.0,
            False,
            5400,
            design_capacity_mwh=80_000,
            full_charge_capacity_mwh=68_000,
            cycle_count=214,
            chemistry="LION",
        ),
        security=SecurityInfo(
            antivirus=STATE_GOOD,
            firewall=STATE_WEAK,
            secure_boot=STATE_UNKNOWN,
            reboot_pending=True,
            defender_last_scan=datetime(2026, 7, 15, 3, 0, tzinfo=timezone.utc),
            signature_age_days=1,
            details=(("firewall_profiles_off", "Public"), ("security_center", "unavailable")),
        ),
        drive_health=(
            DriveHealth(
                "C:\\",
                model="Test NVMe 1TB",
                bus_type="NVMe",
                media_type="SSD",
                percentage_used=6,
                temperature_celsius=41,
                power_on_hours=4210,
                data_written_bytes=42 * GIB,
                critical_warning=False,
                source="NVMe SMART log",
            ),
            # A drive that answered nothing but its name: every figure has to read N/A.
            DriveHealth("D:\\", model="Test HDD", bus_type="SATA"),
        ),
        folder_usage=(
            FolderUsage("downloads", "Downloads", rf"C:\Users\{ACCOUNT}\Downloads", 30 * GIB, 900),
            FolderUsage(
                "documents",
                "Documents",
                rf"C:\Users\{ACCOUNT}\Documents",
                12 * GIB,
                4300,
                truncated=True,
            ),
        ),
        network=NetworkInfo(
            5 * GIB,
            9 * GIB,
            (NetworkInterface("Ethernet", True, 1000), NetworkInterface("Wi-Fi", False)),
        ),
        gpus=(GPUInfo("Test Graphics 4000", "32.0.101", "2026-01-05", 8 * GIB),),
        startup_items=(StartupItem("Updater", "HKCU Run", rf"{TEMP_PATH}\updater.exe"),),
        temp_path=TEMP_PATH,
        temp_locations=(
            TempLocation("User TEMP", TEMP_PATH, 512 * GIB // 1024, 1200, False),
            TempLocation("Windows TEMP", r"C:\Windows\Temp", 64 * GIB // 1024, 90, True),
        ),
        duration_seconds=3.5,
        warnings=("Graphics information was unavailable.",),
    )


def troubled() -> AnalysisData:
    """A snapshot that fires deductions and advice in every category at once.

    The analysed drive is deliberately not the system drive, so the drive-dependent
    sentences carry a value that only the authoritative record can supply.
    """
    return make_analysis(
        cpu_percent=91,
        ram_percent=88,
        swap_percent=85,
        drive="D:\\",
        disk_free=3 * GIB,
        disk_total=512 * GIB,
        disk_is_system=False,
        media_type="HDD",
        process_count=260,
        temp_size=5 * GIB,
        temp_path=TEMP_PATH,
        uptime=200 * 3600.0,
        startup_count=25,
        battery_percent=9.0,
        battery_plugged=False,
        top_processes=(
            ProcessInfo(1000, "browser.exe", 71.0, 6 * GIB, 38.0),
            ProcessInfo(1001, "editor.exe", 2.0, GIB // 2, 3.1),
        ),
        analyzed_at=datetime(2026, 7, 16, 12, 30, tzinfo=timezone.utc),
    )


def exposed() -> AnalysisData:
    """A machine whose protection is off and whose drive is nearly worn out."""
    return replace(
        rich(),
        security=SecurityInfo(
            antivirus=STATE_BAD,
            antivirus_name="Test Antivirus",
            firewall=STATE_BAD,
            secure_boot=STATE_GOOD,
            reboot_pending=False,
            signature_age_days=40,
        ),
        drive_health=(
            DriveHealth("C:\\", model="Worn SSD", percentage_used=94, critical_warning=True),
        ),
    )


def empty() -> AnalysisData:
    """A snapshot in which nothing could be measured."""
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


class ExporterTestCase(unittest.TestCase):
    """Shared fixture: one snapshot with its own score and advice."""

    def setUp(self) -> None:
        self.data = rich()
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)

    def render(self, fmt: str, **kwargs: object) -> str:
        return exporters.render(
            fmt,
            self.data,
            self.recommendations,
            self.assessment,
            **kwargs,  # type: ignore[arg-type]
        )

    def payload(self, **kwargs: object) -> dict[str, object]:
        return exporters.snapshot_to_dict(
            self.data,
            self.recommendations,
            self.assessment,
            **kwargs,  # type: ignore[arg-type]
        )


class FormatVocabularyTests(unittest.TestCase):
    def test_shipped_formats(self) -> None:
        self.assertEqual(exporters.FORMATS, ("text", "json", "html", "markdown"))

    def test_extension_for_every_format(self) -> None:
        self.assertEqual(
            [exporters.extension_for(fmt) for fmt in exporters.FORMATS],
            ["txt", "json", "html", "md"],
        )

    def test_default_filename_round_trips_through_format_from_path(self) -> None:
        moment = datetime(2026, 7, 16, 12, 30, 45)
        for fmt in exporters.FORMATS:
            with self.subTest(fmt=fmt):
                name = exporters.default_filename(fmt, moment)
                self.assertTrue(name.endswith(f".{exporters.extension_for(fmt)}"))
                self.assertIn("20260716_123045", name)
                self.assertEqual(exporters.format_from_path(name), fmt)

    def test_default_filename_is_timestamped_by_default(self) -> None:
        self.assertNotEqual(exporters.default_filename("json"), "")

    def test_format_from_path_accepts_alternative_suffixes(self) -> None:
        for path, expected in (
            ("report.HTM", "html"),
            (Path("folder") / "report.markdown", "markdown"),
            ("report.text", "text"),
            ("report.JSON", "json"),
        ):
            with self.subTest(path=path):
                self.assertEqual(exporters.format_from_path(path), expected)

    def test_format_from_path_returns_none_for_a_foreign_suffix(self) -> None:
        self.assertIsNone(exporters.format_from_path("report.docx"))
        self.assertIsNone(exporters.format_from_path("report"))


class UnknownFormatTests(ExporterTestCase):
    def test_render_rejects_an_unknown_format(self) -> None:
        with self.assertRaises(ValueError):
            self.render("pdf")

    def test_export_rejects_an_unknown_format(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                exporters.export(
                    "pdf",
                    self.data,
                    self.recommendations,
                    self.assessment,
                    Path(folder) / "report.pdf",
                )

    def test_helpers_reject_an_unknown_format(self) -> None:
        for call in (
            lambda: exporters.extension_for("pdf"),
            lambda: exporters.default_filename("pdf"),
        ):
            with self.subTest(call=call):
                with self.assertRaises(ValueError):
                    call()

    def test_known_aliases_are_accepted(self) -> None:
        for alias, expected in (("txt", "text"), ("md", "markdown"), ("HTM", "html")):
            with self.subTest(alias=alias):
                self.assertEqual(exporters.extension_for(alias), exporters.extension_for(expected))


class RenderTests(ExporterTestCase):
    def test_every_format_renders_non_empty_text(self) -> None:
        for fmt in exporters.FORMATS:
            with self.subTest(fmt=fmt):
                content = self.render(fmt)
                self.assertIsInstance(content, str)
                self.assertTrue(content.strip())

    def test_every_format_renders_an_empty_snapshot(self) -> None:
        self.data = empty()
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)
        for fmt in exporters.FORMATS:
            with self.subTest(fmt=fmt):
                self.assertTrue(self.render(fmt).strip())

    def test_text_format_matches_the_plain_report(self) -> None:
        # Without a translator the exporter renders the English catalogue, not the wording a
        # producer happened to store, so the comparison names that language explicitly.
        self.assertEqual(
            self.render("text"),
            build_report(
                self.data,
                self.recommendations,
                self.assessment,
                translator=get_translator("en"),
                colors=None,
            ),
        )

    def test_text_format_carries_no_escape_sequences(self) -> None:
        self.assertNotIn("\x1b", self.render("text"))

    def test_markdown_mentions_the_score_and_stays_non_empty(self) -> None:
        content = self.render("markdown")
        self.assertIn(f"{self.assessment.score}/100", content)
        self.assertIn(self.assessment.status, content)
        self.assertIn("# Apoliak Vitals", content)
        self.assertIn("| PID |", content)

    def test_markdown_escapes_a_pipe_inside_a_cell(self) -> None:
        self.data = replace(
            self.data, top_processes=(ProcessInfo(7, "a|b.exe", 1.0, GIB, 1.0),)
        )
        content = self.render("markdown")
        self.assertIn(r"a\|b.exe", content)

    def test_translator_reaches_every_textual_format(self) -> None:
        translator = get_translator("sk")
        for fmt in ("text", "html", "markdown"):
            with self.subTest(fmt=fmt):
                self.assertIn("len na čítanie", self.render(fmt, translator=translator))


class JsonExportTests(ExporterTestCase):
    def test_json_parses_and_exposes_the_documented_keys(self) -> None:
        payload = json.loads(self.render("json"))
        self.assertEqual(sorted(payload), sorted(JSON_KEYS))

    def test_schema_version_is_reported(self) -> None:
        payload = json.loads(self.render("json"))
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)

    def test_the_schema_version_is_read_from_the_snapshot_never_hardcoded(self) -> None:
        # It was written out as a literal twice before, so an older stored export claimed to
        # be the current schema. The exporter must repeat what the record actually carries.
        self.data = replace(self.data, schema_version="1.9")
        self.assertEqual(json.loads(self.render("json"))["schema_version"], "1.9")
        self.assertNotEqual("1.9", SCHEMA_VERSION)

    def test_a_freshly_built_snapshot_carries_this_releases_schema(self) -> None:
        self.assertEqual(make_analysis().schema_version, SCHEMA_VERSION)

    def test_snapshot_is_json_serialisable_without_a_fallback_encoder(self) -> None:
        # default=None means "no rescue hook": anything unserialisable raises here.
        self.assertTrue(json.dumps(self.payload(), default=None))

    def test_empty_snapshot_is_json_serialisable(self) -> None:
        self.data = empty()
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)
        self.assertTrue(json.dumps(self.payload(), default=None))

    def test_datetimes_are_written_as_iso_strings(self) -> None:
        payload = self.payload()
        self.assertEqual(payload["analyzed_at"], "2026-07-16T12:30:00+00:00")
        system = payload["system"]
        assert isinstance(system, dict)
        self.assertEqual(system["install_date"], "2025-03-01T09:00:00+00:00")

    def test_measurements_survive_the_round_trip(self) -> None:
        payload = json.loads(self.render("json"))
        self.assertEqual(payload["cpu"]["usage_percent"], 42.0)
        self.assertEqual(payload["ram"]["swap_percent"], 25.0)
        self.assertEqual(payload["disk"]["media_type"], "SSD")
        self.assertEqual(len(payload["partitions"]), 2)
        self.assertEqual(payload["processes"]["count"], self.data.process_count)
        self.assertEqual(payload["processes"]["top"][0]["name"], "browser.exe")
        self.assertEqual(payload["battery"]["plugged_in"], False)
        self.assertEqual(payload["network"]["interfaces"][0]["name"], "Ethernet")
        self.assertEqual(payload["gpus"][0]["name"], "Test Graphics 4000")
        self.assertEqual(payload["startup_items"][0]["name"], "Updater")
        self.assertEqual(payload["health"]["score"], self.assessment.score)
        self.assertEqual(payload["generated_by"]["duration_seconds"], 3.5)

    def test_unknown_measurements_stay_null(self) -> None:
        self.data = empty()
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)
        payload = json.loads(self.render("json"))
        self.assertIsNone(payload["cpu"]["usage_percent"])
        self.assertIsNone(payload["uptime_seconds"])
        self.assertIsNone(payload["battery"])
        self.assertIsNone(payload["network"])
        self.assertEqual(payload["gpus"], [])

    def test_recommendation_keys_are_machine_readable(self) -> None:
        payload = json.loads(self.render("json"))
        for item in payload["recommendations"]:
            with self.subTest(item=item):
                self.assertIn("key", item)
                self.assertIn("severity", item)
                self.assertIn("category", item)

    def test_plain_string_advice_is_serialisable(self) -> None:
        self.recommendations = ["Restart the PC."]
        payload = json.loads(self.render("json"))
        self.assertEqual(payload["recommendations"][0]["text"], "Restart the PC.")
        self.assertIsNone(payload["recommendations"][0]["key"])


class HtmlExportTests(ExporterTestCase):
    def test_html_is_a_complete_document(self) -> None:
        content = self.render("html")
        self.assertTrue(content.startswith("<!DOCTYPE html>"))
        self.assertIn("<style>", content)
        self.assertIn("</html>", content)

    def test_html_escapes_injected_markup(self) -> None:
        self.data = replace(
            self.data,
            top_processes=(ProcessInfo(66, "<script>alert(1)</script>", 1.0, GIB, 1.0),),
        )
        content = self.render("html")
        self.assertNotIn("<script>", content)
        self.assertIn("&lt;script&gt;", content)

    def test_html_escapes_an_injected_warning(self) -> None:
        self.data = replace(self.data, warnings=("<img src=x onerror=alert(1)>",))
        content = self.render("html")
        self.assertNotIn("<img src=x", content)
        self.assertIn("&lt;img", content)

    def test_html_makes_no_external_request(self) -> None:
        content = self.render("html")
        self.assertIsNone(_HTTP_REFERENCE.search(content))
        for forbidden in ("<script", "<link", "<iframe", "url(", "@import"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, content)

    def test_html_language_follows_the_translator(self) -> None:
        self.assertIn('<html lang="sk">', self.render("html", translator=get_translator("sk")))
        self.assertIn('<html lang="en">', self.render("html"))


class RedactionTests(ExporterTestCase):
    def test_account_name_is_removed_from_every_format(self) -> None:
        for fmt in exporters.FORMATS:
            with self.subTest(fmt=fmt):
                with patch.dict(os.environ, {"USERNAME": ACCOUNT}):
                    content = self.render(fmt, redact=True)
                self.assertNotIn(ACCOUNT, content)
                self.assertIn("<user>", content.replace("&lt;user&gt;", "<user>"))

    def test_paths_are_kept_when_redaction_is_off(self) -> None:
        for fmt in exporters.FORMATS:
            with self.subTest(fmt=fmt):
                self.assertIn(ACCOUNT, self.render(fmt))

    def test_json_redacts_paths_and_startup_commands(self) -> None:
        payload = self.payload(redact=True)
        temp = payload["temp"]
        assert isinstance(temp, dict)
        self.assertNotIn(ACCOUNT, str(temp["path"]))
        self.assertNotIn(ACCOUNT, json.dumps(payload["startup_items"]))

    def test_json_redacts_the_v2_1_paths(self) -> None:
        # Folder usage is the section that carries a profile path in every single row, so a
        # redacted export that forgot it would leak the account name more thoroughly than
        # any other section could.
        payload = self.payload(redact=True)
        self.assertNotIn(ACCOUNT, json.dumps(payload["folder_usage"]))
        self.assertNotIn(ACCOUNT, json.dumps(payload["security"]))
        self.assertIn("<user>", json.dumps(payload["folder_usage"]))


class SecuritySectionTests(ExporterTestCase):
    """The protection summary: a verdict nobody could read must never look like a finding."""

    def english(self, key: str, default: str) -> str:
        """The catalogue wording, so a future translation cannot break these tests."""
        return render_label(get_translator("en"), key, default)

    def test_json_carries_every_verdict_and_its_details(self) -> None:
        security = self.payload()["security"]
        assert isinstance(security, dict)
        self.assertEqual(security["antivirus"], STATE_GOOD)
        self.assertEqual(security["firewall"], STATE_WEAK)
        self.assertEqual(security["secure_boot"], STATE_UNKNOWN)
        self.assertIs(security["reboot_pending"], True)
        self.assertEqual(security["signature_age_days"], 1)
        self.assertEqual(security["defender_last_scan"], "2026-07-15T03:00:00+00:00")
        self.assertEqual(
            security["details"],
            [
                {"key": "firewall_profiles_off", "value": "Public"},
                {"key": "security_center", "value": "unavailable"},
            ],
        )

    def test_a_verdict_this_version_cannot_interpret_reads_as_unknown(self) -> None:
        self.data = replace(self.data, security=SecurityInfo(antivirus="mostly-fine"))
        security = self.payload()["security"]
        assert isinstance(security, dict)
        self.assertEqual(security["antivirus"], STATE_UNKNOWN)

    def test_markdown_and_html_show_the_section(self) -> None:
        for fmt in ("markdown", "html"):
            with self.subTest(fmt=fmt):
                content = self.render(fmt)
                self.assertIn(self.english("gui.card.security", "Security"), content)
                self.assertIn(self.english("field.antivirus", "Antivirus"), content)
                self.assertIn(self.english("field.state_good", "On"), content)
                self.assertIn(self.english("field.state_weak", "Needs attention"), content)

    def test_the_documents_word_a_verdict_exactly_as_the_text_report_does(self) -> None:
        # One run, four files: a reader who compares two of them has to find one machine
        # described, not two. The text report owns the wording; these two follow it.
        text = self.render("text")
        for key, default in (
            ("field.state_good", "On"),
            ("field.state_weak", "Needs attention"),
            ("field.state_unknown", "Unknown"),
        ):
            word = self.english(key, default)
            with self.subTest(word=word):
                self.assertIn(word, text)
                self.assertIn(word, self.render("markdown"))
                self.assertIn(escape(word), self.render("html"))

    def test_a_machine_nobody_inspected_gets_no_section_at_all(self) -> None:
        self.data = replace(self.data, security=None)
        self.assertIsNone(self.payload()["security"])
        heading = self.english("gui.card.security", "Security")
        self.assertNotIn(f"## {heading}", self.render("markdown"))
        self.assertNotIn(f"<h2>{heading}</h2>", self.render("html"))

    def test_a_snapshot_where_nothing_could_be_read_gets_no_section_either(self) -> None:
        # Three "Unknown" rows are not a finding, and a section header would suggest one.
        self.data = replace(self.data, security=SecurityInfo())
        heading = self.english("gui.card.security", "Security")
        self.assertNotIn(f"## {heading}", self.render("markdown"))
        self.assertNotIn(f"<h2>{heading}</h2>", self.render("html"))
        # The payload still records that protection was inspected and came back unknown.
        security = self.payload()["security"]
        assert isinstance(security, dict)
        self.assertEqual(security["antivirus"], STATE_UNKNOWN)

    def test_html_paints_a_switched_off_antivirus_as_critical(self) -> None:
        self.data = exposed()
        content = self.render("html")
        color = exporters._STATE_COLORS[STATE_BAD]
        word = escape(self.english("field.state_bad", "Off"))
        self.assertIn(f'<span style="color:{color}">{word} (Test Antivirus)</span>', content)
        self.assertIn(f'<span style="color:{color}">{word}</span>', content)

    def test_an_unknown_verdict_is_never_painted(self) -> None:
        # rich() cannot read Secure Boot. That cell says "Unknown" in plain type: colouring
        # it would turn "nobody knows" into a finding the analyser never made.
        content = self.render("html")
        self.assertNotIn(f'color:{exporters._STATE_COLORS[STATE_UNKNOWN]}', content)
        self.assertIn(f'<td>{escape(self.english("field.state_unknown", "Unknown"))}</td>', content)

    def test_an_unreadable_security_center_explains_itself(self) -> None:
        note = self.english("report.security_center_down", "")
        self.assertTrue(note.strip(), "the catalogue owns this sentence")
        for fmt in ("markdown", "html"):
            with self.subTest(fmt=fmt):
                needle = escape(note) if fmt == "html" else note
                self.assertIn(needle, self.render(fmt))

    def test_the_section_wording_follows_the_translator(self) -> None:
        slovak = get_translator("sk")
        expected = render_label(slovak, "field.antivirus", "Antivirus")
        for fmt in ("markdown", "html"):
            with self.subTest(fmt=fmt):
                self.assertIn(expected, self.render(fmt, translator=slovak))


class DriveHealthSectionTests(ExporterTestCase):
    def test_json_carries_the_reported_figures_and_the_derived_life_left(self) -> None:
        drives = self.payload()["drive_health"]
        assert isinstance(drives, list)
        self.assertEqual(len(drives), 2)
        first, second = drives
        self.assertEqual(first["drive"], "C:\\")
        self.assertEqual(first["model"], "Test NVMe 1TB")
        self.assertEqual(first["percentage_used"], 6)
        self.assertEqual(first["life_left_percent"], 94)
        self.assertEqual(first["temperature_celsius"], 41)
        self.assertIs(first["critical_warning"], False)
        self.assertEqual(first["source"], "NVMe SMART log")
        # The drive that reported nothing keeps every figure null - never a zero, never a
        # guess derived from the volume next to it.
        self.assertIsNone(second["percentage_used"])
        self.assertIsNone(second["life_left_percent"])
        self.assertIsNone(second["temperature_celsius"])
        self.assertIsNone(second["critical_warning"])
        self.assertIsNone(second["source"])

    def test_markdown_and_html_list_every_drive(self) -> None:
        heading = render_label(get_translator("en"), "gui.section.drive_health", "Drive health")
        for fmt in ("markdown", "html"):
            with self.subTest(fmt=fmt):
                content = self.render(fmt)
                self.assertIn(heading, content)
                self.assertIn("Test NVMe 1TB", content)
                self.assertIn("Test HDD", content)
                self.assertIn("41 °C", content)

    def test_a_drive_that_answered_nothing_renders_as_na(self) -> None:
        rows = [line for line in self.render("markdown").splitlines() if "Test HDD" in line]
        self.assertTrue(rows, "the drive that answered its name still gets a row")
        self.assertIn("N/A", rows[0])

    def test_a_drive_that_answered_nothing_at_all_is_left_out(self) -> None:
        # A row of nine N/A cells next to a letter is noise, not a measurement.
        self.data = replace(self.data, drive_health=(DriveHealth("E:\\"),))
        heading = render_label(get_translator("en"), "gui.section.drive_health", "Drive health")
        self.assertNotIn(f"## {heading}", self.render("markdown"))
        self.assertNotIn(f"<h2>{heading}</h2>", self.render("html"))
        # It is still written to the payload: the JSON records what was asked, not what
        # was worth printing.
        drives = self.payload()["drive_health"]
        assert isinstance(drives, list)
        self.assertEqual(len(drives), 1)

    def test_html_paints_a_worn_out_drive_red(self) -> None:
        self.data = exposed()
        content = self.render("html")
        self.assertIn(f'<span style="color:{exporters._score_color(6)}">6%</span>', content)

    def test_no_section_when_no_drive_could_be_read(self) -> None:
        self.data = replace(self.data, drive_health=())
        heading = render_label(get_translator("en"), "gui.section.drive_health", "Drive health")
        self.assertEqual(self.payload()["drive_health"], [])
        self.assertNotIn(f"## {heading}", self.render("markdown"))
        self.assertNotIn(f"<h2>{heading}</h2>", self.render("html"))


class FolderUsageSectionTests(ExporterTestCase):
    def test_json_carries_the_measured_folders_in_the_order_they_were_ranked(self) -> None:
        folders = self.payload()["folder_usage"]
        assert isinstance(folders, list)
        self.assertEqual([item["key"] for item in folders], ["downloads", "documents"])
        self.assertEqual(folders[0]["size_bytes"], 30 * GIB)
        self.assertEqual(folders[0]["file_count"], 900)
        self.assertIs(folders[0]["truncated"], False)
        self.assertIs(folders[1]["truncated"], True)

    def test_markdown_and_html_keep_the_biggest_folder_first(self) -> None:
        for fmt in ("markdown", "html"):
            with self.subTest(fmt=fmt):
                content = self.render(fmt)
                self.assertLess(content.index("Downloads"), content.index("Documents"))

    def test_a_folder_scan_that_ran_out_of_time_says_so(self) -> None:
        partial = render_label(get_translator("en"), "report.partial_scan", "partial scan")
        for fmt in ("markdown", "html"):
            with self.subTest(fmt=fmt):
                self.assertIn(partial, self.render(fmt))

    def test_markup_injected_into_a_folder_label_cannot_escape(self) -> None:
        self.data = replace(
            self.data,
            folder_usage=(
                FolderUsage("evil", "<script>alert(1)</script>", r"C:\Data|x", 1024, 1),
            ),
        )
        html = self.render("html")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)
        # The same hostile label in Markdown must not open a new table column either.
        self.assertIn(r"C:\Data\|x", self.render("markdown"))

    def test_paths_are_redacted_in_every_format(self) -> None:
        for fmt in exporters.FORMATS:
            with self.subTest(fmt=fmt):
                with patch.dict(os.environ, {"USERNAME": ACCOUNT}):
                    content = self.render(fmt, redact=True)
                self.assertNotIn(ACCOUNT, content)

    def test_no_section_when_nothing_was_scanned(self) -> None:
        self.data = replace(self.data, folder_usage=())
        heading = render_label(get_translator("en"), "gui.section.folders", "Biggest folders")
        self.assertEqual(self.payload()["folder_usage"], [])
        self.assertNotIn(f"## {heading}", self.render("markdown"))
        self.assertNotIn(f"<h2>{heading}</h2>", self.render("html"))


class BatteryWearExportTests(ExporterTestCase):
    def test_json_battery_carries_the_wear_figures(self) -> None:
        battery = self.payload()["battery"]
        assert isinstance(battery, dict)
        self.assertEqual(battery["design_capacity_mwh"], 80_000)
        self.assertEqual(battery["full_charge_capacity_mwh"], 68_000)
        self.assertEqual(battery["cycle_count"], 214)
        self.assertEqual(battery["chemistry"], "LION")
        self.assertEqual(battery["health_percent"], 85.0)

    def test_documents_show_the_health_and_the_capacities(self) -> None:
        for fmt in ("markdown", "html"):
            with self.subTest(fmt=fmt):
                content = self.render(fmt)
                self.assertIn(
                    render_label(get_translator("en"), "field.battery_health", "Battery Health"),
                    content,
                )
                self.assertIn("85%", content)
                self.assertIn("80 000 mWh", content)
                self.assertIn("214", content)

    def test_a_pack_that_reports_no_capacity_stays_silent_about_wear(self) -> None:
        self.data = replace(self.data, battery=BatteryInfo(64.0, False, 5400))
        battery = self.payload()["battery"]
        assert isinstance(battery, dict)
        self.assertIsNone(battery["health_percent"])
        self.assertIsNone(battery["design_capacity_mwh"])
        label = render_label(get_translator("en"), "field.battery_health", "Battery Health")
        for fmt in ("markdown", "html"):
            with self.subTest(fmt=fmt):
                self.assertNotIn(label, self.render(fmt))


class ActionUriExportTests(ExporterTestCase):
    """A settings link belongs in the machine-readable file, never in a document."""

    URI = "ms-settings:windowsdefender"

    def setUp(self) -> None:
        super().setUp()
        self.recommendations = [
            Recommendation(
                key="antivirus_off",
                text="Turn Windows Security back on.",
                severity="critical",
                action_uri=self.URI,
            )
        ]

    def test_json_exports_it_as_a_plain_string(self) -> None:
        advice = self.payload()["recommendations"]
        assert isinstance(advice, list)
        self.assertEqual(advice[0]["action_uri"], self.URI)

    def test_plain_string_advice_has_no_action(self) -> None:
        self.recommendations = ["Restart the PC."]
        advice = self.payload()["recommendations"]
        assert isinstance(advice, list)
        self.assertIsNone(advice[0]["action_uri"])

    def test_no_document_format_mentions_or_links_it(self) -> None:
        for fmt in ("text", "markdown", "html"):
            with self.subTest(fmt=fmt):
                content = self.render(fmt)
                self.assertNotIn("ms-settings:", content)
        html = self.render("html")
        self.assertNotIn("<a ", html)
        self.assertNotIn("href", html)


class ExportFileTests(ExporterTestCase):
    def export(self, fmt: str, destination: Path, **kwargs: object) -> Path:
        return exporters.export(
            fmt,
            self.data,
            self.recommendations,
            self.assessment,
            destination,
            **kwargs,  # type: ignore[arg-type]
        )

    def test_export_writes_every_format_to_an_explicit_file(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            for fmt in exporters.FORMATS:
                with self.subTest(fmt=fmt):
                    suffix = exporters.extension_for(fmt)
                    saved = self.export(fmt, Path(folder) / f"report.{suffix}")
                    self.assertTrue(saved.exists())
                    self.assertEqual(saved.suffix, f".{suffix}")
                    self.assertEqual(saved.read_text(encoding="utf-8"), self.render(fmt))

    def test_export_into_a_directory_uses_the_default_name(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            for fmt in exporters.FORMATS:
                with self.subTest(fmt=fmt):
                    saved = self.export(fmt, Path(folder))
                    self.assertTrue(saved.is_absolute())
                    self.assertEqual(saved, saved.resolve())
                    self.assertEqual(saved.parent, Path(folder).resolve())
                    self.assertEqual(saved.suffix, f".{exporters.extension_for(fmt)}")

    def test_export_creates_missing_parent_folders(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            saved = self.export("json", Path(folder) / "deep" / "nested" / "report.json")
            self.assertTrue(saved.exists())
            self.assertTrue(json.loads(saved.read_text(encoding="utf-8")))

    def test_exported_file_is_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            saved = self.export(
                "markdown", Path(folder) / "sk.md", translator=get_translator("sk")
            )
            self.assertIn("čítanie".encode("utf-8"), saved.read_bytes())

    def test_export_honours_redaction(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"USERNAME": ACCOUNT}):
                saved = self.export("json", Path(folder) / "report.json", redact=True)
            self.assertNotIn(ACCOUNT, saved.read_text(encoding="utf-8"))


class WordingConsistencyTests(unittest.TestCase):
    """One run, five renderings, one wording.

    The i18n catalogue is the single source of truth for user-facing sentences. The
    producers keep their own English text as a last-resort fallback, but no renderer may
    print it while the catalogue has an entry - otherwise the text report and the JSON of
    the very same analysis describe the same finding with two different sentences.
    """

    def setUp(self) -> None:
        self.data = troubled()
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)
        self.english = get_translator("en")
        self.rendered = {
            "text (no translator)": self.render(),
            "text (english)": self.render(translator=self.english),
            "markdown": self.render("markdown"),
            "html": self.render("html"),
        }
        self.payload = json.loads(self.render("json"))
        # The fixture is only worth anything if it actually produced findings.
        self.assertTrue(self.assessment.deductions)
        self.assertTrue(self.recommendations)

    def render(self, fmt: str = "text", **kwargs: object) -> str:
        return exporters.render(
            fmt,
            self.data,
            self.recommendations,
            self.assessment,
            **kwargs,  # type: ignore[arg-type]
        )

    def assert_present(self, expected: str, label: str, content: str) -> None:
        """HTML escapes what the other formats write literally; everything else is plain."""
        needle = escape(expected) if label == "html" else expected
        self.assertIn(needle, content, f"{label} does not carry the catalogue wording")

    def test_every_recommendation_reads_the_same_in_every_format(self) -> None:
        json_texts = [item["text"] for item in self.payload["recommendations"]]
        for item in self.recommendations:
            expected = self.english.t(f"recommendation.{item.key}", **item.values)
            with self.subTest(key=item.key):
                self.assertIn(expected, json_texts)
                for label, content in self.rendered.items():
                    self.assert_present(expected, label, content)

    def test_every_deduction_reads_the_same_in_every_format(self) -> None:
        json_reasons = [item["reason"] for item in self.payload["health"]["deductions"]]
        for item in self.assessment.deductions:
            expected = self.english.t(f"deduction.{item.key}", **item.values)
            with self.subTest(key=item.key):
                self.assertIn(expected, json_reasons)
                for label, content in self.rendered.items():
                    self.assert_present(expected, label, content)

    def test_no_format_prints_the_producer_wording_instead(self) -> None:
        produced = [
            *((f"recommendation.{i.key}", i.text) for i in self.recommendations),
            *((f"deduction.{i.key}", i.reason) for i in self.assessment.deductions),
        ]
        catalogue = [
            self.english.t(f"recommendation.{i.key}", **i.values) for i in self.recommendations
        ] + [
            self.english.t(f"deduction.{i.key}", **i.values) for i in self.assessment.deductions
        ]
        for key, own_text in produced:
            # A producer sentence that is a fragment of a catalogue sentence cannot be told
            # apart by searching the document, so it proves nothing either way.
            if any(own_text in expected for expected in catalogue):
                continue
            with self.subTest(key=key):
                for label, content in self.rendered.items():
                    self.assertNotIn(own_text, content, f"{label} quoted the producer")
                self.assertNotIn(own_text, json.dumps(self.payload, ensure_ascii=False))

    def test_a_missing_translator_renders_exactly_like_the_english_one(self) -> None:
        self.assertEqual(self.rendered["text (no translator)"], self.rendered["text (english)"])
        for fmt in exporters.FORMATS:
            with self.subTest(fmt=fmt):
                self.assertEqual(self.render(fmt), self.render(fmt, translator=self.english))

    def test_the_json_snapshot_resolves_its_text_through_the_catalogue(self) -> None:
        payload = exporters.snapshot_to_dict(self.data, self.recommendations, self.assessment)
        for item, stored in zip(self.recommendations, payload["recommendations"]):
            with self.subTest(key=item.key):
                self.assertEqual(
                    stored["text"], self.english.t(f"recommendation.{item.key}", **item.values)
                )
        for item, stored in zip(
            self.assessment.deductions, payload["health"]["deductions"]
        ):
            with self.subTest(key=item.key):
                self.assertEqual(
                    stored["reason"], self.english.t(f"deduction.{item.key}", **item.values)
                )

    def test_a_chosen_language_is_applied_by_every_format_alike(self) -> None:
        slovak = get_translator("sk")
        renders = {
            fmt: self.render(fmt, translator=slovak)
            for fmt in ("text", "markdown", "html")
        }
        payload = json.loads(self.render("json", translator=slovak))
        json_texts = [item["text"] for item in payload["recommendations"]]
        for item in self.recommendations:
            expected = slovak.t(f"recommendation.{item.key}", **item.values)
            with self.subTest(key=item.key):
                self.assertNotEqual(
                    expected, self.english.t(f"recommendation.{item.key}", **item.values)
                )
                self.assertIn(expected, json_texts)
                for label, content in renders.items():
                    self.assert_present(expected, label, content)


class TruncatedTempExportTests(unittest.TestCase):
    """A TEMP size the scan never finished must be labelled as a floor in every format."""

    PARTIAL = "partial scan"

    def setUp(self) -> None:
        self.data = replace(
            troubled(),
            temp_truncated=True,
            temp_locations=(
                TempLocation("User TEMP", TEMP_PATH, 5 * GIB, 900, True),
                TempLocation("Windows TEMP", r"C:\Windows\Temp", GIB, 40, False),
            ),
        )
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)

    def render(self, fmt: str, data: AnalysisData | None = None) -> str:
        source = self.data if data is None else data
        return exporters.render(
            fmt, source, generate_recommendations(source), calculate_health_details(source)
        )

    def test_the_json_snapshot_carries_the_flag(self) -> None:
        payload = json.loads(self.render("json"))
        self.assertTrue(payload["temp"]["truncated"])
        self.assertTrue(payload["temp"]["locations"][0]["truncated"])
        self.assertFalse(payload["temp"]["locations"][1]["truncated"])
        self.assertFalse(payload["health"]["data_complete"])

    def test_the_lower_bound_wording_reaches_every_format(self) -> None:
        for fmt in exporters.FORMATS:
            with self.subTest(fmt=fmt):
                self.assertIn("at least 5.0 GB", self.render(fmt))

    def test_the_readable_formats_label_the_size_as_partial(self) -> None:
        for fmt in ("text", "markdown", "html"):
            with self.subTest(fmt=fmt):
                self.assertIn(self.PARTIAL, self.render(fmt))

    def test_an_untruncated_snapshot_says_none_of_it(self) -> None:
        complete = replace(
            self.data,
            temp_truncated=False,
            temp_locations=(TempLocation("User TEMP", TEMP_PATH, 5 * GIB, 900, False),),
        )
        for fmt in exporters.FORMATS:
            with self.subTest(fmt=fmt):
                content = self.render(fmt, complete)
                self.assertNotIn("at least", content)
                self.assertNotIn(self.PARTIAL, content)
        payload = json.loads(self.render("json", complete))
        self.assertFalse(payload["temp"]["truncated"])

    def test_the_incompleteness_is_disclosed_alongside_the_score(self) -> None:
        self.assertFalse(self.assessment.data_complete)
        self.assertIn("incomplete_data", [item.key for item in self.recommendations])


class TranslatedLowerBoundTests(unittest.TestCase):
    """"At least" is a sentence, so it belongs to the reader's language.

    src/health_score.py used to bake the English words into the deduction's ``value``
    parameter, so a Slovak report read "Priecinok TEMP obsahuje vela udajov (at least 12.0
    GB)." The producers now hand over the plain measurement plus a language-neutral marker,
    and the shared rendering helper words the qualifier through ``report.at_least`` - which
    is why the assertions below are the same in all four formats and in both languages.
    """

    SIZE = 12 * GIB
    MEASUREMENT = "12.0 GB"
    #: How the qualifier has to read once the renderer is done with it.
    BOUNDED = {"en": f"at least {MEASUREMENT}", "sk": f"aspoň {MEASUREMENT}"}
    #: The English words that must not survive translation into a Slovak document.
    ENGLISH_ONLY = ("at least", "partial scan")

    def setUp(self) -> None:
        self.data = replace(
            make_analysis(temp_size=self.SIZE, temp_path=TEMP_PATH),
            temp_truncated=True,
            temp_locations=(TempLocation("User TEMP", TEMP_PATH, self.SIZE, 900, True),),
        )
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)
        self.deduction = next(
            item for item in self.assessment.deductions if item.key == "large_temp"
        )
        self.advice = next(item for item in self.recommendations if item.key == "large_temp")

    def render(self, fmt: str, language: str) -> str:
        return exporters.render(
            fmt,
            self.data,
            self.recommendations,
            self.assessment,
            translator=get_translator(language),
        )

    def test_the_producers_hand_over_a_measurement_and_a_marker(self) -> None:
        # Neither side may bake the qualifier into the number: that is what made the Slovak
        # report speak English in the middle of a sentence.
        for item in (self.deduction, self.advice):
            with self.subTest(key=type(item).__name__):
                self.assertEqual(item.values["value"], self.MEASUREMENT)
                self.assertEqual(item.values["bound"], "lower")
                self.assertNotIn("at least", item.values["value"])

    def test_the_english_fallback_sentences_stay_readable_english(self) -> None:
        # They are what a consumer without a translator prints, so they keep the qualifier.
        self.assertIn(self.BOUNDED["en"], self.deduction.reason)
        self.assertIn(self.BOUNDED["en"], self.advice.text)

    def test_every_format_words_the_bound_in_the_chosen_language(self) -> None:
        for language, expected in self.BOUNDED.items():
            for fmt in exporters.FORMATS:
                with self.subTest(language=language, fmt=fmt):
                    self.assertIn(expected, self.render(fmt, language))

    def test_the_catalogue_alone_never_words_the_qualifier(self) -> None:
        # The bound is resolved by the shared rendering helper, not by the string table: a
        # translator asked for the key on its own gets the plain measurement back.
        slovak = get_translator("sk")
        self.assertNotIn(
            self.BOUNDED["sk"],
            slovak.t(f"deduction.{self.deduction.key}", **self.deduction.values),
        )

    def test_the_deduction_and_the_advice_agree_in_every_format(self) -> None:
        # One run may not state one measurement two ways: the advice used to quote the
        # truncated size as an exact total while the deduction called it a floor. Both
        # sentences are built through the one helper every format shares, so agreeing here
        # is what makes the four documents agree.
        for language, expected in self.BOUNDED.items():
            translator = get_translator(language)
            reason = render_label(
                translator,
                f"deduction.{self.deduction.key}",
                self.deduction.reason,
                **self.deduction.values,
            )
            text = render_label(
                translator,
                f"recommendation.{self.advice.key}",
                self.advice.text,
                **self.advice.values,
            )
            self.assertIn(expected, reason)
            self.assertIn(expected, text)
            for fmt in ("text", "markdown", "json"):
                with self.subTest(language=language, fmt=fmt):
                    content = self.render(fmt, language)
                    self.assertIn(reason, content)
                    self.assertIn(text, content)

    def test_no_english_qualifier_survives_in_a_slovak_document(self) -> None:
        for fmt in exporters.FORMATS:
            content = self.render(fmt, "sk")
            for phrase in self.ENGLISH_ONLY:
                with self.subTest(fmt=fmt, phrase=phrase):
                    self.assertNotIn(phrase, content)

    def test_the_json_export_keeps_the_measurement_and_the_marker_apart(self) -> None:
        # A machine reader has to get the number, not a sentence about the number.
        payload = json.loads(self.render("json", "sk"))
        stored = next(
            item for item in payload["health"]["deductions"] if item["key"] == "large_temp"
        )
        self.assertEqual(stored["params"], {"value": self.MEASUREMENT, "bound": "lower"})
        self.assertIn(self.BOUNDED["sk"], stored["reason"])
        advice = next(
            item for item in payload["recommendations"] if item["key"] == "large_temp"
        )
        self.assertEqual(advice["params"]["value"], self.MEASUREMENT)
        self.assertIn(self.BOUNDED["sk"], advice["text"])

    def test_the_partial_scan_note_is_translated_too(self) -> None:
        # The headline carries a tag and the line under it says what the tag means; both are
        # catalogue entries, and report.temp_truncated shipped unused until v2.0.
        slovak = get_translator("sk")
        content = self.render("text", "sk")
        self.assertIn(slovak.t("report.partial_scan"), content)
        self.assertIn(slovak.t("report.temp_truncated"), content)

    def test_an_untruncated_run_carries_no_qualifier_in_either_language(self) -> None:
        self.data = replace(
            self.data,
            temp_truncated=False,
            temp_locations=(TempLocation("User TEMP", TEMP_PATH, self.SIZE, 900, False),),
        )
        self.recommendations = generate_recommendations(self.data)
        self.assessment = calculate_health_details(self.data)
        for language, bounded in self.BOUNDED.items():
            for fmt in exporters.FORMATS:
                with self.subTest(language=language, fmt=fmt):
                    content = self.render(fmt, language)
                    self.assertIn(self.MEASUREMENT, content)
                    self.assertNotIn(bounded, content)


class PoisonedValue:
    """A value that explodes the moment a renderer tries to write it."""

    def __str__(self) -> str:
        raise TypeError("this value cannot be rendered")


class PoisonedDisk:
    """A partition whose every measurement explodes when a renderer reads it."""

    @property
    def drive(self) -> str:
        raise TypeError("this partition cannot be read")

    def __getattr__(self, name: str) -> object:
        raise TypeError("this partition cannot be read")


class PoisonedProcess:
    """A process entry that explodes the moment its fields are read."""

    @property
    def pid(self) -> int:
        raise TypeError("this process cannot be read")

    def __getattr__(self, name: str) -> object:
        raise TypeError("this process cannot be read")


class RendererFailureTests(unittest.TestCase):
    """A defective section costs its own section, never the export.

    The plain-text builder has always had this net. HTML and Markdown gained it in v2.0, and
    JSON followed once it became clear that a data file which raises loses a completed
    analysis the user cannot repeat - the very outcome the net exists to prevent. JSON says
    so in its own terms: the damaged branch is null and names itself in ``export_errors``.
    """

    def setUp(self) -> None:
        self.data = replace(troubled(), warnings=(PoisonedValue(),))  # type: ignore[arg-type]
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)

    def render(self, fmt: str) -> str:
        return exporters.render(fmt, self.data, self.recommendations, self.assessment)

    DOCUMENT_FORMATS = ("text", "markdown", "html", "json")

    def test_no_document_format_raises_on_a_snapshot_that_cannot_be_written(self) -> None:
        for fmt in self.DOCUMENT_FORMATS:
            with self.subTest(fmt=fmt):
                self.assertTrue(self.render(fmt).strip())

    def test_the_damage_is_reported_and_contained(self) -> None:
        for fmt in self.DOCUMENT_FORMATS:
            with self.subTest(fmt=fmt):
                content = self.render(fmt)
                self.assertIn("could not be rendered", content)
                # The sections around it still made it into the document.
                self.assertIn("browser.exe", content)

    def test_the_json_export_still_parses_and_keeps_its_other_sections(self) -> None:
        # The hostile values sit in two different branches, so a net that only caught the
        # first one would still be missing the point.
        data = replace(
            self.data,
            partitions=(PoisonedDisk(),),  # type: ignore[arg-type]
            top_processes=(PoisonedProcess(),),  # type: ignore[arg-type]
        )
        payload = json.loads(
            exporters.render("json", data, self.recommendations, self.assessment)
        )
        self.assertIsNone(payload["partitions"])
        self.assertIsNone(payload["processes"])
        self.assertIsNone(payload["warnings"])
        damaged = {item["section"] for item in payload["export_errors"]}
        self.assertEqual(damaged, {"partitions", "processes", "warnings"})
        # Everything the snapshot could still answer survived the three broken branches.
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertEqual(payload["cpu"]["usage_percent"], data.cpu.usage_percent)
        self.assertEqual(payload["disk"]["drive"], data.disk.drive)
        self.assertEqual(payload["health"]["score"], self.assessment.score)
        self.assertTrue(payload["recommendations"])

    def test_a_healthy_export_reports_no_damage_at_all(self) -> None:
        payload = json.loads(
            exporters.render("json", troubled(), generate_recommendations(troubled()),
                             calculate_health_details(troubled()))
        )
        self.assertEqual(payload["export_errors"], [])

    def test_only_an_unknown_format_name_raises_and_it_raises_value_error(self) -> None:
        for name in ("pdf", "", "  ", "doc", "json5", 7, None):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    exporters.render(
                        name,  # type: ignore[arg-type]
                        self.data,
                        self.recommendations,
                        self.assessment,
                    )


class PoisonedAttributes:
    """Any object whose every field explodes the moment something reads it."""

    def __getattr__(self, name: str) -> object:
        raise TypeError("this record cannot be read")


class JsonSectionNetTests(unittest.TestCase):
    """One hostile value per section, swept over every section the payload has.

    Text, HTML and Markdown have always contained a failure inside the section that caused
    it. snapshot_to_dict had no net at all, so a single unwritable value raised out of the
    whole export and lost a completed analysis the user cannot repeat. The sweep below aims
    one hostile value at each branch in turn and asks for the same three things every time:
    the file still parses, the damaged branch is null, and it names itself.
    """

    #: Section name -> the snapshot field that feeds it a value it cannot write.
    HOSTILE_FIELDS: dict[str, dict[str, object]] = {
        "schema_version": {"schema_version": PoisonedValue()},
        "analyzed_at": {"analyzed_at": PoisonedValue()},
        "system": {"system": PoisonedAttributes()},
        "cpu": {"cpu": PoisonedAttributes()},
        "ram": {"ram": PoisonedAttributes()},
        "disk": {"disk": PoisonedAttributes()},
        "partitions": {"partitions": (PoisonedDisk(),)},
        "drive_health": {"drive_health": (PoisonedAttributes(),)},
        "processes": {"process_count": PoisonedValue()},
        "temp": {"temp_path": PoisonedValue()},
        "folder_usage": {"folder_usage": (PoisonedAttributes(),)},
        "security": {"security": PoisonedAttributes()},
        "battery": {"battery": PoisonedAttributes()},
        "network": {"network": PoisonedAttributes()},
        "gpus": {"gpus": (PoisonedAttributes(),)},
        "startup_items": {"startup_items": (PoisonedAttributes(),)},
        "warnings": {"warnings": (PoisonedValue(),)},
    }

    #: The two sections a snapshot cannot poison: they write constants and a number that
    #: _number() has already reduced to an int, a float or None. Asserted rather than
    #: silently skipped, so a future section that starts reading real data is noticed.
    CONSTANT_SECTIONS = ("generated_by", "uptime_seconds")

    def setUp(self) -> None:
        self.data = troubled()
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)

    def payload(
        self,
        data: object | None = None,
        *,
        recommendations: object | None = None,
        assessment: object | None = None,
    ) -> dict[str, object]:
        advice = self.recommendations if recommendations is None else recommendations
        content = exporters.render(
            "json",
            self.data if data is None else data,  # type: ignore[arg-type]
            advice,  # type: ignore[arg-type]
            self.assessment if assessment is None else assessment,  # type: ignore[arg-type]
        )
        return json.loads(content)  # Parseable JSON is the whole point of the net.

    def test_the_sweep_covers_every_section_of_the_payload(self) -> None:
        # A section added without a hostile case would otherwise never be swept.
        covered = set(self.HOSTILE_FIELDS) | set(self.CONSTANT_SECTIONS) | {
            "health",
            "recommendations",
            "export_errors",
        }
        self.assertEqual(covered, set(JSON_KEYS))

    def test_each_section_survives_its_own_hostile_value(self) -> None:
        for section, fields in self.HOSTILE_FIELDS.items():
            with self.subTest(section=section):
                payload = self.payload(replace(self.data, **fields))
                self.assertIsNone(payload[section], "the damaged branch is written as null")
                damaged = {item["section"] for item in payload["export_errors"]}
                self.assertIn(section, damaged, "the damaged branch has to name itself")
                self.assertTrue(str(payload["export_errors"][0]["error"]).strip())

    def test_the_damage_never_spreads_beyond_its_own_section(self) -> None:
        # Measured against a healthy export of the same snapshot, so "nothing else changed"
        # is exact rather than a count: only the poisoned branch may turn null.
        healthy = self.payload()
        already_null = {name for name in JSON_KEYS if healthy[name] is None}
        for section, fields in self.HOSTILE_FIELDS.items():
            with self.subTest(section=section):
                payload = self.payload(replace(self.data, **fields))
                nulls = {name for name in JSON_KEYS if payload[name] is None}
                self.assertEqual(nulls, already_null | {section})
                self.assertEqual(payload["health"]["score"], self.assessment.score)
                self.assertTrue(payload["recommendations"])

    def test_a_hostile_assessment_only_costs_the_health_section(self) -> None:
        payload = self.payload(self.data, assessment=PoisonedAttributes())
        self.assertIsNone(payload["health"])
        self.assertEqual(
            {item["section"] for item in payload["export_errors"]}, {"health"}
        )
        self.assertEqual(payload["cpu"]["usage_percent"], self.data.cpu.usage_percent)

    def test_hostile_advice_only_costs_the_recommendations_section(self) -> None:
        payload = self.payload(self.data, recommendations=[PoisonedValue()])
        self.assertIsNone(payload["recommendations"])
        self.assertEqual(
            {item["section"] for item in payload["export_errors"]}, {"recommendations"}
        )
        self.assertEqual(payload["health"]["score"], self.assessment.score)

    def test_the_two_constant_sections_are_written_even_next_to_a_broken_neighbour(self) -> None:
        payload = self.payload(replace(self.data, cpu=PoisonedAttributes()))
        for section in self.CONSTANT_SECTIONS:
            with self.subTest(section=section):
                self.assertIsNotNone(payload[section])

    def test_several_broken_sections_at_once_still_leave_a_usable_file(self) -> None:
        data = replace(
            self.data,
            partitions=(PoisonedDisk(),),
            top_processes=(PoisonedProcess(),),
            warnings=(PoisonedValue(),),
            gpus=(PoisonedAttributes(),),
        )
        payload = self.payload(data)
        damaged = {item["section"] for item in payload["export_errors"]}
        self.assertEqual(damaged, {"partitions", "processes", "warnings", "gpus"})
        self.assertEqual(payload["schema_version"], SCHEMA_VERSION)
        self.assertEqual(payload["disk"]["drive"], data.disk.drive)

    def test_a_hostile_value_never_reaches_the_caller_as_an_exception(self) -> None:
        # The one thing the net exists for: render() may only raise for an unknown format.
        for section, fields in self.HOSTILE_FIELDS.items():
            with self.subTest(section=section):
                content = exporters.render(
                    "json",
                    replace(self.data, **fields),
                    self.recommendations,
                    self.assessment,
                )
                self.assertTrue(json.loads(content))

    def test_only_an_unknown_format_raises_and_it_raises_value_error(self) -> None:
        hostile = replace(self.data, warnings=(PoisonedValue(),))
        for name in ("pdf", "", "  ", "doc", "json5", 7, None, [], object()):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    exporters.render(
                        name,  # type: ignore[arg-type]
                        hostile,
                        self.recommendations,
                        self.assessment,
                    )


class AutoNameCollisionTests(unittest.TestCase):
    """Two exports started in the same second must not silently replace each other."""

    def setUp(self) -> None:
        self.data = troubled()
        self.assessment = calculate_health_details(self.data)
        self.recommendations = generate_recommendations(self.data)
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)

    def export(self, destination: Path) -> Path:
        return exporters.export(
            "text", self.data, self.recommendations, self.assessment, destination
        )

    def test_the_generated_name_really_does_collide(self) -> None:
        # The timestamp resolves to whole seconds, which is what makes unique_path necessary.
        moment = datetime(2026, 7, 16, 12, 30, 30)
        self.assertEqual(
            exporters.default_filename("text", moment), exporters.default_filename("text", moment)
        )

    def test_two_automatic_exports_in_the_same_second_produce_two_files(self) -> None:
        with patch.object(exporters, "default_filename", return_value="report.txt"):
            first = self.export(self.folder)
            second = self.export(self.folder)
        self.assertNotEqual(first, second)
        self.assertEqual(first.name, "report.txt")
        self.assertEqual(second.name, "report_2.txt")
        self.assertEqual(sorted(item.name for item in self.folder.iterdir()),
                         ["report.txt", "report_2.txt"])

    def test_the_counter_keeps_going_past_two(self) -> None:
        with patch.object(exporters, "default_filename", return_value="report.txt"):
            names = [self.export(self.folder).name for _ in range(4)]
        self.assertEqual(names, ["report.txt", "report_2.txt", "report_3.txt", "report_4.txt"])

    def test_an_explicit_path_still_overwrites(self) -> None:
        # Naming a file means "put it here"; stepping aside would surprise the user.
        destination = self.folder / "chosen.txt"
        destination.write_text("older content", encoding="utf-8")
        saved = self.export(destination)
        self.assertEqual(saved, destination.resolve())
        self.assertEqual(list(self.folder.iterdir()), [destination])
        self.assertNotIn("older content", destination.read_text(encoding="utf-8"))

    def test_unique_path_leaves_a_free_name_alone(self) -> None:
        candidate = self.folder / "free.txt"
        self.assertEqual(exporters.unique_path(candidate), candidate)

    def test_unique_path_keeps_the_suffix_and_only_varies_the_stem(self) -> None:
        (self.folder / "report.json").write_text("{}", encoding="utf-8")
        resolved = exporters.unique_path(self.folder / "report.json")
        self.assertEqual(resolved.suffix, ".json")
        self.assertEqual(resolved.stem, "report_2")

    def test_a_pathless_target_is_returned_unchanged(self) -> None:
        root = Path(self.folder.anchor or self.folder)
        self.assertEqual(exporters.unique_path(root.anchor), Path(root.anchor))


if __name__ == "__main__":
    unittest.main()
