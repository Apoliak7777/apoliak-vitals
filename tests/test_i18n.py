"""Tests for the bilingual string tables.

Two properties matter more than any individual sentence: the two languages must expose the
same keys with the same placeholders, and no raw key may ever reach a rendered report. The
second is checked end to end, with a set of snapshots that fires every deduction and every
recommendation the engine can produce.
"""

from __future__ import annotations

import os
import re
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from string import Formatter
from unittest.mock import patch

import main
from src import exporters, i18n
from src.health_score import calculate_health_details
from src.i18n import (
    LANGUAGES,
    Translator,
    available_languages,
    detect_language,
    get_translator,
    language_label,
    translation_keys,
)
from src.models import (
    CATEGORY_CPU,
    STATE_BAD,
    STATE_UNKNOWN,
    STATE_WEAK,
    AnalysisData,
    BatteryInfo,
    CPUInfo,
    DiskInfo,
    DriveHealth,
    FolderUsage,
    HealthAssessment,
    ProcessInfo,
    RAMInfo,
    ScoreDeduction,
    SecurityInfo,
    StartupItem,
    SystemInfo,
)
from src.recommendations import generate_recommendations
from src.utils import GIB, TIB
from tests.helpers import make_analysis

#: The fixed vocabulary every module shares. Duplicated here on purpose: the test has to
#: fail when a key is silently renamed on one side.
DEDUCTION_KEYS = (
    "high_cpu",
    "high_ram",
    "high_swap",
    "low_disk",
    "disk_nearly_full",
    "many_processes",
    "large_temp",
    "long_uptime",
    "many_startup_items",
    "low_battery",
    # v2.1: durable state rather than momentary load.
    "antivirus_off",
    "firewall_off",
    "stale_signatures",
    "reboot_pending",
    "drive_failing",
    "drive_worn",
    "battery_worn",
)

RECOMMENDATION_KEYS = (
    "high_cpu",
    "medium_cpu",
    "high_ram",
    "medium_ram",
    "high_swap",
    "medium_swap",
    "low_disk",
    "medium_disk",
    "disk_nearly_full",
    "medium_disk_full",
    "many_processes",
    "some_processes",
    "large_temp",
    "medium_temp",
    "long_uptime",
    "medium_uptime",
    "many_startup_items",
    "low_battery",
    "top_memory_process",
    "top_cpu_process",
    "hdd_system_drive",
    "incomplete_data",
    "all_good",
    # v2.1. secure_boot_off is advice with no matching deduction on purpose: Secure Boot is
    # off for legitimate reasons, so it is reported without costing the machine a point.
    "antivirus_off",
    "firewall_off",
    "stale_signatures",
    "reboot_pending",
    "secure_boot_off",
    "drive_failing",
    "drive_worn",
    "battery_worn",
    "large_folder",
)

STATUS_KEYS = ("excellent", "good", "needs_optimization", "poor")
SEVERITY_KEYS = ("info", "warning", "critical")
CATEGORY_KEYS = ("cpu", "memory", "storage", "maintenance", "power", "security", "general")

#: Prefixes that identify a translation key. None of them may survive into rendered output.
KEY_PREFIXES = ("deduction.", "recommendation.", "gui.", "field.", "section.", "status.",
                "severity.", "category.", "report.", "cli.")

#: Environment variables that steer detect_language(); cleared so a test cannot inherit them.
LOCALE_VARIABLES = ("APOLIAK_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE")


def placeholders(template: str) -> tuple[str, ...]:
    """Named ``str.format`` fields used by one template, in sorted order."""
    return tuple(sorted({field for _, field, _, _ in Formatter().parse(template) if field}))


def table(language: str) -> dict[str, str]:
    """Raw template table for one language; the tests need the text before formatting."""
    return dict(i18n._TRANSLATIONS[language])


def base() -> AnalysisData:
    return replace(
        make_analysis(),
        analyzed_at=datetime(2026, 7, 16, 12, 30, tzinfo=timezone.utc),
        system=SystemInfo("Windows 11", "11", "10.0.26100", "AMD64", "Test CPU"),
        disk=DiskInfo("C:\\", 512 * GIB, 412 * GIB, 100 * GIB, 80.0, "NTFS", "SSD", True),
    )


def every_problem() -> AnalysisData:
    """Everything at once: the worst tier of every rule that can fire together."""
    return replace(
        base(),
        cpu=CPUInfo(6, 12, 97.0, (95.0, 99.0)),
        ram=RAMInfo(16 * GIB, GIB, 15 * GIB, 96.0, 8 * GIB, 7 * GIB, 95.0),
        disk=DiskInfo("C:\\", 512 * GIB, 510 * GIB, 2 * GIB, 99.6, "NTFS", "HDD", True),
        process_count=400,
        temp_size_bytes=30 * GIB,
        uptime_seconds=400 * 3600.0,
        startup_items=tuple(StartupItem(f"App {index}", "HKCU Run") for index in range(35)),
        battery=BatteryInfo(5.0, False, 600),
        top_processes=(
            ProcessInfo(1000, "hog.exe", 80.0, 6 * GIB, 40.0),
            ProcessInfo(1001, "quiet.exe", 1.0, GIB, 6.0),
        ),
        warnings=("Graphics information was unavailable.",),
    )


def nearly_full_disk() -> AnalysisData:
    """A drive too large to trip the free-bytes rule, but almost full by percentage."""
    total, free = 4 * TIB, 100 * GIB
    return replace(
        base(),
        disk=DiskInfo(
            "C:\\", total, total - free, free, (total - free) / total * 100, "NTFS", "SSD", True
        ),
    )


def mild_problems() -> AnalysisData:
    """The lower tier of the maintenance rules, where the softer advice lives."""
    return replace(base(), process_count=160, temp_size_bytes=2 * GIB, uptime_seconds=30 * 3600.0)


def mild_load() -> AnalysisData:
    """The mild tier of CPU, RAM and page-file usage.

    These three used to deduct points in silence, so their advice keys are new - and a key
    the coverage fixture never fires is a key no test proves translatable.
    """
    return replace(
        base(),
        cpu=CPUInfo(6, 12, 60.0, (58.0, 62.0)),
        ram=RAMInfo(16 * GIB, 5 * GIB, 11 * GIB, 72.0, 8 * GIB, 5 * GIB, 60.0),
    )


def shrinking_disk() -> AnalysisData:
    """The mild tier of the free-bytes rule: past 50 GB free, still short of the 20 GB one."""
    total, free = 512 * GIB, 30 * GIB
    return replace(
        base(),
        disk=DiskInfo(
            "C:\\", total, total - free, free, (total - free) / total * 100, "NTFS", "SSD", True
        ),
    )


def filling_disk() -> AnalysisData:
    """The mild tier of the percentage rule: roomy enough that free bytes stay quiet."""
    total, free = 1024 * GIB, 100 * GIB
    return replace(
        base(),
        disk=DiskInfo(
            "C:\\", total, total - free, free, (total - free) / total * 100, "NTFS", "SSD", True
        ),
    )


def every_state_problem() -> AnalysisData:
    """The v2.1 half of the vocabulary: what is durably wrong, not how busy the PC is.

    Protection off, a drive that reports a critical warning and almost no rated life left,
    a worn battery pack, and a user folder big enough to be worth naming.
    """
    return replace(
        base(),
        battery=BatteryInfo(
            percent=80.0,
            plugged_in=True,
            design_capacity_mwh=80_000,
            full_charge_capacity_mwh=36_000,  # 45% left: the severe tier of battery_worn.
            cycle_count=642,
            chemistry="LION",
        ),
        security=SecurityInfo(
            antivirus=STATE_BAD,
            antivirus_name="Windows Defender",
            firewall=STATE_BAD,
            secure_boot=STATE_BAD,
            reboot_pending=True,
            defender_last_scan=datetime(2026, 6, 1, 8, 15, tzinfo=timezone.utc),
            signature_age_days=45,
        ),
        drive_health=(
            DriveHealth(
                drive="C:\\",
                model="Test NVMe 2TB",
                bus_type="NVMe",
                media_type="SSD",
                percentage_used=95,
                temperature_celsius=61,
                power_on_hours=1,  # Singular on purpose: "1 hodina", never "1 hodín".
                data_written_bytes=180 * GIB,
                critical_warning=True,
                source="nvme",
            ),
            DriveHealth(
                drive="D:\\",
                model="Test SATA 1TB",
                bus_type="SATA",
                media_type="SSD",
                percentage_used=12,
                temperature_celsius=33,
                power_on_hours=12_345,
                data_written_bytes=40 * GIB,
                critical_warning=False,
                source="storage_predict_failure",
            ),
        ),
        folder_usage=(
            # The biggest folder is measured in full, so its advice quotes an exact size;
            # the smaller one was cut short, which is what puts "(partial scan)" in the table.
            FolderUsage("downloads", "Downloads", r"C:\Users\Test\Downloads", 62 * GIB, 12_004),
            FolderUsage("documents", "Documents", r"C:\Users\Test\Documents", 3 * GIB, 812, True),
            FolderUsage("onedrive", "OneDrive", r"C:\Users\Test\OneDrive"),
        ),
    )


def unreadable_protection() -> AnalysisData:
    """A PC whose Security Center never answered. Unknown must never render as "off"."""
    return replace(
        base(),
        security=SecurityInfo(
            antivirus=STATE_UNKNOWN,
            firewall=STATE_UNKNOWN,
            secure_boot=STATE_WEAK,
            details=(("security_center", "the Security Center did not answer"),),
        ),
        drive_health=(DriveHealth(drive="C:\\", model="Test NVMe 2TB"),),
        folder_usage=(FolderUsage("desktop", "Desktop", r"C:\Users\Test\Desktop"),),
    )


def coverage_snapshots() -> tuple[AnalysisData, ...]:
    """Snapshots whose union fires every deduction and every recommendation key."""
    return (
        every_problem(),
        every_state_problem(),
        unreadable_protection(),
        nearly_full_disk(),
        shrinking_disk(),
        filling_disk(),
        mild_problems(),
        mild_load(),
        base(),
    )


class LanguageTableTests(unittest.TestCase):
    def test_shipped_languages(self) -> None:
        self.assertEqual(LANGUAGES, ("en", "sk"))
        self.assertEqual(available_languages(), LANGUAGES)

    def test_both_languages_expose_identical_key_sets(self) -> None:
        english = set(translation_keys("en"))
        slovak = set(translation_keys("sk"))
        self.assertEqual(english ^ slovak, set(), "translation tables drifted apart")

    def test_tables_are_not_empty(self) -> None:
        self.assertGreater(len(translation_keys("en")), 100)

    def test_no_translation_is_blank(self) -> None:
        for language in LANGUAGES:
            for key, text in table(language).items():
                with self.subTest(language=language, key=key):
                    self.assertTrue(str(text).strip())

    def test_placeholders_match_across_languages(self) -> None:
        english, slovak = table("en"), table("sk")
        for key in sorted(english):
            with self.subTest(key=key):
                self.assertEqual(
                    placeholders(english[key]),
                    placeholders(slovak[key]),
                    f"placeholders differ for {key}",
                )

    def test_every_deduction_key_is_translated(self) -> None:
        for language in LANGUAGES:
            entries = table(language)
            for key in DEDUCTION_KEYS:
                with self.subTest(language=language, key=key):
                    self.assertIn(f"deduction.{key}", entries)

    def test_every_recommendation_key_is_translated(self) -> None:
        for language in LANGUAGES:
            entries = table(language)
            for key in RECOMMENDATION_KEYS:
                with self.subTest(language=language, key=key):
                    self.assertIn(f"recommendation.{key}", entries)

    def test_status_severity_and_category_keys_are_translated(self) -> None:
        groups = (("status", STATUS_KEYS), ("severity", SEVERITY_KEYS), ("category", CATEGORY_KEYS))
        for language in LANGUAGES:
            entries = table(language)
            for prefix, keys in groups:
                for key in keys:
                    with self.subTest(language=language, key=f"{prefix}.{key}"):
                        self.assertIn(f"{prefix}.{key}", entries)

    def test_slovak_is_actually_translated(self) -> None:
        english, slovak = table("en"), table("sk")
        shared = [key for key in english if english[key] == slovak[key]]
        # Some entries are identical on purpose (CPU, PID, Mbps); most must differ.
        self.assertLess(len(shared), len(english) // 3)


class TranslatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.translator = get_translator("sk")

    def test_known_key_is_translated(self) -> None:
        self.assertEqual(self.translator.t("field.yes"), "Áno")

    def test_call_is_an_alias_for_t(self) -> None:
        self.assertEqual(self.translator("field.no"), self.translator.t("field.no"))

    def test_default_is_ignored_for_a_known_key(self) -> None:
        self.assertEqual(self.translator.t("field.yes", "Yes"), "Áno")

    def test_missing_key_returns_the_default(self) -> None:
        self.assertEqual(self.translator.t("nope.missing", "Fallback"), "Fallback")

    def test_missing_key_without_a_default_returns_the_key(self) -> None:
        self.assertEqual(self.translator.t("nope.missing"), "nope.missing")

    def test_missing_keys_are_recorded_in_request_order(self) -> None:
        self.translator.t("nope.first", "a")
        self.translator.t("nope.second")
        self.translator.t("field.yes")
        self.translator.t("nope.first", "a")
        self.assertEqual(self.translator.missing_keys(), ("nope.first", "nope.second"))

    def test_a_fresh_translator_reports_no_missing_keys(self) -> None:
        self.assertEqual(get_translator("en").missing_keys(), ())

    def test_has_covers_the_english_fallback(self) -> None:
        self.assertTrue(self.translator.has("field.yes"))
        self.assertFalse(self.translator.has("nope.missing"))

    def test_parameters_are_substituted(self) -> None:
        self.assertEqual(self.translator.t("report.score_value", score=72), "72/100")

    def test_missing_parameter_does_not_raise(self) -> None:
        self.assertIsInstance(self.translator.t("report.score_value"), str)

    def test_unsupplied_optional_value_drops_its_parenthesis(self) -> None:
        text = get_translator("en").t("deduction.high_cpu")
        self.assertNotIn("(", text)
        self.assertNotIn("N/A", text)

    def test_bad_format_parameter_does_not_raise(self) -> None:
        # A format spec the supplied value cannot satisfy must degrade, never explode.
        self.assertEqual(
            self.translator.t("nope.broken", "Value: {number:d}", number="not-a-number"),
            "Value: {number:d}",
        )

    def test_unbalanced_braces_do_not_raise(self) -> None:
        self.assertEqual(self.translator.t("nope.unbalanced", "Broken {"), "Broken {")

    def test_language_can_be_switched_in_place(self) -> None:
        translator = get_translator("en")
        self.assertEqual(translator.t("field.yes"), "Yes")
        translator.language = "sk"
        self.assertEqual(translator.language, "sk")
        self.assertEqual(translator.t("field.yes"), "Áno")

    def test_unknown_language_falls_back_to_english(self) -> None:
        translator = Translator("klingon")
        self.assertEqual(translator.language, "en")
        self.assertEqual(translator.t("field.yes"), "Yes")

    def test_language_labels_are_self_referencing(self) -> None:
        self.assertEqual(language_label("en"), "English")
        self.assertEqual(language_label("sk"), "Slovenčina")

    def test_language_label_of_an_unknown_code_falls_back(self) -> None:
        self.assertEqual(language_label("klingon"), "English")


class LanguageDetectionTests(unittest.TestCase):
    def environment(self, **values: str) -> dict[str, str]:
        cleared = {name: "" for name in LOCALE_VARIABLES}
        cleared.update(values)
        return cleared

    def test_env_override_selects_slovak(self) -> None:
        with patch.dict(os.environ, self.environment(APOLIAK_LANG="sk")):
            self.assertEqual(detect_language(), "sk")

    def test_env_override_accepts_a_full_locale(self) -> None:
        with patch.dict(os.environ, self.environment(APOLIAK_LANG="sk_SK.UTF-8")):
            self.assertEqual(detect_language(), "sk")

    def test_env_override_selects_english(self) -> None:
        with patch.dict(os.environ, self.environment(APOLIAK_LANG="en-GB")):
            self.assertEqual(detect_language(), "en")

    def test_env_override_wins_over_the_locale_variables(self) -> None:
        with patch.dict(os.environ, self.environment(APOLIAK_LANG="en", LANG="sk_SK")):
            self.assertEqual(detect_language(), "en")

    def test_detection_always_returns_a_shipped_language(self) -> None:
        for value in ("", "klingon", "de_DE", "sk"):
            with self.subTest(value=value):
                with patch.dict(os.environ, self.environment(APOLIAK_LANG=value)):
                    self.assertIn(detect_language(), LANGUAGES)

    def test_get_translator_without_a_language_detects_one(self) -> None:
        with patch.dict(os.environ, self.environment(APOLIAK_LANG="sk")):
            self.assertEqual(get_translator().language, "sk")


class RenderedKeyCoverageTests(unittest.TestCase):
    """End-to-end: every key the engine can emit renders as real Slovak text."""

    def setUp(self) -> None:
        self.snapshots = coverage_snapshots()
        self.runs = [
            (data, generate_recommendations(data), calculate_health_details(data))
            for data in self.snapshots
        ]

    def test_the_fixture_fires_every_deduction_key(self) -> None:
        fired = {item.key for _, _, assessment in self.runs for item in assessment.deductions}
        self.assertEqual(fired, set(DEDUCTION_KEYS))

    def test_the_fixture_fires_every_recommendation_key(self) -> None:
        fired = {item.key for _, advice, _ in self.runs for item in advice}
        self.assertEqual(fired, set(RECOMMENDATION_KEYS))

    def test_no_raw_translation_key_leaks_into_a_rendered_report(self) -> None:
        # Both shipped languages, plus the "no translator" path that renders English from
        # the same catalogue: a key that leaks in one of them leaks in a real report.
        translators = [("sk", get_translator("sk")), ("en", get_translator("en")), ("-", None)]
        for language, translator in translators:
            for index, (data, advice, assessment) in enumerate(self.runs):
                for fmt in ("text", "markdown", "html"):
                    content = exporters.render(
                        fmt, data, advice, assessment, translator=translator
                    )
                    for prefix in KEY_PREFIXES:
                        with self.subTest(
                            language=language, snapshot=index, fmt=fmt, prefix=prefix
                        ):
                            self.assertNotIn(prefix, content)

    def test_a_render_reports_no_missing_translation_keys_in_either_language(self) -> None:
        for language in LANGUAGES:
            translator = get_translator(language)
            for data, advice, assessment in self.runs:
                for fmt in exporters.FORMATS:
                    exporters.render(fmt, data, advice, assessment, translator=translator)
            with self.subTest(language=language):
                self.assertEqual(translator.missing_keys(), ())

    def test_every_deduction_and_recommendation_is_rendered_in_slovak(self) -> None:
        translator = get_translator("sk")
        english = get_translator("en")
        for data, advice, assessment in self.runs:
            content = exporters.render("text", data, advice, assessment, translator=translator)
            for item in assessment.deductions:
                with self.subTest(key=f"deduction.{item.key}"):
                    self.assertNotIn(item.reason, content)
                    self.assertIn(translator.t(f"deduction.{item.key}", **item.values), content)
            for item in advice:
                with self.subTest(key=f"recommendation.{item.key}"):
                    self.assertIn(
                        translator.t(f"recommendation.{item.key}", **item.values), content
                    )
                    self.assertNotEqual(
                        translator.t(f"recommendation.{item.key}"),
                        english.t(f"recommendation.{item.key}"),
                    )


class SlovakStateSectionTests(unittest.TestCase):
    """The three v2.1 sections have to be Slovak in a Slovak report, headings included.

    A section added late is exactly the section most likely to reach a user in English: the
    engine keys are swept above, but a heading is a literal at the call site and nothing
    forces a translation to exist for it beyond this test and the orphan sweep.
    """

    #: (catalogue key, the English wording that must not survive into a Slovak render).
    HEADINGS: tuple[tuple[str, str], ...] = (
        ("gui.card.security", "Security"),
        ("gui.section.drive_health", "Drive health"),
        ("gui.section.folders", "Biggest folders"),
    )

    def setUp(self) -> None:
        self.data = every_state_problem()
        self.advice = generate_recommendations(self.data)
        self.assessment = calculate_health_details(self.data)
        self.slovak = get_translator("sk")
        self.english = get_translator("en")

    def render(self, fmt: str, translator: object) -> str:
        return exporters.render(
            fmt,
            self.data,
            self.advice,
            self.assessment,
            translator=translator,  # type: ignore[arg-type]
        )

    def test_the_snapshot_really_carries_all_three_sections(self) -> None:
        # Otherwise the assertions below would pass on a report that has none of them.
        self.assertIsNotNone(self.data.security)
        self.assertTrue(self.data.drive_health)
        self.assertTrue(self.data.folder_usage)

    def test_each_heading_is_translated_rather_than_left_in_english(self) -> None:
        for key, wording in self.HEADINGS:
            with self.subTest(key=key):
                self.assertEqual(self.english.t(key), wording)
                self.assertNotEqual(self.slovak.t(key), wording)

    def test_a_slovak_report_shows_the_slovak_headings_in_every_document_format(self) -> None:
        for fmt in ("markdown", "html"):
            content = self.render(fmt, self.slovak)
            for key, wording in self.HEADINGS:
                with self.subTest(fmt=fmt, key=key):
                    self.assertIn(self.slovak.t(key), content)

    def test_the_state_field_labels_reach_the_report_from_the_catalogue(self) -> None:
        content = self.render("text", self.slovak)
        # "Secure Boot" is a product name and stays as it is in both languages; the labels
        # around it are ordinary words and must be translated.
        for key in ("field.antivirus", "field.firewall", "field.secure_boot"):
            with self.subTest(key=key):
                self.assertIn(self.slovak.t(key), content)
        for key in ("field.firewall", "field.battery_health"):
            with self.subTest(translated=key):
                self.assertNotEqual(self.slovak.t(key), self.english.t(key))


class PluralFormTests(unittest.TestCase):
    """Slovak declines a counted noun in three groups; "3 bodov" is simply wrong.

    1 takes "bod", 2 to 4 take "body", and 0 as well as everything from 5 upwards take
    "bodov". English only needs two forms. The choice is a property of the language, so it
    lives in the catalogue and not in whichever renderer happens to print the number.
    """

    SLOVAK_POINTS = ((0, "bodov"), (1, "bod"), (2, "body"), (3, "body"), (4, "body"),
                     (5, "bodov"), (11, "bodov"), (21, "bodov"), (100, "bodov"))
    ENGLISH_POINTS = ((0, "points"), (1, "point"), (2, "points"), (3, "points"), (5, "points"))

    def test_slovak_points_decline_with_the_count(self) -> None:
        translator = get_translator("sk")
        for count, expected in self.SLOVAK_POINTS:
            with self.subTest(count=count):
                self.assertEqual(translator.t_plural("report.points", count), expected)

    def test_english_points_only_distinguish_one_from_the_rest(self) -> None:
        translator = get_translator("en")
        for count, expected in self.ENGLISH_POINTS:
            with self.subTest(count=count):
                self.assertEqual(translator.t_plural("report.points", count), expected)

    def test_the_grammatical_number_itself(self) -> None:
        for count, expected in ((0, "many"), (1, "one"), (2, "few"), (4, "few"), (5, "many")):
            with self.subTest(count=count, language="sk"):
                self.assertEqual(i18n.plural_form(count, "sk"), expected)
        for count in (0, 2, 3, 4, 5):  # English has no "few" group at all.
            with self.subTest(count=count, language="en"):
                self.assertEqual(i18n.plural_form(count, "en"), "many")
        self.assertEqual(i18n.plural_form(1, "en"), "one")

    def test_a_number_that_is_not_whole_is_never_singular(self) -> None:
        for count in (1.5, "many", None, float("nan"), float("inf")):
            with self.subTest(count=count):
                self.assertEqual(i18n.plural_form(count, "sk"), "many")

    def test_every_plural_key_ships_all_three_forms_in_both_languages(self) -> None:
        bases = {key.rsplit(".", 1)[0] for key in translation_keys("en") if key.endswith(".one")}
        self.assertTrue(bases)
        for language in LANGUAGES:
            keys = set(translation_keys(language))
            for base in sorted(bases):
                for form in i18n.PLURAL_FORMS:
                    with self.subTest(language=language, key=f"{base}.{form}"):
                        self.assertIn(f"{base}.{form}", keys)

    def test_slovak_really_uses_three_distinct_forms_somewhere(self) -> None:
        translator = get_translator("sk")
        forms = {translator.t_plural("report.points", count) for count in (1, 3, 5)}
        self.assertEqual(len(forms), 3)


class PluralRenderingTests(unittest.TestCase):
    """The renderers have to ask the translator, not append an "s" of their own."""

    POINTS = (1, 3, 5)

    def setUp(self) -> None:
        self.data = base()
        # A hand-built assessment is the only way to land on 1, 3 and 5 points at once: the
        # score table has no one-point row, and the plural rule has to hold for every count.
        self.assessment = HealthAssessment(
            score=91,
            status="Excellent",
            deductions=tuple(
                ScoreDeduction(
                    key=key,
                    points=points,
                    reason=f"{key} fired",
                    category=CATEGORY_CPU,
                    severity="info",
                    params=(("value", "42%"),),
                )
                for key, points in zip(("high_cpu", "high_ram", "high_swap"), self.POINTS)
            ),
            data_complete=True,
            categories=(),
        )

    def render(self, fmt: str, language: str) -> str:
        return exporters.render(
            fmt, self.data, [], self.assessment, translator=get_translator(language)
        )

    def test_the_text_report_declines_the_noun_in_slovak(self) -> None:
        content = self.render("text", "sk")
        for fragment in ("1 bod:", "3 body:", "5 bodov:"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, content)
        self.assertNotIn("1 bodov", content)
        self.assertNotIn("3 bodov", content)

    def test_the_text_report_uses_the_english_pair_in_english(self) -> None:
        content = self.render("text", "en")
        for fragment in ("1 point:", "3 points:", "5 points:"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, content)

    def test_the_html_report_declines_the_noun_too(self) -> None:
        slovak = self.render("html", "sk")
        for fragment in ("1 bod", "3 body", "5 bodov"):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, slovak)
        english = self.render("html", "en")
        self.assertIn("1 point", english)
        self.assertIn("3 points", english)

    def test_no_renderer_invents_a_form_for_a_language_it_does_not_know(self) -> None:
        # A translator that predates t_plural() must still produce readable English.
        class OldTranslator:
            language = "en"

            def t(self, key: str, default: str | None = None, **params: object) -> str:
                text = default if default is not None else key
                try:
                    return text.format(**params)
                except Exception:
                    return text

        content = exporters.render(
            "text", self.data, [], self.assessment, translator=OldTranslator()
        )
        self.assertIn("1 point:", content)
        self.assertIn("3 points:", content)


class CatalogueWiringTests(unittest.TestCase):
    """Every shipped key is asked for somewhere, and everything asked for is shipped.

    29 keys shipped in v2.0 with no call site at all - history column headers, a window
    title, a clipboard message, and a tail of strings for interface elements that were never
    built. A shipped key nobody requests is a promise the product does not keep, so this
    scans the whole application rather than main.py alone, and both allowances are empty.

    A key can be requested in three shapes, and all three are resolved here:

    * a literal, ``t("field.os", "System")``;
    * a dynamic family, ``t(f"deduction.{key}")`` - resolved against the very table the
      producer builds those keys from, so the net can never be widened by accident;
    * a plural family, ``t_plural("report.points", count)`` - which asks for
      ``report.points.one``, ``.few`` or ``.many`` and never for the base itself.

    src/i18n.py is deliberately not scanned: it is where the keys are declared, so counting
    it as a call site would let every key vouch for itself.
    """

    #: Keys the code asks for that no table ships. A gap degrades to the English default, so
    #: one line of a Slovak run would silently print in English.
    KNOWN_UNSHIPPED: frozenset[str] = frozenset()

    #: Shipped keys with no call site. Nothing may sit here: a key that truly cannot be
    #: resolved statically belongs to one of the documented families below instead.
    KNOWN_UNUSED: frozenset[str] = frozenset()

    #: Every namespace the catalogue uses. Written out so a new one cannot slip past the scan.
    NAMESPACES = (
        "cli", "gui", "report", "field", "section", "status",
        "severity", "category", "deduction", "recommendation", "progress",
    )

    _NAMES = "|".join(NAMESPACES)
    #: ``"field.os"`` or ``'field.os'`` - a key written out in full. The back-reference keeps
    #: the two quote styles apart; both are used in the code base.
    LITERAL_KEY = re.compile(rf'(["\'])((?:{_NAMES})\.[a-z0-9_.]*[a-z0-9_])\1')
    #: ``f"deduction.{item.key}"`` - a family whose members are computed at runtime.
    DYNAMIC_FSTRING = re.compile(rf'["\']((?:{_NAMES})\.(?:[a-z0-9_]+\.)*)\{{')
    #: ``"status." + slug`` - the same thing built by concatenation.
    DYNAMIC_CONCAT = re.compile(rf'(["\'])((?:{_NAMES})\.(?:[a-z0-9_]+\.)*)\1')

    #: The catalogue itself. Excluded from the scan for the obvious reason: every key appears
    #: there as a literal, so counting it as a call site would make the sweep below vacuous.
    CATALOGUE = "i18n.py"

    #: The window's own view keys and the export formats it offers. They are literals here so
    #: that the sweep does not need a Tk toolkit to run; a separate test, skipped when the GUI
    #: cannot be imported, holds them against the tables gui.py really builds its keys from.
    GUI_VIEWS = frozenset(
        {"overview", "processes", "storage", "security", "system", "history"}
    )

    @classmethod
    def setUpClass(cls) -> None:
        root = Path(main.__file__).resolve().parent
        sources = [root / "main.py", root / "gui.py", *sorted((root / "src").glob("*.py"))]
        cls.sources = [
            path for path in sources if path.exists() and path.name != cls.CATALOGUE
        ]
        text = "\n".join(path.read_text(encoding="utf-8") for path in cls.sources)
        cls.literal = frozenset(match.group(2) for match in cls.LITERAL_KEY.finditer(text))
        cls.dynamic = frozenset(
            match.group(1) for match in cls.DYNAMIC_FSTRING.finditer(text)
        ) | frozenset(match.group(2) for match in cls.DYNAMIC_CONCAT.finditer(text))
        cls.shipped = {language: frozenset(translation_keys(language)) for language in LANGUAGES}

    def families(self) -> dict[str, set[str]]:
        """Dynamic key families, each enumerated from the table that generates it."""
        from src.analyzer import PROGRESS_LABELS
        from src.health_score import DEDUCTION_TEMPLATES, STATUS_BANDS
        from src.models import SEVERITY_ORDER
        from src.recommendations import RECOMMENDATION_TEMPLATES

        return {
            "deduction.": set(DEDUCTION_TEMPLATES),
            "recommendation.": set(RECOMMENDATION_TEMPLATES),
            "progress.": set(PROGRESS_LABELS),
            "severity.": set(SEVERITY_ORDER),
            "category.": set(CATEGORY_KEYS),
            "status.": {status.casefold().replace(" ", "_") for _, status in STATUS_BANDS},
            "gui.nav.": set(self.GUI_VIEWS),
            "gui.format.": set(exporters.FORMATS),
            "gui.filetype.": set(exporters.FORMATS),
            # The window looks its card titles up by key; the exporters name the very same
            # cards literally, so the literals are the family. Nothing new is excused: a card
            # key only the window asks for still has to justify itself as an orphan.
            "gui.card.": {
                key.split(".", 2)[2] for key in self.literal if key.startswith("gui.card.")
            },
        }

    def plural_bases(self) -> set[str]:
        """Base keys that only ever appear with a grammatical-number suffix."""
        return {
            key.rsplit(".", 1)[0]
            for key in self.shipped["en"]
            if key.rsplit(".", 1)[-1] in i18n.PLURAL_FORMS
        }

    def resolved(self) -> set[str]:
        """Every key some call site can actually ask for."""
        keys = set(self.literal)
        for prefix, members in self.families().items():
            keys |= {prefix + member for member in members}
        for base in self.plural_bases():
            if base in self.literal:  # The renderer asks for base + grammatical number.
                keys |= {f"{base}.{form}" for form in i18n.PLURAL_FORMS}
        return keys

    def test_the_scan_reads_the_whole_application(self) -> None:
        # Guards the scan itself: a rename that breaks the regexes must not quietly pass the
        # two assertions that matter.
        names = {path.name for path in self.sources}
        self.assertIn("main.py", names)
        self.assertIn("gui.py", names)
        self.assertIn("report.py", names)
        self.assertGreater(len(self.literal), 200)
        for namespace in self.NAMESPACES:
            with self.subTest(namespace=namespace):
                found = {key for key in self.literal if key.startswith(f"{namespace}.")}
                # Six namespaces are only ever built dynamically, and have no literal at all.
                self.assertTrue(found or f"{namespace}." in self.dynamic)

    def test_every_dynamic_namespace_has_an_enumerated_family(self) -> None:
        # Without this, adding f"newthing.{x}" would silently excuse every "newthing.*" key
        # from the orphan check below.
        self.assertEqual(self.dynamic, frozenset(self.families()))

    def test_no_catalogue_key_is_shipped_without_a_call_site(self) -> None:
        # The whole point of P5, as an absolute: not "few orphans" and not "no new orphans",
        # but none. A key with no call site is a promise the product does not keep.
        resolved = self.resolved()
        for language in LANGUAGES:
            orphans = self.shipped[language] - resolved - self.KNOWN_UNUSED
            with self.subTest(language=language):
                self.assertEqual(orphans, set(), "a shipped key has no call site")

    def test_every_key_the_code_asks_for_exists_in_both_languages(self) -> None:
        # A plural base is never requested on its own; its three forms are checked below.
        requested = self.literal - self.plural_bases()
        for language in LANGUAGES:
            missing = requested - self.shipped[language] - self.KNOWN_UNSHIPPED
            with self.subTest(language=language):
                self.assertEqual(missing, frozenset(), "the code asks for a key nobody ships")

    def test_every_plural_base_the_code_asks_for_ships_all_three_forms(self) -> None:
        bases = self.literal & self.plural_bases()
        self.assertTrue(bases)
        for language in LANGUAGES:
            for base in sorted(bases):
                for form in i18n.PLURAL_FORMS:
                    with self.subTest(language=language, key=f"{base}.{form}"):
                        self.assertIn(f"{base}.{form}", self.shipped[language])

    def test_every_member_of_every_dynamic_family_is_shipped(self) -> None:
        for language in LANGUAGES:
            for prefix, members in self.families().items():
                for member in sorted(members):
                    with self.subTest(language=language, key=prefix + member):
                        self.assertIn(prefix + member, self.shipped[language])

    def test_the_gui_families_match_the_tables_the_window_builds_them_from(self) -> None:
        # GUI_VIEWS is a literal so the sweep runs without a Tk toolkit; here it is held
        # against gui.py itself, so the two can never drift apart unnoticed.
        try:
            import gui
        except BaseException as error:  # noqa: BLE001 - any import problem means "no GUI here"
            self.skipTest(f"the GUI cannot be imported here ({type(error).__name__}: {error})")
        self.assertEqual(set(gui.VIEW_DEFAULT_LABELS), set(self.GUI_VIEWS))
        self.assertEqual({spec[0] for spec in gui.FORMAT_SPECS}, set(exporters.FORMATS))

    def test_both_allowances_stay_empty(self) -> None:
        # Stated on its own so that quietly parking a key in an allowance is a visible edit
        # rather than a passing test.
        self.assertEqual(self.KNOWN_UNUSED, frozenset())
        self.assertEqual(self.KNOWN_UNSHIPPED, frozenset())

    #: The only console string that is deliberately identical in both languages: it is a
    #: bare "{message}" passthrough for the progress line.
    SAME_IN_BOTH_LANGUAGES = frozenset({"cli.msg.progress"})

    def test_the_console_keys_are_translated_rather_than_copied(self) -> None:
        english, slovak = get_translator("en"), get_translator("sk")
        wired = {key for key in self.literal if key.startswith("cli.")} - self.KNOWN_UNSHIPPED
        self.assertGreater(len(wired), 20)
        identical = {key for key in wired if english.t(key) == slovak.t(key)}
        self.assertEqual(identical, self.SAME_IN_BOTH_LANGUAGES)

    def test_the_newly_wired_keys_really_are_requested(self) -> None:
        # The named survivors of the orphan sweep: they were kept because they had a place to
        # go, so the test says where. A future edit that drops one of these call sites again
        # fails here instead of quietly reintroducing a dead key.
        wired = {
            "report.at_least": "src/report.py",
            "report.temp_truncated": "src/report.py",
            "cli.history.column.date": "main.py",
            "cli.history.column.score": "main.py",
            "cli.history.column.status": "main.py",
            "cli.history.column.cpu": "main.py",
            "cli.history.column.ram": "main.py",
            "cli.history.column.free_disk": "main.py",
            "gui.msg.copied": "gui.py",
            "gui.title": "gui.py",
        }
        root = Path(main.__file__).resolve().parent
        for key, where in wired.items():
            with self.subTest(key=key):
                self.assertIn(key, self.literal)
                self.assertIn(key, self.shipped["sk"])
                owner = root.joinpath(*where.split("/"))
                source = owner.read_text(encoding="utf-8")
                # Quoted and outside a comment: a key named in prose is not a call site.
                calls = [
                    line
                    for line in source.splitlines()
                    if f'"{key}"' in line and not line.lstrip().startswith(("#", "#:"))
                ]
                self.assertTrue(calls, f"{key} has no call site in {where}")

    def test_the_deleted_keys_are_gone_from_both_tables(self) -> None:
        # The other half of the sweep: 19 keys described interface elements that do not
        # exist. Shipping one again without a call site would fail the orphan test, but this
        # names them, so the deletion cannot be undone by a merge without anyone noticing.
        deleted = (
            "cli.msg.analyzing",
            "cli.msg.readonly",
            "cli.msg.invalid_language",
            "section.categories",
            "gui.label.data_complete",
            "gui.label.status",
            "gui.button.cancel",
            "gui.button.close",
            "gui.theme.system",
            "report.language",
            "report.schema_version",
            "field.command",
            "field.count",
            "field.driver_date",
            "field.gpu",
            "field.recommendation",
            "field.speed",
            "field.state",
            "field.warning",
        )
        for language in LANGUAGES:
            for key in deleted:
                with self.subTest(language=language, key=key):
                    self.assertNotIn(key, self.shipped[language])
                    self.assertNotIn(key, self.literal)


if __name__ == "__main__":
    unittest.main()
