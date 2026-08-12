"""Tests for the frozen data contract in src/models.py.

Two derived properties live here rather than in a collector, and both exist so the project
has exactly one definition of a figure every layer quotes: how worn a battery is, and how
much rated life a drive has left. A second definition anywhere would let the score and the
report disagree about the same PC, so they are asserted on their own - including every path
where the answer has to be "unknown" instead of a number.
"""

from __future__ import annotations

import unittest
from dataclasses import FrozenInstanceError, fields
from datetime import datetime, timezone

from src import models
from src.models import (
    CATEGORY_SECURITY,
    SCHEMA_VERSION,
    SEVERITY_ORDER,
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
    RAMInfo,
    Recommendation,
    SecurityInfo,
    SystemInfo,
    severity_rank,
)


def battery(design: int | None, full: int | None) -> BatteryInfo:
    return BatteryInfo(
        percent=80.0,
        plugged_in=True,
        design_capacity_mwh=design,
        full_charge_capacity_mwh=full,
    )


class SchemaTests(unittest.TestCase):
    def test_the_schema_version_is_the_one_this_release_publishes(self) -> None:
        self.assertEqual(SCHEMA_VERSION, "2.1")

    def test_a_snapshot_carries_the_schema_version_by_default(self) -> None:
        data = AnalysisData(
            analyzed_at=datetime(2026, 7, 16, tzinfo=timezone.utc),
            system=SystemInfo("Windows 11", "11", "10.0.26100", "AMD64", "Test CPU"),
            cpu=CPUInfo(None, None, None),
            ram=RAMInfo(None, None, None, None),
            disk=DiskInfo("C:\\", None, None, None, None),
            process_count=None,
            temp_path="C:\\Temp",
            temp_size_bytes=None,
            uptime_seconds=None,
        )
        self.assertEqual(data.schema_version, SCHEMA_VERSION)

    def test_the_v2_1_fields_default_to_nobody_looked(self) -> None:
        # An absent field must never read as a healthy measurement, so the defaults are
        # "no record" and "no rows" rather than an empty verdict.
        defaults = {field.name: field.default for field in fields(AnalysisData)}
        self.assertIsNone(defaults["security"])
        self.assertEqual(defaults["drive_health"], ())
        self.assertEqual(defaults["folder_usage"], ())

    def test_the_security_category_key_is_part_of_the_vocabulary(self) -> None:
        self.assertEqual(CATEGORY_SECURITY, "security")

    def test_the_state_words_are_the_four_the_project_agreed_on(self) -> None:
        self.assertEqual(
            (STATE_GOOD, STATE_WEAK, STATE_BAD, STATE_UNKNOWN),
            ("good", "weak", "bad", "unknown"),
        )

    def test_severity_rank_orders_least_to_most_urgent(self) -> None:
        self.assertEqual(SEVERITY_ORDER, ("info", "warning", "critical"))
        ranks = [severity_rank(name) for name in SEVERITY_ORDER]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(severity_rank("nonsense"), -1)  # Unknown sorts lowest, deterministically.


class BatteryHealthTests(unittest.TestCase):
    """``health_percent`` is the one definition of battery wear in the project."""

    def test_a_pack_that_still_holds_its_design_capacity_is_at_100(self) -> None:
        self.assertEqual(battery(80_000, 80_000).health_percent, 100.0)

    def test_wear_is_the_share_of_the_original_capacity_that_is_left(self) -> None:
        for design, full, expected in (
            (80_000, 68_000, 85.0),
            (99_000, 74_250, 75.0),
            (100_000, 45_000, 45.0),
            (50_000, 1_000, 2.0),
        ):
            with self.subTest(design=design, full=full):
                self.assertAlmostEqual(battery(design, full).health_percent, expected)

    def test_a_missing_figure_leaves_the_wear_unknown(self) -> None:
        # Never estimated from the charge level, and never assumed to be 100%.
        for design, full in ((None, 68_000), (80_000, None), (None, None)):
            with self.subTest(design=design, full=full):
                self.assertIsNone(battery(design, full).health_percent)

    def test_a_design_capacity_of_zero_is_unknown_rather_than_a_division_by_zero(self) -> None:
        for design in (0, -1, -80_000):
            with self.subTest(design=design):
                self.assertIsNone(battery(design, 68_000).health_percent)

    def test_a_pack_that_reports_nothing_at_all_is_unknown(self) -> None:
        self.assertIsNone(BatteryInfo(percent=55.0, plugged_in=False).health_percent)

    def test_a_full_charge_of_zero_is_a_real_reading_of_nothing_left(self) -> None:
        self.assertEqual(battery(80_000, 0).health_percent, 0.0)

    def test_a_pack_charging_past_its_rating_is_clamped_to_100(self) -> None:
        # New packs regularly report a full charge above the design capacity; "104% of its
        # original capacity" would read as a fault rather than as a healthy battery.
        self.assertEqual(battery(80_000, 83_000).health_percent, 100.0)

    def test_the_wear_is_never_negative(self) -> None:
        self.assertEqual(battery(80_000, -5_000).health_percent, 0.0)


class DriveLifeTests(unittest.TestCase):
    """``life_left_percent`` is the drive's own endurance figure, inverted once."""

    def test_the_life_left_is_the_complement_of_the_wear(self) -> None:
        for used, expected in ((0, 100), (6, 94), (50, 50), (94, 6), (100, 0)):
            with self.subTest(percentage_used=used):
                drive = DriveHealth("C:\\", percentage_used=used)
                self.assertEqual(drive.life_left_percent, expected)

    def test_a_drive_that_reported_no_wear_figure_is_unknown(self) -> None:
        self.assertIsNone(DriveHealth("C:\\").life_left_percent)
        self.assertIsNone(DriveHealth("C:\\", model="Test SSD").life_left_percent)

    def test_a_drive_past_its_rated_endurance_never_reports_a_negative_life(self) -> None:
        for used in (101, 150, 255):
            with self.subTest(percentage_used=used):
                self.assertEqual(DriveHealth("C:\\", percentage_used=used).life_left_percent, 0)

    def test_the_answer_is_a_whole_number(self) -> None:
        value = DriveHealth("C:\\", percentage_used=6).life_left_percent
        self.assertIsInstance(value, int)

    def test_zero_used_is_a_measurement_not_a_missing_one(self) -> None:
        # The difference the whole project turns on: 0% used is a new drive, None is silence.
        self.assertEqual(DriveHealth("C:\\", percentage_used=0).life_left_percent, 100)
        self.assertIsNone(DriveHealth("C:\\", percentage_used=None).life_left_percent)


class SecurityRecordTests(unittest.TestCase):
    def test_an_untouched_record_knows_nothing_and_claims_nothing(self) -> None:
        state = SecurityInfo()
        self.assertEqual(state.antivirus, STATE_UNKNOWN)
        self.assertEqual(state.firewall, STATE_UNKNOWN)
        self.assertEqual(state.secure_boot, STATE_UNKNOWN)
        self.assertIsNone(state.reboot_pending)
        self.assertIsNone(state.antivirus_name)
        self.assertIsNone(state.defender_last_scan)
        self.assertIsNone(state.signature_age_days)
        self.assertEqual(state.details, ())

    def test_details_are_pairs_of_strings(self) -> None:
        state = SecurityInfo(details=(("firewall_profiles_off", "Public"),))
        self.assertEqual(dict(state.details)["firewall_profiles_off"], "Public")


class FolderUsageRecordTests(unittest.TestCase):
    def test_a_folder_that_was_never_measured_carries_no_size(self) -> None:
        folder = FolderUsage("downloads", "Downloads", r"C:\Users\Test\Downloads")
        self.assertIsNone(folder.size_bytes)
        self.assertIsNone(folder.file_count)
        self.assertFalse(folder.truncated)


class RecommendationTests(unittest.TestCase):
    def test_advice_carries_no_settings_page_unless_one_is_given(self) -> None:
        self.assertIsNone(Recommendation(key="all_good", text="Nothing to do.").action_uri)

    def test_a_settings_page_travels_with_the_advice(self) -> None:
        advice = Recommendation(
            key="antivirus_off", text="Turn it on.", action_uri="ms-settings:windowsdefender"
        )
        self.assertEqual(advice.action_uri, "ms-settings:windowsdefender")

    def test_v1_call_sites_that_printed_the_advice_still_work(self) -> None:
        advice = Recommendation(key="all_good", text="Nothing to do.")
        self.assertEqual(str(advice), "Nothing to do.")


class ImmutabilityTests(unittest.TestCase):
    """Every model is frozen: a snapshot is a record of one moment, not a working copy."""

    def test_the_v2_1_models_cannot_be_edited_after_the_fact(self) -> None:
        cases = (
            (SecurityInfo(), "antivirus", STATE_BAD),
            (DriveHealth("C:\\"), "percentage_used", 90),
            (FolderUsage("downloads", "Downloads", "C:\\"), "size_bytes", 1),
            (BatteryInfo(50.0, True), "percent", 10.0),
        )
        for record, field, value in cases:
            with self.subTest(model=type(record).__name__):
                with self.assertRaises(FrozenInstanceError):
                    setattr(record, field, value)

    def test_every_model_in_the_module_is_frozen(self) -> None:
        # A mutable model would let one consumer change what the next one reads.
        for name in dir(models):
            candidate = getattr(models, name)
            parameters = getattr(candidate, "__dataclass_params__", None)
            if parameters is None:
                continue
            with self.subTest(model=name):
                self.assertTrue(parameters.frozen)


if __name__ == "__main__":
    unittest.main()
