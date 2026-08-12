"""Tests for the graded, transparent health score in src/health_score.py.

The score is a published table, so the tests read like the table: every tier is checked at
its exact threshold (must not fire) and one step past it (must fire, with the exact points).
The six v1.0 anchors are asserted separately, because those numbers were promised in the
README and must survive the v2.0 rewrite unchanged.
"""

from __future__ import annotations

import unittest
from dataclasses import replace

from src.health_score import (
    CATEGORY_LABELS,
    DEDUCTION_TEMPLATES,
    LOWER_BOUND_PARAM,
    METRICS,
    MIN_MEANINGFUL_SWAP_BYTES,
    SCORE_RULES,
    STATE_LEVELS,
    STATUS_BANDS,
    calculate_health_details,
    calculate_health_score,
    failing_drive,
    get_score_status,
    most_worn_drive,
    required_values_present,
    score_rules,
    state_level,
)
from src.models import (
    CATEGORY_CPU,
    CATEGORY_MAINTENANCE,
    CATEGORY_MEMORY,
    CATEGORY_POWER,
    CATEGORY_SECURITY,
    CATEGORY_STORAGE,
    SEVERITY_ORDER,
    STATE_BAD,
    STATE_GOOD,
    STATE_UNKNOWN,
    STATE_WEAK,
    AnalysisData,
    HealthAssessment,
    severity_rank,
)
from src.utils import GIB
from tests.helpers import (
    make_analysis,
    make_drive,
    make_security,
    silent_drive,
    unreadable_security,
)


def worn_drive(life_left: int, drive: str = "C:\\", **overrides: object) -> object:
    """A drive with exactly ``life_left`` percent of its rated endurance remaining."""
    used = 100 - int(life_left)
    return make_drive(drive, percentage_used=used, **overrides)  # type: ignore[arg-type]


def unreadable_security_with(**overrides: object) -> object:
    """A record where only the named verdicts were readable; everything else is unknown."""
    return replace(unreadable_security(), **overrides)  # type: ignore[arg-type]


HOUR = 3600.0

#: The complete key vocabulary the whole project agreed on for deductions.
DEDUCTION_KEYS = frozenset(
    {
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
        # v2.1: durable state rather than momentary load. secure_boot_off is deliberately
        # absent - it is advice only, because Secure Boot is off for legitimate reasons.
        "antivirus_off",
        "firewall_off",
        "stale_signatures",
        "reboot_pending",
        "drive_failing",
        "drive_worn",
        "battery_worn",
    }
)

#: Deductions whose sentence quotes no measurement, because there is no number to quote: the
#: finding is that a setting is off or a flag is raised, and the tier - not the wording -
#: carries how far off it is. They still have to name what they are about, which is why
#: drive_failing is here too: it quotes the drive, never a figure.
STATELESS_DEDUCTION_KEYS = frozenset(
    {"antivirus_off", "firewall_off", "stale_signatures", "reboot_pending", "drive_failing"}
)


def deduction(result: HealthAssessment, key: str) -> object | None:
    return next((item for item in result.deductions if item.key == key), None)


def points(data: AnalysisData, key: str) -> int:
    """Points charged for one key, or 0 when the rule did not fire."""
    found = deduction(calculate_health_details(data), key)
    return 0 if found is None else found.points  # type: ignore[union-attr]


class ScoreTableTests(unittest.TestCase):
    """The table itself has to stay well formed; every other test reads from it."""

    def test_every_rule_is_well_formed(self) -> None:
        for rule in SCORE_RULES:
            with self.subTest(key=rule.key, tier=rule.tier):
                self.assertIn(rule.key, DEDUCTION_KEYS)
                self.assertIn(rule.tier, ("mild", "standard", "high", "severe"))
                self.assertIn(rule.metric, METRICS)
                self.assertIn(rule.severity, SEVERITY_ORDER)
                self.assertGreater(rule.points, 0)
                self.assertIn(rule.key, DEDUCTION_TEMPLATES)
                self.assertTrue(rule.condition.strip())

    def test_every_key_has_exactly_one_standard_tier(self) -> None:
        for key in DEDUCTION_KEYS:
            standard = [rule for rule in SCORE_RULES if rule.key == key and rule.tier == "standard"]
            with self.subTest(key=key):
                self.assertEqual(len(standard), 1)

    def test_score_rules_are_grouped_by_key_and_ordered_mild_to_severe(self) -> None:
        rules = score_rules()
        self.assertEqual(len(rules), len(SCORE_RULES))
        self.assertEqual(set(rules), set(SCORE_RULES))

        seen: list[str] = []
        for key, group in _grouped(rules):
            seen.append(key)
            self.assertEqual([rule.points for rule in group], sorted(rule.points for rule in group))
        self.assertEqual(len(seen), len(set(seen)))  # A key is never split across groups.
        self.assertEqual(set(seen), DEDUCTION_KEYS)

    def test_score_rules_is_a_stable_snapshot(self) -> None:
        self.assertEqual(score_rules(), score_rules())

    def test_unknown_values_never_match_a_rule(self) -> None:
        for rule in SCORE_RULES:
            with self.subTest(key=rule.key, tier=rule.tier):
                self.assertFalse(rule.matches(None))

    def test_status_bands_are_descending_and_cover_zero(self) -> None:
        minimums = [minimum for minimum, _ in STATUS_BANDS]
        self.assertEqual(minimums, sorted(minimums, reverse=True))
        self.assertEqual(minimums[-1], 0)


def _grouped(rules: tuple[object, ...]) -> list[tuple[str, list[object]]]:
    groups: list[tuple[str, list[object]]] = []
    for rule in rules:
        key = rule.key  # type: ignore[attr-defined]
        if groups and groups[-1][0] == key:
            groups[-1][1].append(rule)
        else:
            groups.append((key, [rule]))
    return groups


class HealthyMachineTests(unittest.TestCase):
    def test_healthy_pc_scores_100(self) -> None:
        result = calculate_health_details(make_analysis())
        self.assertEqual(result.score, 100)
        self.assertEqual(result.status, "Excellent")
        self.assertEqual(result.deductions, ())
        self.assertEqual(result.total_deduction, 0)
        self.assertTrue(result.data_complete)

    def test_compatibility_api_returns_score_and_status(self) -> None:
        self.assertEqual(calculate_health_score(make_analysis()), (100, "Excellent"))


class V1AnchorTests(unittest.TestCase):
    """The six thresholds published for v1.0 are now the ``standard`` tier. Prove it."""

    #: key, snapshot exactly at the v1.0 threshold, snapshot one step past it,
    #: points charged at the threshold (the mild tier) and past it (the v1.0 penalty).
    ANCHORS: tuple[tuple[str, dict[str, object], dict[str, object], int, int], ...] = (
        ("high_cpu", {"cpu_percent": 70}, {"cpu_percent": 71}, 6, 15),
        ("high_ram", {"ram_percent": 80}, {"ram_percent": 81}, 8, 20),
        ("low_disk", {"disk_free": 20 * GIB}, {"disk_free": 20 * GIB - 1}, 8, 20),
        ("many_processes", {"process_count": 180}, {"process_count": 181}, 4, 10),
        ("large_temp", {"temp_size": 3 * GIB}, {"temp_size": 3 * GIB + 1}, 4, 10),
        ("long_uptime", {"uptime": 48 * HOUR}, {"uptime": 48 * HOUR + 1}, 2, 5),
    )

    def test_the_published_threshold_itself_never_costs_the_published_points(self) -> None:
        # v1.0 compared with ">", and so does v2.0: sitting exactly on 70% CPU is still not
        # "above 70%". Only the softer mild tier, which sits lower, applies there.
        for key, at_threshold, _, mild_points, standard_points in self.ANCHORS:
            with self.subTest(key=key):
                charged = points(make_analysis(**at_threshold), key)
                self.assertEqual(charged, mild_points)
                self.assertLess(charged, standard_points)

    def test_one_step_past_the_threshold_costs_the_published_points(self) -> None:
        for key, _, past_threshold, _, expected in self.ANCHORS:
            with self.subTest(key=key):
                self.assertEqual(points(make_analysis(**past_threshold), key), expected)

    def test_all_six_anchors_together_still_score_20(self) -> None:
        data = make_analysis(
            cpu_percent=71,
            ram_percent=81,
            disk_free=19 * GIB,
            process_count=181,
            temp_size=3 * GIB + 1,
            uptime=48 * HOUR + 1,
        )
        result = calculate_health_details(data)
        self.assertEqual(result.total_deduction, 80)
        self.assertEqual(result.score, 20)
        self.assertEqual(result.status, "Poor")
        self.assertEqual(len(result.deductions), 6)

    def test_the_v1_boundary_snapshot_now_only_pays_the_mild_tiers(self) -> None:
        # v1.0 scored this snapshot 100/100. v2.0 deliberately charges the mild tiers
        # instead, so a PC drifting towards a threshold is no longer reported as perfect.
        data = make_analysis(
            cpu_percent=70,
            ram_percent=80,
            disk_free=20 * GIB,
            process_count=180,
            temp_size=3 * GIB,
            uptime=48 * HOUR,
        )
        result = calculate_health_details(data)
        self.assertEqual(result.total_deduction, sum(mild for *_, mild, _ in self.ANCHORS))
        self.assertEqual(calculate_health_score(data), (68, "Needs Optimization"))
        self.assertTrue(all(item.severity == "info" for item in result.deductions))

    def test_a_machine_below_every_mild_tier_is_still_perfect(self) -> None:
        # 50 GB free out of 330 GB is 84.8% used, which clears both storage mild tiers.
        data = make_analysis(
            cpu_percent=55,
            ram_percent=70,
            disk_free=50 * GIB,
            disk_total=330 * GIB,
            process_count=150,
            temp_size=GIB,
            uptime=24 * HOUR,
        )
        self.assertEqual(calculate_health_score(data), (100, "Excellent"))


class TierBoundaryTests(unittest.TestCase):
    """Each tier, at its threshold and one step past it."""

    def assert_tiers(self, key: str, build: object, steps: tuple[tuple[object, int], ...]) -> None:
        for value, expected in steps:
            with self.subTest(key=key, value=value):
                self.assertEqual(points(build(value), key), expected)  # type: ignore[operator]

    def test_high_cpu(self) -> None:
        self.assert_tiers(
            "high_cpu",
            lambda value: make_analysis(cpu_percent=value),
            (
                (55.0, 0), (55.1, 6), (70.0, 6), (70.1, 15),
                (85.0, 15), (85.1, 22), (95.0, 22), (95.1, 28),
            ),
        )

    def test_high_ram(self) -> None:
        self.assert_tiers(
            "high_ram",
            lambda value: make_analysis(ram_percent=value),
            (
                (70.0, 0), (70.1, 8), (80.0, 8), (80.1, 20),
                (90.0, 20), (90.1, 28), (95.0, 28), (95.1, 34),
            ),
        )

    def test_high_swap(self) -> None:
        self.assert_tiers(
            "high_swap",
            lambda value: make_analysis(swap_percent=value),
            ((50.0, 0), (50.1, 4), (75.0, 4), (75.1, 10), (90.0, 10), (90.1, 16)),
        )

    def test_low_disk(self) -> None:
        self.assert_tiers(
            "low_disk",
            lambda value: make_analysis(disk_free=value),
            (
                (50 * GIB, 0),
                (50 * GIB - 1, 8),
                (20 * GIB, 8),
                (20 * GIB - 1, 20),
                (10 * GIB, 20),
                (10 * GIB - 1, 26),
                (5 * GIB, 26),
                (5 * GIB - 1, 32),
            ),
        )

    def test_disk_nearly_full(self) -> None:
        # A 4 TB drive keeps free space above the low_disk thresholds at every tier, so the
        # percentage rule is the only one talking about the disk here.
        def build(free_gib: int) -> AnalysisData:
            return make_analysis(disk_free=free_gib * GIB, disk_total=4000 * GIB)

        self.assert_tiers(
            "disk_nearly_full",
            build,
            ((600, 0), (599, 5), (320, 5), (319, 12), (120, 12), (119, 18)),
        )

    def test_many_processes(self) -> None:
        self.assert_tiers(
            "many_processes",
            lambda value: make_analysis(process_count=value),
            ((150, 0), (151, 4), (180, 4), (181, 10), (250, 10), (251, 14), (350, 14), (351, 18)),
        )

    def test_large_temp(self) -> None:
        self.assert_tiers(
            "large_temp",
            lambda value: make_analysis(temp_size=value),
            (
                (GIB, 0),
                (GIB + 1, 4),
                (3 * GIB, 4),
                (3 * GIB + 1, 10),
                (10 * GIB, 10),
                (10 * GIB + 1, 14),
                (25 * GIB, 14),
                (25 * GIB + 1, 18),
            ),
        )

    def test_long_uptime(self) -> None:
        self.assert_tiers(
            "long_uptime",
            lambda value: make_analysis(uptime=value),
            (
                (24 * HOUR, 0),
                (24 * HOUR + 1, 2),
                (48 * HOUR, 2),
                (48 * HOUR + 1, 5),
                (168 * HOUR, 5),
                (168 * HOUR + 1, 8),
                (336 * HOUR, 8),
                (336 * HOUR + 1, 10),
            ),
        )

    def test_many_startup_items(self) -> None:
        self.assert_tiers(
            "many_startup_items",
            lambda value: make_analysis(startup_count=value),
            ((12, 0), (13, 3), (20, 3), (21, 6), (30, 6), (31, 10)),
        )

    def test_low_battery(self) -> None:
        self.assert_tiers(
            "low_battery",
            lambda value: make_analysis(battery_percent=value, battery_plugged=False),
            ((25.0, 0), (24.9, 2), (15.0, 2), (14.9, 4), (7.0, 4), (6.9, 6)),
        )

    # -- v2.1: durable state. The "value" of a state rule is a rung, not a quantity, so the
    # boundary is the verdict itself: one rung below the threshold must cost nothing.

    def test_antivirus_off(self) -> None:
        # The heaviest penalty in the whole table: a PC with nothing watching it must not be
        # able to read "Excellent" however idle it is.
        self.assert_tiers(
            "antivirus_off",
            lambda value: make_analysis(security=make_security(antivirus=value)),
            ((STATE_GOOD, 0), (STATE_UNKNOWN, 0), (STATE_WEAK, 30), (STATE_BAD, 40)),
        )

    def test_firewall_off(self) -> None:
        self.assert_tiers(
            "firewall_off",
            lambda value: make_analysis(security=make_security(firewall=value)),
            ((STATE_GOOD, 0), (STATE_UNKNOWN, 0), (STATE_WEAK, 12), (STATE_BAD, 18)),
        )

    def test_stale_signatures(self) -> None:
        self.assert_tiers(
            "stale_signatures",
            lambda value: make_analysis(security=make_security(signature_age_days=value)),
            ((0, 0), (7, 0), (8, 8), (30, 8), (31, 14), (365, 14)),
        )

    def test_reboot_pending(self) -> None:
        # Housekeeping rather than danger: the fix is a restart the user was going to do.
        self.assert_tiers(
            "reboot_pending",
            lambda value: make_analysis(security=make_security(reboot_pending=value)),
            ((False, 0), (None, 0), (True, 3)),
        )

    def test_drive_failing(self) -> None:
        # The drive's own controller raised its warning. That is the drive stating its
        # condition, not this application predicting anything, so it is charged in full.
        self.assert_tiers(
            "drive_failing",
            lambda value: make_analysis(drive_health=(make_drive(critical_warning=value),)),
            ((False, 0), (None, 0), (True, 25)),
        )

    def test_drive_worn(self) -> None:
        self.assert_tiers(
            "drive_worn",
            lambda value: make_analysis(drive_health=(worn_drive(value),)),
            ((100, 0), (31, 0), (30, 0), (29, 4), (20, 4), (19, 10), (10, 10), (9, 18), (0, 18)),
        )

    def test_battery_worn(self) -> None:
        # Ageing, not a fault, so it costs little: it explains a short runtime honestly
        # without pretending the PC is unhealthy.
        self.assert_tiers(
            "battery_worn",
            lambda value: make_analysis(
                battery_percent=80.0, battery_plugged=True, battery_health=value
            ),
            ((100.0, 0), (70.0, 0), (69.9, 3), (60.0, 3), (59.9, 6), (50.0, 6), (49.9, 10)),
        )


class RuleInteractionTests(unittest.TestCase):
    def test_only_one_tier_of_a_key_can_fire(self) -> None:
        result = calculate_health_details(make_analysis(cpu_percent=99))
        cpu_deductions = [item for item in result.deductions if item.key == "high_cpu"]
        self.assertEqual(len(cpu_deductions), 1)
        self.assertEqual(cpu_deductions[0].points, 28)  # Not 6 + 15 + 22 + 28.
        self.assertEqual(result.score, 72)

    def test_free_bytes_and_percent_full_are_never_charged_twice(self) -> None:
        result = calculate_health_details(make_analysis(disk_free=GIB))
        keys = [item.key for item in result.deductions]
        self.assertIn("low_disk", keys)
        self.assertNotIn("disk_nearly_full", keys)

    def test_percent_full_still_covers_a_large_but_stuffed_drive(self) -> None:
        result = calculate_health_details(make_analysis(disk_free=100 * GIB, disk_total=4000 * GIB))
        keys = [item.key for item in result.deductions]
        self.assertNotIn("low_disk", keys)
        self.assertIn("disk_nearly_full", keys)

    def test_a_tiny_page_file_is_never_scored(self) -> None:
        # A 256 MB page file sits at 95% on a perfectly healthy PC.
        for swap_total in (None, MIN_MEANINGFUL_SWAP_BYTES - 1, 256 * 1024**2):
            with self.subTest(swap_total=swap_total):
                data = make_analysis(swap_total=swap_total, swap_percent=99.0)
                self.assertEqual(points(data, "high_swap"), 0)

    def test_a_page_file_at_the_size_limit_is_scored(self) -> None:
        data = make_analysis(swap_total=MIN_MEANINGFUL_SWAP_BYTES, swap_percent=99.0)
        self.assertEqual(points(data, "high_swap"), 16)

    def test_battery_level_only_counts_while_discharging(self) -> None:
        for plugged in (True, None):
            with self.subTest(plugged_in=plugged):
                data = make_analysis(battery_percent=3.0, battery_plugged=plugged)
                self.assertEqual(points(data, "low_battery"), 0)
        discharging = make_analysis(battery_percent=3.0, battery_plugged=False)
        self.assertEqual(points(discharging, "low_battery"), 6)

    def test_disk_usage_is_derived_when_the_snapshot_omits_it(self) -> None:
        data = make_analysis(disk_free=100 * GIB, disk_total=4000 * GIB, disk_percent=None)
        self.assertEqual(points(data, "disk_nearly_full"), 18)

    def test_score_is_clamped_at_zero(self) -> None:
        data = make_analysis(
            cpu_percent=100,
            ram_percent=100,
            swap_percent=100,
            disk_free=1,
            process_count=5000,
            temp_size=100 * GIB,
            uptime=400 * 24 * HOUR,
            startup_count=90,
            battery_percent=1.0,
            battery_plugged=False,
        )
        result = calculate_health_details(data)
        self.assertGreater(result.total_deduction, 100)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.status, "Poor")


class UnknownValueTests(unittest.TestCase):
    @staticmethod
    def blank() -> AnalysisData:
        return make_analysis(
            cpu_percent=None,
            ram_percent=None,
            disk_free=None,
            process_count=None,
            temp_size=None,
            uptime=None,
            swap_total=None,
            swap_percent=None,
            startup_count=0,
        )

    def test_a_completely_unmeasurable_pc_is_never_penalised(self) -> None:
        result = calculate_health_details(self.blank())
        self.assertEqual(result.score, 100)
        self.assertEqual(result.deductions, ())
        self.assertFalse(result.data_complete)

    def test_every_category_reports_itself_unavailable(self) -> None:
        result = calculate_health_details(self.blank())
        self.assertEqual(len(result.categories), len(CATEGORY_LABELS))
        for category in result.categories:
            with self.subTest(category=category.key):
                self.assertFalse(category.available)
                self.assertEqual(category.score, 100)  # Nominal, and flagged as unearned.

    def test_a_single_missing_metric_only_reduces_completeness(self) -> None:
        required = (
            "cpu_percent", "ram_percent", "disk_free", "process_count", "temp_size", "uptime",
        )
        for missing in required:
            with self.subTest(missing=missing):
                result = calculate_health_details(make_analysis(**{missing: None}))
                self.assertEqual(result.score, 100)
                self.assertFalse(result.data_complete)

    def test_optional_metrics_do_not_affect_completeness(self) -> None:
        # Startup entries, swap and battery are best-effort extras, not required readings.
        result = calculate_health_details(
            make_analysis(swap_total=None, swap_percent=None, startup_count=0, battery=None)
        )
        self.assertTrue(result.data_complete)


class RequiredValuesTests(unittest.TestCase):
    """``required_values_present`` is the project's single definition of "incomplete".

    Three places used to answer that question with three slightly different rules: the score
    flag, the advice disclosure, and the exporters. They now all read this one predicate, so
    it is asserted here on its own rather than only through its callers.
    """

    #: The six readings a complete snapshot must carry, as make_analysis() names them.
    REQUIRED = ("cpu_percent", "ram_percent", "disk_free", "process_count", "temp_size", "uptime")

    def test_a_fully_measured_snapshot_is_complete(self) -> None:
        self.assertTrue(required_values_present(make_analysis()))

    def test_each_of_the_six_readings_is_required_on_its_own(self) -> None:
        for missing in self.REQUIRED:
            with self.subTest(missing=missing):
                self.assertFalse(required_values_present(make_analysis(**{missing: None})))

    def test_a_truncated_temp_scan_counts_as_a_missing_reading(self) -> None:
        # The scan produced a floor, and a floor is not the measurement the table asks for.
        self.assertFalse(required_values_present(make_analysis(temp_truncated=True)))

    def test_the_optional_readings_are_not_required(self) -> None:
        optional = (
            {"swap_total": None, "swap_percent": None},
            {"startup_count": 0},
            {"battery": None},
            {"gpus": ()},
            {"partitions": ()},
            {"top_processes": ()},
        )
        for overrides in optional:
            with self.subTest(overrides=tuple(overrides)):
                self.assertTrue(required_values_present(make_analysis(**overrides)))

    def test_warnings_alone_do_not_make_a_snapshot_incomplete(self) -> None:
        # A warning is a separate signal; the advice engine ors the two together itself.
        self.assertTrue(required_values_present(make_analysis(warnings=("GPU list failed",))))

    def test_the_assessment_flag_is_computed_from_the_predicate(self) -> None:
        cases = (
            make_analysis(),
            make_analysis(cpu_percent=None),
            make_analysis(temp_truncated=True),
            make_analysis(temp_size=None, uptime=None),
            make_analysis(warnings=("GPU list failed",)),
        )
        for data in cases:
            with self.subTest(complete=required_values_present(data)):
                assessment = calculate_health_details(data)
                self.assertEqual(assessment.data_complete, required_values_present(data))


class TruncatedTempScoringTests(unittest.TestCase):
    """A TEMP size cut short by the time budget is a floor, and the score has to say so."""

    def charged(self, key: str, **overrides: object) -> object:
        found = deduction(calculate_health_details(make_analysis(**overrides)), key)
        self.assertIsNotNone(found, f"{key} did not fire")
        return found

    def test_the_rule_still_fires_at_the_same_tier(self) -> None:
        # Firing on a floor is never less accurate than staying silent: the real folder is
        # at least this big, so the tier it crossed was really crossed.
        exact = self.charged("large_temp", temp_size=5 * GIB)
        floored = self.charged("large_temp", temp_size=5 * GIB, temp_truncated=True)
        self.assertEqual(floored.points, exact.points)  # type: ignore[union-attr]
        self.assertEqual(floored.severity, exact.severity)  # type: ignore[union-attr]

    def test_the_params_mark_the_measurement_as_a_floor(self) -> None:
        # The qualifier is a sentence, so it is not baked into the number: the params carry
        # the plain measurement plus a language-neutral marker, and the renderer words it
        # through "report.at_least". Only the fallback reason spells it out in English.
        floored = self.charged("large_temp", temp_size=5 * GIB, temp_truncated=True)
        self.assertEqual(floored.values["value"], "5.0 GB")  # type: ignore[union-attr]
        self.assertEqual(floored.values["bound"], "lower")  # type: ignore[union-attr]
        self.assertEqual(("bound", "lower"), LOWER_BOUND_PARAM)
        self.assertIn("at least 5.0 GB", floored.reason)  # type: ignore[union-attr]
        self.assertNotIn("(5.0 GB)", floored.reason)  # type: ignore[union-attr]

    def test_an_untruncated_scan_quotes_the_measurement_itself(self) -> None:
        exact = self.charged("large_temp", temp_size=5 * GIB)
        self.assertEqual(exact.values["value"], "5.0 GB")  # type: ignore[union-attr]
        self.assertNotIn("bound", exact.values)  # type: ignore[union-attr]
        self.assertNotIn("at least", exact.reason)  # type: ignore[union-attr]

    def test_only_the_temp_measurement_is_bounded(self) -> None:
        # The flag describes one collector, so no other sentence may be softened by it.
        result = calculate_health_details(
            make_analysis(temp_size=5 * GIB, cpu_percent=95, uptime=200 * HOUR, temp_truncated=True)
        )
        others = [item for item in result.deductions if item.key != "large_temp"]
        self.assertTrue(others)
        for item in others:
            with self.subTest(key=item.key):
                self.assertNotIn("at least", item.reason)

    def test_the_snapshot_is_reported_as_incomplete(self) -> None:
        result = calculate_health_details(make_analysis(temp_size=5 * GIB, temp_truncated=True))
        self.assertFalse(result.data_complete)


class CategoryTests(unittest.TestCase):
    def test_categories_are_reported_in_a_fixed_order(self) -> None:
        result = calculate_health_details(make_analysis())
        self.assertEqual(
            [(item.key, item.label) for item in result.categories], list(CATEGORY_LABELS)
        )

    def test_a_weak_area_is_visible_instead_of_averaged_away(self) -> None:
        result = calculate_health_details(make_analysis(cpu_percent=99))
        cpu = result.category(CATEGORY_CPU)
        assert cpu is not None
        self.assertEqual(cpu.score, 72)
        self.assertEqual(cpu.lost_points, 28)
        self.assertEqual([item.key for item in cpu.deductions], ["high_cpu"])
        for key in (CATEGORY_MEMORY, CATEGORY_STORAGE, CATEGORY_MAINTENANCE):
            other = result.category(key)
            assert other is not None
            self.assertEqual(other.score, 100)
            self.assertEqual(other.deductions, ())

    def test_availability_follows_the_measurements(self) -> None:
        result = calculate_health_details(make_analysis())
        for key in (CATEGORY_CPU, CATEGORY_MEMORY, CATEGORY_STORAGE, CATEGORY_MAINTENANCE):
            category = result.category(key)
            assert category is not None
            self.assertTrue(category.available, key)
        power = result.category(CATEGORY_POWER)
        assert power is not None
        self.assertFalse(power.available)  # A desktop has no battery to report on.

    def test_a_battery_makes_the_power_category_available(self) -> None:
        result = calculate_health_details(make_analysis(battery_percent=95.0, battery_plugged=True))
        power = result.category(CATEGORY_POWER)
        assert power is not None
        self.assertTrue(power.available)
        self.assertEqual(power.score, 100)

    def test_category_lookup_of_an_unknown_key(self) -> None:
        self.assertIsNone(calculate_health_details(make_analysis()).category("nope"))

    def test_category_scores_never_go_below_zero(self) -> None:
        result = calculate_health_details(
            make_analysis(
                process_count=5000, temp_size=100 * GIB, uptime=400 * 24 * HOUR, startup_count=90
            )
        )
        maintenance = result.category(CATEGORY_MAINTENANCE)
        assert maintenance is not None
        self.assertGreaterEqual(maintenance.score, 0)
        self.assertEqual(maintenance.score, max(0, 100 - maintenance.lost_points))


class DeductionOutputTests(unittest.TestCase):
    def test_ordering_is_worst_first_then_heaviest_then_alphabetical(self) -> None:
        data = make_analysis(
            cpu_percent=96,  # severe / critical, 28
            ram_percent=71,  # mild / info, 8
            temp_size=3 * GIB + 1,  # standard / warning, 10
            uptime=25 * HOUR,  # mild / info, 2
        )
        result = calculate_health_details(data)
        self.assertEqual(
            [item.key for item in result.deductions],
            ["high_cpu", "large_temp", "high_ram", "long_uptime"],
        )
        ranks = [
            (-severity_rank(item.severity), -item.points, item.key) for item in result.deductions
        ]
        self.assertEqual(ranks, sorted(ranks))

    def test_ties_are_broken_by_key_so_output_is_deterministic(self) -> None:
        data = make_analysis(uptime=25 * HOUR, battery_percent=24.0, battery_plugged=False)
        result = calculate_health_details(data)
        info = [item.key for item in result.deductions if item.severity == "info"]
        self.assertEqual(info, ["long_uptime", "low_battery"])  # Equal points, key order.

    def test_scoring_is_reproducible(self) -> None:
        data = make_analysis(cpu_percent=88, disk_free=3 * GIB, process_count=400)
        first = calculate_health_details(data)
        second = calculate_health_details(data)
        self.assertEqual(first, second)

    def test_every_deduction_states_the_number_it_was_based_on(self) -> None:
        data = make_analysis(
            cpu_percent=99,
            ram_percent=99,
            swap_percent=99,
            disk_free=GIB,
            process_count=999,
            temp_size=99 * GIB,
            uptime=999 * HOUR,
            startup_count=40,
            battery_percent=2.0,
            battery_plugged=False,
            # v2.1 state. One battery carries both a flat charge and a worn pack, and one
            # drive carries both its own critical warning and a wear figure, so the snapshot
            # still describes a single machine rather than a list of unrelated faults.
            battery_health=40.0,
            security=make_security(
                antivirus=STATE_BAD,
                firewall=STATE_BAD,
                reboot_pending=True,
                signature_age_days=45,
            ),
            drive_health=(make_drive(percentage_used=95, critical_warning=True),),
        )
        result = calculate_health_details(data)
        fired = {item.key for item in result.deductions}
        # disk_nearly_full is the one key this snapshot cannot reach: low_disk suppresses it.
        self.assertEqual(fired, DEDUCTION_KEYS - {"disk_nearly_full"})
        for item in result.deductions:
            with self.subTest(key=item.key):
                self.assertIn(item.key, DEDUCTION_KEYS)
                self.assertIn(item.severity, SEVERITY_ORDER)
                self.assertNotIn("{", item.reason)
                self.assertTrue(item.reason.endswith("."))
                if item.key not in STATELESS_DEDUCTION_KEYS:
                    self.assertIn("value", item.values)
                    self.assertNotEqual(item.values["value"], "N/A")
                for name, value in item.params:
                    self.assertIn("{" + name + "}", DEDUCTION_TEMPLATES[item.key])
                    self.assertIn(value, item.reason)

    def test_a_stateless_deduction_quotes_no_measurement_and_still_reads_cleanly(self) -> None:
        # The other half of the rule above: a sentence with no number must not smuggle one in,
        # and must not leave an empty pair of brackets where a figure used to be.
        data = make_analysis(
            security=make_security(
                antivirus=STATE_BAD,
                firewall=STATE_BAD,
                reboot_pending=True,
                signature_age_days=45,
            ),
            drive_health=(make_drive(percentage_used=1, critical_warning=True),),
        )
        charged = {item.key: item for item in calculate_health_details(data).deductions}
        self.assertEqual(set(charged), STATELESS_DEDUCTION_KEYS)
        for key, item in charged.items():
            with self.subTest(key=key):
                self.assertNotIn("value", item.values)
                self.assertNotIn("()", item.reason)
                self.assertNotIn("N/A", item.reason)

    def test_drive_letter_is_carried_into_disk_reasons(self) -> None:
        result = calculate_health_details(make_analysis(disk_free=GIB, drive="D:\\"))
        low_disk = deduction(result, "low_disk")
        assert low_disk is not None
        self.assertEqual(low_disk.values["drive"], "D:")  # type: ignore[union-attr]
        self.assertIn("D:", low_disk.reason)  # type: ignore[union-attr]


class SecureBootTests(unittest.TestCase):
    """Measured, reported, and deliberately never scored.

    Secure Boot is off for entirely legitimate reasons - a dual-boot machine, older firmware -
    so taking points away for it would be dishonest. The absence of a rule is therefore a
    decision, and a decision has to be asserted or a future edit will quietly reverse it.
    """

    def test_no_rule_in_the_table_reads_the_secure_boot_metric(self) -> None:
        self.assertIn("secure_boot_state", METRICS)
        reading_it = [rule.key for rule in SCORE_RULES if rule.metric == "secure_boot_state"]
        self.assertEqual(reading_it, [])

    def test_no_deduction_key_is_named_after_it(self) -> None:
        self.assertNotIn("secure_boot_off", DEDUCTION_KEYS)
        self.assertNotIn("secure_boot_off", DEDUCTION_TEMPLATES)
        self.assertNotIn("secure_boot_off", {rule.key for rule in SCORE_RULES})

    def test_a_machine_with_secure_boot_off_loses_nothing_at_all(self) -> None:
        for state in (STATE_GOOD, STATE_WEAK, STATE_BAD, STATE_UNKNOWN):
            with self.subTest(secure_boot=state):
                result = calculate_health_details(
                    make_analysis(security=make_security(secure_boot=state))
                )
                self.assertEqual(result.deductions, ())
                self.assertEqual(result.score, 100)

    def test_it_still_counts_as_having_measured_the_security_area(self) -> None:
        # A machine that answered only this question is not "unknown" - the sub-score was
        # measurable, it simply found nothing to charge for.
        result = calculate_health_details(
            make_analysis(security=unreadable_security_with(secure_boot=STATE_WEAK))
        )
        security = result.category(CATEGORY_SECURITY)
        assert security is not None
        self.assertTrue(security.available)
        self.assertEqual(security.score, 100)


class UnknownStateTests(unittest.TestCase):
    """An unreadable verdict is not a finding, and it never becomes one."""

    def test_a_machine_that_answered_nothing_about_protection_loses_nothing(self) -> None:
        result = calculate_health_details(make_analysis(security=unreadable_security()))
        self.assertEqual(result.deductions, ())
        self.assertEqual(result.score, 100)

    def test_a_snapshot_with_no_security_record_at_all_loses_nothing(self) -> None:
        # The step can be switched off, and a step that did not run is not a machine at risk.
        self.assertEqual(calculate_health_details(make_analysis(security=None)).score, 100)

    def test_a_verdict_this_version_cannot_interpret_is_unknown_rather_than_bad(self) -> None:
        for verdict in ("mostly-fine", "", "GOOD", None, 2, True):
            with self.subTest(verdict=verdict):
                data = make_analysis(security=make_security(antivirus=verdict))
                self.assertEqual(points(data, "antivirus_off"), 0)

    def test_a_drive_that_reported_no_wear_figure_is_never_charged(self) -> None:
        data = make_analysis(drive_health=(silent_drive(),))
        self.assertEqual(calculate_health_details(data).deductions, ())

    def test_a_battery_that_reported_no_capacity_is_never_charged(self) -> None:
        data = make_analysis(battery_percent=80.0, battery_plugged=True)
        self.assertEqual(points(data, "battery_worn"), 0)

    def test_an_unknown_signature_age_is_never_charged(self) -> None:
        data = make_analysis(security=make_security(signature_age_days=None))
        self.assertEqual(points(data, "stale_signatures"), 0)

    def test_the_ladder_places_only_the_three_known_verdicts(self) -> None:
        self.assertEqual(STATE_LEVELS, {STATE_GOOD: 0.0, STATE_WEAK: 1.0, STATE_BAD: 2.0})
        for state, level in ((STATE_GOOD, 0.0), (STATE_WEAK, 1.0), (STATE_BAD, 2.0)):
            with self.subTest(state=state):
                self.assertEqual(state_level(state), level)
        for value in (STATE_UNKNOWN, "nonsense", None, 1, True, 2.0, []):
            with self.subTest(value=value):
                self.assertIsNone(state_level(value))


class SecurityCategoryTests(unittest.TestCase):
    """The new sub-score: unavailable until something was actually readable."""

    def category(self, **overrides: object):
        result = calculate_health_details(make_analysis(**overrides))
        found = result.category(CATEGORY_SECURITY)
        assert found is not None
        return found

    def test_the_security_category_is_reported_last_and_labelled(self) -> None:
        self.assertEqual(CATEGORY_LABELS[-1], (CATEGORY_SECURITY, "Security"))

    def test_a_snapshot_that_never_looked_reports_the_area_unavailable(self) -> None:
        area = self.category(security=None)
        self.assertFalse(area.available)
        self.assertEqual(area.score, 100)  # Nominal, and flagged as unearned.
        self.assertEqual(area.deductions, ())

    def test_a_machine_where_nothing_could_be_read_reports_it_unavailable_too(self) -> None:
        # Three "Unknown" rows are not a clean bill of health.
        area = self.category(security=unreadable_security())
        self.assertFalse(area.available)
        self.assertEqual(area.score, 100)

    def test_one_readable_verdict_makes_the_area_available(self) -> None:
        for field in ("antivirus", "firewall", "secure_boot"):
            with self.subTest(readable=field):
                area = self.category(security=unreadable_security_with(**{field: STATE_GOOD}))
                self.assertTrue(area.available)

    def test_a_readable_signature_age_also_counts_as_a_measurement(self) -> None:
        area = self.category(security=unreadable_security_with(signature_age_days=0))
        self.assertTrue(area.available)

    def test_the_area_carries_exactly_its_own_deductions(self) -> None:
        area = self.category(
            security=make_security(antivirus=STATE_BAD, firewall=STATE_WEAK, signature_age_days=40),
            cpu_percent=99,  # A finding in another area may not leak into this one.
        )
        self.assertEqual(
            sorted(item.key for item in area.deductions),
            ["antivirus_off", "firewall_off", "stale_signatures"],
        )
        self.assertEqual(area.lost_points, 40 + 12 + 14)
        self.assertEqual(area.score, max(0, 100 - area.lost_points))

    def test_a_pending_restart_is_maintenance_rather_than_protection(self) -> None:
        # It sits with the housekeeping because the fix is a restart, not a security setting.
        result = calculate_health_details(
            make_analysis(security=make_security(reboot_pending=True))
        )
        charged = deduction(result, "reboot_pending")
        assert charged is not None
        self.assertEqual(charged.category, CATEGORY_MAINTENANCE)  # type: ignore[union-attr]

    def test_an_unguarded_pc_cannot_read_excellent(self) -> None:
        # The reason antivirus_off carries the heaviest penalty in the table.
        result = calculate_health_details(
            make_analysis(security=make_security(antivirus=STATE_BAD))
        )
        self.assertEqual(result.score, 60)
        self.assertNotEqual(result.status, "Excellent")


class StateCategoryAvailabilityTests(unittest.TestCase):
    """Storage and Power gain new inputs, and "nobody answered" must stay visible."""

    def area(self, key: str, **overrides: object):
        found = calculate_health_details(make_analysis(**overrides)).category(key)
        assert found is not None
        return found

    def test_a_drive_that_answered_its_own_health_question_makes_storage_measured(self) -> None:
        self.assertTrue(self.area(CATEGORY_STORAGE, drive_health=(make_drive(),)).available)

    def test_a_battery_that_answered_its_capacity_makes_power_measured(self) -> None:
        area = self.area(CATEGORY_POWER, battery_percent=None, battery_health=88.0)
        self.assertTrue(area.available)

    def test_a_desktop_with_no_battery_still_reports_power_unavailable(self) -> None:
        self.assertFalse(self.area(CATEGORY_POWER).available)


class DriveSelectionTests(unittest.TestCase):
    """One problem, one deduction - however many disks are fitted."""

    def test_the_worst_drive_is_the_one_charged_for(self) -> None:
        data = make_analysis(
            drive_health=(worn_drive(80, "C:\\"), worn_drive(5, "D:\\"), worn_drive(25, "E:\\"))
        )
        charged = deduction(calculate_health_details(data), "drive_worn")
        assert charged is not None
        self.assertEqual(charged.points, 18)  # type: ignore[union-attr]
        self.assertEqual(charged.values["drive"], "D:")  # type: ignore[union-attr]

    def test_two_worn_drives_are_one_finding_not_two(self) -> None:
        data = make_analysis(drive_health=(worn_drive(5, "C:\\"), worn_drive(6, "D:\\")))
        deductions = calculate_health_details(data).deductions
        charged = [item for item in deductions if item.key == "drive_worn"]
        self.assertEqual(len(charged), 1)

    def test_two_failing_drives_are_one_finding_too(self) -> None:
        data = make_analysis(
            drive_health=(
                make_drive("C:\\", critical_warning=True),
                make_drive("D:\\", critical_warning=True),
            )
        )
        deductions = calculate_health_details(data).deductions
        charged = [item for item in deductions if item.key == "drive_failing"]
        self.assertEqual(len(charged), 1)
        self.assertEqual(charged[0].values["drive"], "C:")  # Alphabetical, so it is stable.

    def test_the_selectors_agree_with_what_the_deduction_names(self) -> None:
        drives = (worn_drive(40, "C:\\"), worn_drive(12, "D:\\", critical_warning=True))
        worst = most_worn_drive(drives)
        failing = failing_drive(drives)
        assert worst is not None and failing is not None
        self.assertEqual(worst.drive, "D:\\")
        self.assertEqual(failing.drive, "D:\\")

    def test_the_selectors_say_nothing_about_drives_that_answered_nothing(self) -> None:
        drives = (silent_drive("C:\\"), silent_drive("D:\\"))
        self.assertIsNone(most_worn_drive(drives))
        self.assertIsNone(failing_drive(drives))
        self.assertIsNone(most_worn_drive(()))
        self.assertIsNone(failing_drive(()))

    def test_a_healthy_drive_beside_a_silent_one_is_still_a_measurement(self) -> None:
        # "No drive told us" and "every drive said it is fine" are different facts, and only
        # the second one may report the Storage area as measured.
        data = make_analysis(drive_health=(silent_drive("C:\\"), make_drive("D:\\")))
        area = calculate_health_details(data).category(CATEGORY_STORAGE)
        assert area is not None
        self.assertTrue(area.available)
        self.assertEqual(area.deductions, ())


class StateInteractionTests(unittest.TestCase):
    """The new rows behave like every other row: one tier, and they add up honestly."""

    def test_only_one_tier_of_a_protection_rule_can_fire(self) -> None:
        result = calculate_health_details(
            make_analysis(security=make_security(antivirus=STATE_BAD))
        )
        charged = [item for item in result.deductions if item.key == "antivirus_off"]
        self.assertEqual(len(charged), 1)
        self.assertEqual(charged[0].points, 40)  # Not 30 + 40.

    def test_a_worn_drive_that_is_also_failing_is_charged_for_both_facts(self) -> None:
        # Deliberately not suppressed, unlike low_disk and disk_nearly_full: "this drive
        # raised its warning" and "this drive is out of rated life" are two findings.
        data = make_analysis(drive_health=(worn_drive(5, critical_warning=True),))
        result = calculate_health_details(data)
        self.assertEqual({item.key for item in result.deductions}, {"drive_failing", "drive_worn"})
        self.assertEqual(result.total_deduction, 25 + 18)

    def test_the_state_rules_never_touch_completeness(self) -> None:
        # They are best-effort extras: a PC whose Security Center is silent is still a
        # completely measured PC as far as the six required readings are concerned.
        for overrides in (
            {"security": None},
            {"security": unreadable_security()},
            {"drive_health": ()},
            {"folder_usage": ()},
        ):
            with self.subTest(overrides=tuple(overrides)):
                self.assertTrue(required_values_present(make_analysis(**overrides)))

    def test_a_fully_afflicted_machine_still_scores_within_the_band(self) -> None:
        data = make_analysis(
            security=make_security(
                antivirus=STATE_BAD, firewall=STATE_BAD, reboot_pending=True, signature_age_days=90
            ),
            drive_health=(worn_drive(2, critical_warning=True),),
            battery_percent=50.0,
            battery_plugged=True,
            battery_health=40.0,
        )
        result = calculate_health_details(data)
        self.assertEqual(result.total_deduction, 40 + 18 + 14 + 3 + 25 + 18 + 10)
        self.assertEqual(result.score, 0)
        self.assertEqual(result.status, "Poor")


class StatusBandTests(unittest.TestCase):
    def test_status_boundaries(self) -> None:
        expected = {
            100: "Excellent",
            90: "Excellent",
            89: "Good",
            75: "Good",
            74: "Needs Optimization",
            50: "Needs Optimization",
            49: "Poor",
            0: "Poor",
        }
        for score, status in expected.items():
            with self.subTest(score=score):
                self.assertEqual(get_score_status(score), status)

    def test_out_of_range_scores_are_clamped(self) -> None:
        self.assertEqual(get_score_status(1000), "Excellent")
        self.assertEqual(get_score_status(-50), "Poor")

    def test_status_matches_the_reported_score(self) -> None:
        for cpu in (10, 60, 75, 90, 99):
            for ram in (10, 75, 85, 96):
                result = calculate_health_details(make_analysis(cpu_percent=cpu, ram_percent=ram))
                with self.subTest(cpu=cpu, ram=ram):
                    self.assertEqual(result.status, get_score_status(result.score))
                    self.assertEqual(result.score, max(0, 100 - result.total_deduction))


if __name__ == "__main__":
    unittest.main()
