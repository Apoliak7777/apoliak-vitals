"""Tests for the rule-based advice in src/recommendations.py.

Two properties matter more than the wording: every recommendation key must be reachable
from a real snapshot, and the advice must stay silent about anything that was not measured.
"""

from __future__ import annotations

import itertools
import unittest
from dataclasses import replace

from src import recommendations
from src.health_score import (
    LOWER_BOUND_PARAM,
    SCORE_RULES,
    calculate_health_details,
    required_values_present,
)
from src.models import (
    CATEGORY_CPU,
    CATEGORY_MEMORY,
    CATEGORY_STORAGE,
    SEVERITY_ORDER,
    STATE_BAD,
    STATE_WEAK,
    AnalysisData,
    Recommendation,
    severity_rank,
)
from src.recommendations import (
    RECOMMENDATION_ACTIONS,
    RECOMMENDATION_TEMPLATES,
    TOP_CPU_PERCENT,
    TOP_MEMORY_PERCENT,
    generate_recommendations,
)
from src.utils import GIB, format_bytes
from tests.helpers import (
    make_analysis,
    make_drive,
    make_folder,
    make_partition,
    make_process,
    make_security,
)

HOUR = 3600.0

#: Read from the score table itself: a deduction key added there must gain advice too.
DEDUCTION_KEYS = frozenset(rule.key for rule in SCORE_RULES)

#: The complete key vocabulary the whole project agreed on for recommendations.
RECOMMENDATION_KEYS = frozenset(
    {
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
        # v2.1. secure_boot_off is advice with no matching deduction on purpose: Secure Boot
        # is off for legitimate reasons, so it is reported without costing a point.
        "antivirus_off",
        "firewall_off",
        "stale_signatures",
        "secure_boot_off",
        "reboot_pending",
        "drive_failing",
        "drive_worn",
        "battery_worn",
        "large_folder",
    }
)

#: One snapshot per key, chosen so that key is guaranteed to appear.
TRIGGERS: dict[str, dict[str, object]] = {
    "high_cpu": {"cpu_percent": 75},
    "medium_cpu": {"cpu_percent": 60},
    "high_ram": {"ram_percent": 85},
    "medium_ram": {"ram_percent": 75},
    "high_swap": {"swap_percent": 80},
    "medium_swap": {"swap_percent": 60},
    "low_disk": {"disk_free": 15 * GIB},
    # Past the mild free-bytes tier but not the standard one, on the default 512 GiB drive.
    "medium_disk": {"disk_free": 30 * GIB},
    "disk_nearly_full": {"disk_free": 100 * GIB, "disk_total": 4000 * GIB},
    # Roomy enough that the free-bytes rule stays quiet, yet past the mild percentage tier.
    "medium_disk_full": {"disk_free": 100 * GIB, "disk_total": 1024 * GIB},
    "many_processes": {"process_count": 200},
    "some_processes": {"process_count": 160},
    "large_temp": {"temp_size": 5 * GIB},
    "medium_temp": {"temp_size": 2 * GIB},
    "long_uptime": {"uptime": 72 * HOUR},
    "medium_uptime": {"uptime": 30 * HOUR},
    "many_startup_items": {"startup_count": 15},
    "low_battery": {"battery_percent": 20.0, "battery_plugged": False},
    "hdd_system_drive": {"media_type": "HDD"},
    "incomplete_data": {"warnings": ("Disk information could not be collected: denied",)},
    "all_good": {},
    # --- v2.1: durable state. One condition per snapshot, so the trigger proves that key. ---
    "antivirus_off": {"security": make_security(antivirus=STATE_BAD)},
    "firewall_off": {"security": make_security(firewall=STATE_WEAK)},
    "stale_signatures": {"security": make_security(signature_age_days=45)},
    "secure_boot_off": {"security": make_security(secure_boot=STATE_WEAK)},
    "reboot_pending": {"security": make_security(reboot_pending=True)},
    "drive_failing": {"drive_health": (make_drive(critical_warning=True),)},
    "drive_worn": {"drive_health": (make_drive(percentage_used=85),)},
    "battery_worn": {"battery_health": 40.0},
    "large_folder": {"folder_usage": (make_folder("videos", size_bytes=60 * GIB),)},
    # The two process keys need a process list rather than a threshold, but they are keys of
    # the same vocabulary, so they are triggered here too - see the coverage test below.
    "top_memory_process": {
        "top_processes": (make_process(200, "chrome.exe", memory_bytes=4 * GIB,
                                       memory_percent=25.0),)
    },
    "top_cpu_process": {
        "top_processes": (make_process(201, "build.exe", memory_bytes=GIB // 4,
                                       cpu_percent=40.0),)
    },
}


#: A perfectly healthy drive Windows booted from. Present in every foreign-drive snapshot,
#: so a reader that picks the "system" partition instead of the analysed one sees a clean
#: bill of health and stays silent - which is exactly the defect these tests lock out.
HEALTHY_SYSTEM_PARTITION = make_partition(
    "C:\\", total=1024 * GIB, free=800 * GIB, media_type="SSD", is_system=True
)

#: Snapshots whose analysed drive is deliberately not the drive Windows booted from, which
#: is what analyze_pc(drive="D:\\") produces.
FOREIGN_DRIVE_SNAPSHOTS: tuple[tuple[str, dict[str, object]], ...] = (
    ("a full data drive", {"drive": "D:\\", "disk_free": 2 * GIB, "disk_total": 512 * GIB}),
    (
        "a huge data drive that is nearly full",
        {"drive": "E:\\", "disk_free": 100 * GIB, "disk_total": 4000 * GIB},
    ),
    ("a rotating data drive", {"drive": "F:\\", "media_type": "HDD"}),
    (
        "a data drive with several problems at once",
        {
            "drive": "G:\\",
            "disk_free": 4 * GIB,
            "disk_total": 512 * GIB,
            "media_type": "HDD",
            "cpu_percent": 88,
            "temp_size": 12 * GIB,
        },
    ),
)


#: Six conditions are named differently by the two engines: the score charges one key at
#: every tier, while the advice has a gentler sentence for the mild tier. Both describe the
#: same measurement crossing the same threshold, so either one explains the deduction.
SOFTER_VARIANT: dict[str, str] = {
    "high_cpu": "medium_cpu",
    "high_ram": "medium_ram",
    "high_swap": "medium_swap",
    "low_disk": "medium_disk",
    "disk_nearly_full": "medium_disk_full",
    "many_processes": "some_processes",
    "large_temp": "medium_temp",
    "long_uptime": "medium_uptime",
}


def unexplained(deducted: set[str], advised: set[str]) -> set[str]:
    """Deduction keys the advice failed to mention, under either of their two wordings."""
    return {
        key
        for key in deducted
        if key not in advised and SOFTER_VARIANT.get(key) not in advised
    }


def foreign_drive(**overrides: object) -> AnalysisData:
    """A snapshot about a non-system drive, with a healthy system drive alongside it."""
    fields: dict[str, object] = {
        "disk_is_system": False,
        "partitions": (HEALTHY_SYSTEM_PARTITION,),
    }
    fields.update(overrides)
    return make_analysis(**fields)  # type: ignore[arg-type]


def keys_for(**kwargs: object) -> list[str]:
    return [item.key for item in generate_recommendations(make_analysis(**kwargs))]


def only(data: AnalysisData, key: str) -> Recommendation:
    """The single recommendation carrying ``key``; raises loudly when it did not fire."""
    return next(item for item in generate_recommendations(data) if item.key == key)


class VocabularyTests(unittest.TestCase):
    def test_every_template_key_is_in_the_agreed_vocabulary(self) -> None:
        self.assertEqual(set(RECOMMENDATION_TEMPLATES), RECOMMENDATION_KEYS)

    def test_every_key_in_the_vocabulary_has_a_trigger(self) -> None:
        # Without this, a key could be shipped - and translated into both languages - with no
        # proof that any machine can ever produce it. Every entry below is then fired for real
        # by test_every_key_can_fire, so "it has a trigger" cannot degrade into "it has a row".
        self.assertEqual(set(TRIGGERS), RECOMMENDATION_KEYS)

    def test_every_key_can_fire(self) -> None:
        for key, snapshot in TRIGGERS.items():
            with self.subTest(key=key):
                self.assertIn(key, keys_for(**snapshot))

    def test_the_two_process_keys_can_fire(self) -> None:
        data = make_analysis(
            top_processes=(
                make_process(
                    200, "chrome.exe", memory_bytes=4 * GIB, memory_percent=25.0, cpu_percent=40.0
                ),
            )
        )
        keys = [item.key for item in generate_recommendations(data)]
        self.assertIn("top_memory_process", keys)
        self.assertIn("top_cpu_process", keys)

    def test_generated_advice_is_always_well_formed(self) -> None:
        for key, snapshot in TRIGGERS.items():
            for item in generate_recommendations(make_analysis(**snapshot)):
                with self.subTest(trigger=key, key=item.key):
                    self.assertIn(item.key, RECOMMENDATION_KEYS)
                    self.assertIn(item.severity, SEVERITY_ORDER)
                    self.assertTrue(item.text.strip())
                    self.assertNotIn("{", item.text)
                    # v1.0 call sites printed the advice directly, so str() must stay the text.
                    self.assertEqual(str(item), item.text)
                    for name, value in item.params:
                        if (name, value) == LOWER_BOUND_PARAM:
                            continue  # A qualifier for the renderer, not a substitution.
                        self.assertIn("{" + name + "}", RECOMMENDATION_TEMPLATES[item.key])
                        self.assertIn(value, item.text)


class HealthyMachineTests(unittest.TestCase):
    def test_healthy_pc_gets_one_maintenance_message(self) -> None:
        recommendations = generate_recommendations(make_analysis())
        self.assertEqual(len(recommendations), 1)
        self.assertEqual(recommendations[0].key, "all_good")
        self.assertIn("No urgent issues", str(recommendations[0]))

    def test_all_good_never_appears_next_to_a_finding(self) -> None:
        for key, snapshot in TRIGGERS.items():
            if key == "all_good":
                continue
            with self.subTest(key=key):
                self.assertNotIn("all_good", keys_for(**snapshot))

    def test_a_completely_unmeasurable_pc_produces_no_invented_advice(self) -> None:
        keys = keys_for(
            cpu_percent=None,
            ram_percent=None,
            disk_free=None,
            disk_total=None,
            disk_percent=None,
            process_count=None,
            temp_size=None,
            uptime=None,
            swap_total=None,
            swap_percent=None,
            media_type=None,
        )
        # Nothing was measured, so nothing is claimed - but silence would read as a clean
        # bill of health, which is why the disclosure replaces "all_good" here.
        self.assertEqual(keys, ["incomplete_data"])


class SeverityTests(unittest.TestCase):
    def severity_of(self, key: str, **kwargs: object) -> str:
        return only(make_analysis(**kwargs), key).severity

    def test_severity_escalates_with_the_measurement(self) -> None:
        cases = (
            ("high_cpu", {"cpu_percent": 75}, "warning", {"cpu_percent": 90}, "critical"),
            ("high_ram", {"ram_percent": 85}, "warning", {"ram_percent": 95}, "critical"),
            ("high_swap", {"swap_percent": 80}, "warning", {"swap_percent": 95}, "critical"),
            ("low_disk", {"disk_free": 15 * GIB}, "warning", {"disk_free": 5 * GIB}, "critical"),
            (
                "disk_nearly_full",
                {"disk_free": 300 * GIB, "disk_total": 4000 * GIB},
                "warning",
                {"disk_free": 100 * GIB, "disk_total": 4000 * GIB},
                "critical",
            ),
            ("many_startup_items", {"startup_count": 15}, "info", {"startup_count": 25}, "warning"),
            (
                "low_battery",
                {"battery_percent": 20.0, "battery_plugged": False},
                "info",
                {"battery_percent": 10.0, "battery_plugged": False},
                "warning",
            ),
        )
        for key, mild, mild_severity, harsh, harsh_severity in cases:
            with self.subTest(key=key):
                self.assertEqual(self.severity_of(key, **mild), mild_severity)
                self.assertEqual(self.severity_of(key, **harsh), harsh_severity)

    def test_advice_is_ordered_worst_first_then_by_category_and_key(self) -> None:
        data = make_analysis(
            cpu_percent=95,  # critical
            temp_size=5 * GIB,  # warning
            uptime=30 * HOUR,  # info
            process_count=160,  # info
        )
        recommendations = generate_recommendations(data)
        order = [
            (-severity_rank(item.severity), item.category, item.key) for item in recommendations
        ]
        self.assertEqual(order, sorted(order))
        self.assertEqual(recommendations[0].key, "high_cpu")

    def test_advice_is_reproducible(self) -> None:
        data = make_analysis(cpu_percent=95, ram_percent=85, disk_free=4 * GIB, uptime=100 * HOUR)
        self.assertEqual(generate_recommendations(data), generate_recommendations(data))


class ThresholdBehaviourTests(unittest.TestCase):
    def test_quiet_below_every_threshold(self) -> None:
        # Every value sits exactly on the *mild* tier of its rule, and the table compares
        # with ">", so nothing fires on either side. These used to be the standard
        # thresholds, which the mild tiers had long since started charging for: the snapshot
        # lost 18 points and was still told "no urgent issues were detected".
        quiet = {
            "cpu_percent": 55,
            "ram_percent": 70,
            "swap_percent": 50,
            "process_count": 150,
            "temp_size": GIB,
            "uptime": 24 * HOUR,
            "startup_count": 11,
        }
        self.assertEqual(keys_for(**quiet), ["all_good"])
        # "all_good" may only ever be said about a snapshot that really lost nothing.
        self.assertEqual(calculate_health_details(make_analysis(**quiet)).deductions, ())

    def test_the_softer_variant_gives_way_to_the_stronger_one(self) -> None:
        for softer, stronger, snapshot in (
            ("medium_cpu", "high_cpu", {"cpu_percent": 75}),
            ("medium_ram", "high_ram", {"ram_percent": 85}),
            ("medium_swap", "high_swap", {"swap_percent": 80}),
            ("some_processes", "many_processes", {"process_count": 200}),
            ("medium_temp", "large_temp", {"temp_size": 5 * GIB}),
            ("medium_uptime", "long_uptime", {"uptime": 72 * HOUR}),
        ):
            with self.subTest(key=stronger):
                keys = keys_for(**snapshot)
                self.assertIn(stronger, keys)
                self.assertNotIn(softer, keys)

    def test_low_disk_and_nearly_full_are_never_said_together(self) -> None:
        keys = keys_for(disk_free=3 * GIB, disk_total=512 * GIB)
        self.assertIn("low_disk", keys)
        self.assertNotIn("disk_nearly_full", keys)

    def test_a_tiny_page_file_is_never_mentioned(self) -> None:
        for swap_total in (None, 256 * 1024**2):
            with self.subTest(swap_total=swap_total):
                self.assertNotIn("high_swap", keys_for(swap_total=swap_total, swap_percent=99.0))

    def test_a_charging_battery_is_not_a_finding(self) -> None:
        for plugged in (True, None):
            with self.subTest(plugged_in=plugged):
                keys = keys_for(battery_percent=4.0, battery_plugged=plugged)
                self.assertNotIn("low_battery", keys)

    def test_an_ssd_never_triggers_the_upgrade_advice(self) -> None:
        for media_type in ("SSD", None, "", "nvme"):
            with self.subTest(media_type=media_type):
                self.assertNotIn("hdd_system_drive", keys_for(media_type=media_type))

    def test_startup_advice_starts_one_entry_before_the_penalty(self) -> None:
        # Reviewing the startup list is free, so the advice appears at 12 while the score
        # only starts deducting above 12.
        self.assertNotIn("many_startup_items", keys_for(startup_count=11))
        self.assertIn("many_startup_items", keys_for(startup_count=12))


class StoragePartitionTests(unittest.TestCase):
    def test_the_analysed_drive_wins_over_a_flagged_partition(self) -> None:
        # data.disk is the drive the snapshot is about, even when another partition carries
        # the is_system flag. The score reads the same record, so both sides describe D:.
        data = make_analysis(
            drive="D:\\",
            disk_free=3 * GIB,
            disk_total=512 * GIB,
            disk_is_system=False,
            partitions=(
                make_partition("C:\\", total=1024 * GIB, free=700 * GIB, is_system=True),
                make_partition("D:\\", total=512 * GIB, free=3 * GIB),
            ),
        )
        found = only(data, "low_disk")
        self.assertEqual(found.values["drive"], "D:")
        self.assertEqual(found.severity, "critical")

    def test_the_drive_label_is_carried_into_the_text(self) -> None:
        found = only(make_analysis(disk_free=3 * GIB, drive="E:\\"), "low_disk")
        self.assertEqual(found.values["drive"], "E:")
        self.assertIn("E:", found.text)
        self.assertEqual(found.category, CATEGORY_STORAGE)

    def test_a_rotating_system_drive_is_reported_once(self) -> None:
        data = make_analysis(media_type="hdd")  # Case is normalised before comparing.
        keys = [item.key for item in generate_recommendations(data)]
        self.assertEqual(keys.count("hdd_system_drive"), 1)


class TopProcessTests(unittest.TestCase):
    def test_a_clear_memory_leader_is_named_with_its_size(self) -> None:
        data = make_analysis(
            top_processes=(
                make_process(1, "chrome.exe", memory_bytes=4 * GIB, memory_percent=25.0),
                make_process(2, "explorer.exe", memory_bytes=GIB // 4, memory_percent=1.5),
            )
        )
        found = only(data, "top_memory_process")
        self.assertEqual(found.values["name"], "chrome.exe")
        self.assertEqual(found.values["value"], "4.0 GB")
        self.assertEqual(found.category, CATEGORY_MEMORY)

    def test_no_leader_means_no_advice(self) -> None:
        data = make_analysis(
            top_processes=(
                make_process(1, "a.exe", memory_bytes=GIB, memory_percent=TOP_MEMORY_PERCENT),
                make_process(
                    2, "b.exe", memory_bytes=GIB, memory_percent=5.0, cpu_percent=TOP_CPU_PERCENT
                ),
            )
        )
        keys = [item.key for item in generate_recommendations(data)]
        self.assertNotIn("top_memory_process", keys)
        self.assertNotIn("top_cpu_process", keys)

    def test_an_empty_process_list_says_nothing(self) -> None:
        keys = keys_for(top_processes=())
        self.assertNotIn("top_memory_process", keys)
        self.assertNotIn("top_cpu_process", keys)

    def test_the_share_is_derived_when_psutil_did_not_report_one(self) -> None:
        data = make_analysis(
            ram_total=16 * GIB,
            top_processes=(make_process(1, "vm.exe", memory_bytes=6 * GIB, memory_percent=None),),
        )
        found = only(data, "top_memory_process")
        self.assertEqual(found.values["name"], "vm.exe")

    def test_an_unmeasurable_process_is_never_named(self) -> None:
        data = make_analysis(
            ram_total=None,
            ram_percent=None,
            top_processes=(make_process(1, "ghost.exe", memory_bytes=None, memory_percent=None),),
        )
        keys = [item.key for item in generate_recommendations(data)]
        self.assertNotIn("top_memory_process", keys)

    def test_ties_are_broken_by_name_so_output_is_deterministic(self) -> None:
        data = make_analysis(
            top_processes=(
                make_process(9, "zeta.exe", memory_bytes=2 * GIB, memory_percent=30.0),
                make_process(8, "alpha.exe", memory_bytes=2 * GIB, memory_percent=30.0),
            )
        )
        found = only(data, "top_memory_process")
        self.assertEqual(found.values["name"], "alpha.exe")

    def test_a_busy_process_reports_a_clamped_percentage(self) -> None:
        data = make_analysis(
            top_processes=(make_process(1, "render.exe", memory_bytes=GIB, cpu_percent=180.0),)
        )
        found = only(data, "top_cpu_process")
        self.assertEqual(found.values["value"], "100%")
        self.assertEqual(found.category, CATEGORY_CPU)


class WarningDisclosureTests(unittest.TestCase):
    def test_warnings_are_disclosed(self) -> None:
        recommendations = generate_recommendations(
            make_analysis(warnings=("Disk information could not be collected",))
        )
        self.assertTrue(any("unavailable" in str(item) for item in recommendations))
        self.assertIn("incomplete_data", [item.key for item in recommendations])

    def test_the_disclosure_accompanies_the_findings_instead_of_replacing_them(self) -> None:
        keys = keys_for(cpu_percent=95, warnings=("RAM information could not be collected",))
        self.assertIn("incomplete_data", keys)
        self.assertIn("high_cpu", keys)
        self.assertNotIn("all_good", keys)

    def test_no_warnings_means_no_disclosure(self) -> None:
        self.assertNotIn("incomplete_data", keys_for(cpu_percent=95))


class ScoreParityTests(unittest.TestCase):
    """A run may never deduct points for a problem its own advice then fails to mention.

    The pairing is asserted for the tiers the advice engine reacts to. The score's ``mild``
    tier deliberately fires earlier, as an early warning at info level, and has no matching
    sentence; every tier from ``standard`` upwards must be explained.
    """

    #: Snapshots whose union fires every deduction key the score table can produce.
    SNAPSHOTS: tuple[tuple[str, dict[str, object]], ...] = (
        (
            "everything at once",
            {
                "cpu_percent": 99,
                "ram_percent": 99,
                "swap_percent": 99,
                "disk_free": GIB,
                "process_count": 999,
                "temp_size": 99 * GIB,
                "uptime": 999 * HOUR,
                "startup_count": 40,
                "battery_percent": 2.0,
                "battery_plugged": False,
            },
        ),
        # A drive too large for the free-bytes rule, so only the percentage rule talks.
        ("nearly full drive", {"disk_free": 100 * GIB, "disk_total": 4000 * GIB}),
        # v2.1 state, every rule of it at once: an unguarded PC, a firewall with a profile
        # switched off, definitions a month old, a restart owed, a drive that raised its own
        # warning while nearly worn out, and a pack down to 40 % of its design capacity.
        (
            "everything durable at once",
            {
                "security": make_security(
                    antivirus=STATE_BAD,
                    firewall=STATE_BAD,
                    secure_boot=STATE_WEAK,
                    reboot_pending=True,
                    signature_age_days=45,
                ),
                "drive_health": (make_drive(percentage_used=95, critical_warning=True),),
                "battery_health": 40.0,
            },
        ),
    )

    def parity(self, data: AnalysisData) -> tuple[set[str], set[str]]:
        deducted = {item.key for item in calculate_health_details(data).deductions}
        advised = {item.key for item in generate_recommendations(data)}
        self.assertTrue(deducted, "a snapshot that charges nothing proves nothing")
        return deducted, advised

    def test_every_deduction_key_is_explained_by_a_recommendation(self) -> None:
        covered: set[str] = set()
        for label, snapshot in self.SNAPSHOTS:
            with self.subTest(snapshot=label):
                deducted, advised = self.parity(make_analysis(**snapshot))
                self.assertEqual(deducted - advised, set())
                covered |= deducted
        # Proof that the snapshots above really do exercise the whole table.
        self.assertEqual(covered, DEDUCTION_KEYS)

    def test_a_full_secondary_drive_is_penalised_and_advised_on_together(self) -> None:
        # The regression this class exists for: analyze_pc(drive="D:\\") once deducted 32
        # points for a full D: while the advice engine looked at the is_system partition,
        # found C: healthy, and reported "all_good" in the very same report.
        data = make_analysis(
            drive="D:\\",
            disk_free=3 * GIB,
            disk_total=512 * GIB,
            disk_is_system=False,
            partitions=(make_partition("C:\\", total=1024 * GIB, free=700 * GIB, is_system=True),),
        )
        deducted, advised = self.parity(data)
        self.assertEqual(deducted, {"low_disk"})
        self.assertEqual(deducted - advised, set())
        self.assertNotIn("all_good", advised)

        # Both sides must also name the same drive, not just the same problem.
        charged = next(item for item in calculate_health_details(data).deductions)
        self.assertEqual(charged.values["drive"], "D:")
        self.assertEqual(only(data, "low_disk").values["drive"], "D:")

    def test_drive_findings_carry_both_the_drive_and_the_measurement(self) -> None:
        cases = (
            ("low_disk", {"disk_free": 3 * GIB}),
            ("disk_nearly_full", {"disk_free": 100 * GIB, "disk_total": 4000 * GIB}),
            ("hdd_system_drive", {"media_type": "HDD"}),
        )
        for key, snapshot in cases:
            with self.subTest(key=key):
                data = make_analysis(drive="D:\\", **snapshot)
                found = only(data, key)
                self.assertEqual(tuple(name for name, _ in found.params), ("drive", "value"))
                self.assertEqual(found.values["drive"], "D:")
                self.assertTrue(found.values["value"].strip())


class DriveAuthorityTests(unittest.TestCase):
    """``data.disk`` is the one authoritative drive; the advice may not consult another one.

    The advice engine used to look up the partition flagged ``is_system`` instead. On a
    snapshot taken about a data drive that produced a report which charged points for a full
    D:, found C: perfectly healthy, and then announced that nothing was wrong.
    """

    def snapshots(self) -> tuple[tuple[str, AnalysisData], ...]:
        return tuple(
            (label, foreign_drive(**overrides)) for label, overrides in FOREIGN_DRIVE_SNAPSHOTS
        )

    def test_the_analysed_drive_is_the_one_every_finding_talks_about(self) -> None:
        for label, data in self.snapshots():
            expected = data.disk.drive.rstrip("\\/")
            for item in generate_recommendations(data):
                if "drive" not in item.values:
                    continue
                with self.subTest(snapshot=label, key=item.key):
                    self.assertEqual(item.values["drive"], expected)
                    self.assertIn(expected, item.text)

    def test_no_deduction_is_ever_left_without_matching_advice(self) -> None:
        for label, data in self.snapshots():
            with self.subTest(snapshot=label):
                deducted = {item.key for item in calculate_health_details(data).deductions}
                advised = {item.key for item in generate_recommendations(data)}
                self.assertEqual(unexplained(deducted, advised), set())

    def test_a_penalised_snapshot_is_never_declared_healthy(self) -> None:
        for label, data in self.snapshots():
            with self.subTest(snapshot=label):
                advised = [item.key for item in generate_recommendations(data)]
                self.assertNotIn("all_good", advised)
                self.assertTrue(advised)

    def test_the_healthy_system_partition_is_never_quoted_instead(self) -> None:
        for label, data in self.snapshots():
            with self.subTest(snapshot=label):
                for item in generate_recommendations(data):
                    self.assertNotEqual(item.values.get("drive"), "C:")

    def test_the_score_and_the_advice_read_the_same_record(self) -> None:
        # Both sides are asked for the drive they used; a disagreement here is the bug.
        for label, data in self.snapshots():
            with self.subTest(snapshot=label):
                charged = [
                    item
                    for item in calculate_health_details(data).deductions
                    if "drive" in item.values
                ]
                advised = [
                    item for item in generate_recommendations(data) if "drive" in item.values
                ]
                drives = {item.values["drive"] for item in [*charged, *advised]}
                self.assertEqual(drives, {data.disk.drive.rstrip("\\/")})


class DeductionAdviceInvariantTests(unittest.TestCase):
    """The general property: a run may never charge for something it does not explain."""

    def snapshots(self) -> tuple[tuple[str, AnalysisData], ...]:
        cases = [(f"trigger {key}", make_analysis(**fields)) for key, fields in TRIGGERS.items()]
        cases.extend(
            (f"foreign drive: {label}", foreign_drive(**overrides))
            for label, overrides in FOREIGN_DRIVE_SNAPSHOTS
        )
        cases.append(
            (
                "everything at once",
                make_analysis(
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
                    media_type="HDD",
                ),
            )
        )
        cases.append(("nothing measurable", make_analysis(
            cpu_percent=None,
            ram_percent=None,
            disk_free=None,
            process_count=None,
            temp_size=None,
            uptime=None,
            swap_total=None,
            swap_percent=None,
        )))
        cases.append(("truncated temp scan", make_analysis(temp_size=5 * GIB,
                                                           temp_truncated=True)))
        return tuple(cases)

    def test_every_deduction_key_is_matched_by_a_recommendation_key(self) -> None:
        for label, data in self.snapshots():
            with self.subTest(snapshot=label):
                deducted = {item.key for item in calculate_health_details(data).deductions}
                advised = {item.key for item in generate_recommendations(data)}
                self.assertEqual(unexplained(deducted, advised), set())

    def test_all_good_can_never_appear_next_to_a_deduction(self) -> None:
        for label, data in self.snapshots():
            with self.subTest(snapshot=label):
                deducted = calculate_health_details(data).deductions
                advised = [item.key for item in generate_recommendations(data)]
                if deducted:
                    self.assertNotIn("all_good", advised)

    def test_all_good_is_the_only_thing_said_when_it_is_said(self) -> None:
        # It is the fallback for "nothing else fired", so it can never share a report.
        for label, data in self.snapshots():
            advised = [item.key for item in generate_recommendations(data)]
            if "all_good" in advised:
                with self.subTest(snapshot=label):
                    self.assertEqual(advised, ["all_good"])
                    self.assertEqual(calculate_health_details(data).deductions, ())

    def test_advice_is_never_empty(self) -> None:
        for label, data in self.snapshots():
            with self.subTest(snapshot=label):
                self.assertTrue(generate_recommendations(data))


class DeductionAdviceGridTests(unittest.TestCase):
    """The invariant as an absolute, swept over a grid instead of one snapshot per key.

    Until v2.0 the mild tiers of high_cpu, high_ram and high_swap deducted points while the
    advice stayed silent, so a real report printed "- 8 points: RAM usage is high (72%)" and
    then "No urgent issues were detected" three lines further down. One snapshot per key
    cannot catch that class of defect once the keys interact, hence the grid: every
    combination has to satisfy the same three statements.
    """

    #: One value per tier of each rule, quiet value first. Sweeping the product of these
    #: covers every combination of tiers the three rules can be in at once.
    LOAD_GRID: tuple[tuple[str, tuple[object, ...]], ...] = (
        ("cpu_percent", (20, 60, 75, 97)),
        ("ram_percent", (40, 72, 85, 96)),
        ("swap_percent", (10, 60, 80, 95)),
        ("temp_size", (GIB // 2, 2 * GIB, 5 * GIB)),
    )

    #: The same idea for the rules that do not share a category, so the sweep still reaches
    #: every tier of every rule without a nine-dimensional product. 60 GB and 49 GB free of
    #: the fixture's 512 GB drive are the mild tier of low_disk, which deducted in silence
    #: until "medium_disk" was added; they stay in the grid to keep it that way.
    HOUSEKEEPING_GRID: tuple[tuple[str, tuple[object, ...]], ...] = (
        ("disk_free", (100 * GIB, 60 * GIB, 49 * GIB, 30 * GIB, 15 * GIB, 4 * GIB)),
        ("process_count", (100, 160, 200, 400)),
        ("uptime", (HOUR, 30 * HOUR, 72 * HOUR, 400 * HOUR)),
        ("startup_count", (0, 15, 25)),
    )

    #: The v2.1 rules, which react to durable state rather than to a load figure. The first
    #: value on every axis is "nobody looked", the second is a machine that answered and is
    #: fine - two cases the load grids cannot express and that must both stay silent.
    STATE_GRID: tuple[tuple[str, tuple[object, ...]], ...] = (
        (
            "security",
            (
                None,
                make_security(),
                make_security(antivirus=STATE_WEAK, signature_age_days=10),
                make_security(
                    antivirus=STATE_BAD,
                    firewall=STATE_BAD,
                    secure_boot=STATE_WEAK,
                    reboot_pending=True,
                    signature_age_days=45,
                ),
            ),
        ),
        (
            "drive_health",
            (
                (),
                (make_drive(),),
                (make_drive(percentage_used=75),),
                (make_drive(percentage_used=95, critical_warning=True),),
            ),
        ),
        ("battery_health", (None, 95.0, 65.0, 40.0)),
    )

    def grid(self) -> list[tuple[str, AnalysisData]]:
        """Every combination of all three grids, labelled by the values that produced it."""
        cases: list[tuple[str, AnalysisData]] = []
        for axes in (self.LOAD_GRID, self.HOUSEKEEPING_GRID, self.STATE_GRID):
            names = [name for name, _ in axes]
            for values in itertools.product(*(values for _, values in axes)):
                fields = dict(zip(names, values))
                label = ", ".join(f"{name}={value}" for name, value in fields.items())
                cases.append((label, make_analysis(**fields)))  # type: ignore[arg-type]
        return cases

    def test_the_grid_is_wide_enough_to_be_worth_running(self) -> None:
        # A grid that quietly collapsed to a handful of snapshots would pass everything.
        cases = self.grid()
        self.assertGreater(len(cases), 400)
        fired = {
            item.key for _, data in cases for item in calculate_health_details(data).deductions
        }
        # low_battery needs a machine shape rather than a value, so it is covered by
        # DeductionAdviceInvariantTests; every other rule fires somewhere inside the grid.
        self.assertEqual(fired, DEDUCTION_KEYS - {"low_battery"})

    def test_no_deduction_is_ever_charged_without_advice_covering_it(self) -> None:
        for label, data in self.grid():
            deducted = {item.key for item in calculate_health_details(data).deductions}
            advised = {item.key for item in generate_recommendations(data)}
            with self.subTest(snapshot=label):
                self.assertEqual(unexplained(deducted, advised), set())

    def test_the_covering_advice_quotes_the_same_measurement(self) -> None:
        # "Covering the same condition" has to mean the same number, not merely a related
        # key: a deduction that says 72% next to advice that says 40% explains nothing.
        for label, data in self.grid():
            advice = {item.key: item for item in generate_recommendations(data)}
            for item in calculate_health_details(data).deductions:
                cover = advice.get(item.key) or advice.get(SOFTER_VARIANT.get(item.key, ""))
                with self.subTest(snapshot=label, key=item.key):
                    self.assertIsNotNone(cover)
                    assert cover is not None
                    if "value" in item.values:
                        self.assertEqual(cover.values.get("value"), item.values["value"])

    def test_all_good_is_only_ever_said_alone(self) -> None:
        for label, data in self.grid():
            advised = [item.key for item in generate_recommendations(data)]
            if "all_good" not in advised:
                continue
            with self.subTest(snapshot=label):
                self.assertEqual(advised, ["all_good"])
                self.assertEqual(calculate_health_details(data).deductions, ())

    def test_a_snapshot_that_lost_points_never_hears_that_nothing_is_wrong(self) -> None:
        for label, data in self.grid():
            assessment = calculate_health_details(data)
            if assessment.score == 100:
                continue
            with self.subTest(snapshot=label, score=assessment.score):
                self.assertNotIn("all_good", [item.key for item in generate_recommendations(data)])

    def test_advice_is_never_empty_anywhere_in_the_grid(self) -> None:
        for label, data in self.grid():
            with self.subTest(snapshot=label):
                self.assertTrue(generate_recommendations(data))

    #: Every mild tier that used to deduct in silence, with the points it charges and the key
    #: that now explains it. The first three are the ones P1 named; the two storage rows were
    #: the same defect one layer down, found by the grid above and closed the same way.
    SILENT_DEDUCTIONS: tuple[tuple[str, dict[str, object], str, int, str], ...] = (
        ("high_cpu", {"cpu_percent": 60}, "medium_cpu", 6, "60%"),
        ("high_ram", {"ram_percent": 72}, "medium_ram", 8, "72%"),
        ("high_swap", {"swap_percent": 60}, "medium_swap", 4, "60%"),
        ("low_disk", {"disk_free": 49 * GIB}, "medium_disk", 8, "49.0 GB"),
        (
            "disk_nearly_full",
            {"disk_free": 480 * GIB, "disk_total": 4000 * GIB},
            "medium_disk_full",
            5,
            "88%",
        ),
    )

    def test_each_formerly_silent_mild_tier_now_explains_itself(self) -> None:
        for key, snapshot, advice_key, expected_points, measurement in self.SILENT_DEDUCTIONS:
            with self.subTest(key=key):
                data = make_analysis(**snapshot)  # type: ignore[arg-type]
                charged = [
                    item for item in calculate_health_details(data).deductions if item.key == key
                ]
                self.assertEqual(len(charged), 1)
                self.assertEqual(charged[0].points, expected_points)
                self.assertEqual(charged[0].values["value"], measurement)

                covering = only(data, advice_key)
                self.assertEqual(covering.severity, "info")
                self.assertEqual(covering.values["value"], measurement)
                self.assertIn(measurement, covering.text)
                self.assertNotIn("all_good", [item.key for item in generate_recommendations(data)])

    def test_the_three_mild_tiers_together_still_explain_every_point(self) -> None:
        data = make_analysis(cpu_percent=60, ram_percent=72, swap_percent=60)
        assessment = calculate_health_details(data)
        advised = [item.key for item in generate_recommendations(data)]
        self.assertEqual(assessment.total_deduction, 18)  # 6 + 8 + 4, exactly as before.
        self.assertEqual(assessment.score, 82)
        for key in ("medium_cpu", "medium_ram", "medium_swap"):
            with self.subTest(key=key):
                self.assertIn(key, advised)
        self.assertNotIn("all_good", advised)


class IncompleteDataDisclosureTests(unittest.TestCase):
    """``incomplete_data`` fires exactly when the score calls the snapshot incomplete."""

    CASES: tuple[tuple[str, dict[str, object]], ...] = (
        ("fully measured, no warnings", {}),
        ("warning-free but a reading is missing", {"cpu_percent": None}),
        ("warning-free but the TEMP scan was cut short", {"temp_truncated": True}),
        ("complete but a collector complained", {"warnings": ("GPU list failed",)}),
        (
            "both incomplete and warned",
            {"uptime": None, "warnings": ("Uptime could not be collected: denied",)},
        ),
    )

    def test_the_disclosure_follows_the_single_definition(self) -> None:
        for label, overrides in self.CASES:
            with self.subTest(case=label):
                data = make_analysis(**overrides)
                expected = bool(data.warnings) or not required_values_present(data)
                fired = "incomplete_data" in [
                    item.key for item in generate_recommendations(data)
                ]
                self.assertEqual(fired, expected)

    def test_a_silent_gap_is_disclosed_just_like_a_loud_one(self) -> None:
        # A collector that failed with a warning and one that quietly returned nothing look
        # identical to a reader, so both have to disclose.
        silent = make_analysis(process_count=None)
        loud = make_analysis(warnings=("Running processes could not be counted: denied",))
        self.assertEqual(silent.warnings, ())
        self.assertTrue(required_values_present(loud))
        for data in (silent, loud):
            with self.subTest(warnings=data.warnings):
                self.assertIn("incomplete_data", [i.key for i in generate_recommendations(data)])

    def test_a_truncated_temp_scan_alone_is_enough_to_disclose(self) -> None:
        # Hard-coded rather than derived from the predicate, so a change to the definition
        # of "incomplete" cannot make this test agree with itself.
        data = make_analysis(temp_size=5 * GIB, temp_truncated=True)
        self.assertEqual(data.warnings, ())
        self.assertIn("incomplete_data", [item.key for item in generate_recommendations(data)])

    def test_the_disclosure_matches_the_assessment_flag(self) -> None:
        for label, overrides in self.CASES:
            with self.subTest(case=label):
                data = make_analysis(**overrides)
                fired = "incomplete_data" in [i.key for i in generate_recommendations(data)]
                if not data.warnings:
                    # Without warnings the two must agree exactly; a warning can only add.
                    self.assertEqual(fired, not calculate_health_details(data).data_complete)


class TruncatedTempTests(unittest.TestCase):
    """A TEMP scan that ran out of time reports a floor, and must say so."""

    def truncated(self, **overrides: object) -> AnalysisData:
        return replace(make_analysis(temp_size=5 * GIB, **overrides), temp_truncated=True)

    def test_the_deduction_states_a_lower_bound(self) -> None:
        charged = next(
            item
            for item in calculate_health_details(self.truncated()).deductions
            if item.key == "large_temp"
        )
        self.assertEqual(charged.points, 10)  # The tier selection is unchanged.
        # The params carry the plain measurement plus a language-neutral marker; the English
        # qualifier appears only in the producer's own fallback sentence.
        self.assertEqual(charged.values["value"], "5.0 GB")
        self.assertEqual(charged.values["bound"], "lower")
        self.assertIn("at least 5.0 GB", charged.reason)

    def test_the_temp_advice_is_bounded_exactly_like_the_deduction(self) -> None:
        # One run may not state the same measurement two ways: the advice used to quote the
        # truncated size as an exact total while the deduction called it a floor.
        for size, key in ((5 * GIB, "large_temp"), (2 * GIB, "medium_temp")):
            with self.subTest(key=key):
                advice = only(replace(make_analysis(temp_size=size), temp_truncated=True), key)
                self.assertEqual(advice.values["bound"], "lower")
                self.assertEqual(advice.values["value"], format_bytes(size))
                self.assertIn(f"at least {format_bytes(size)}", advice.text)

    def test_an_untruncated_scan_leaves_the_advice_unqualified(self) -> None:
        for size, key in ((5 * GIB, "large_temp"), (2 * GIB, "medium_temp")):
            with self.subTest(key=key):
                advice = only(make_analysis(temp_size=size), key)
                self.assertNotIn("bound", advice.values)
                self.assertNotIn("at least", advice.text)

    def test_a_truncated_scan_makes_the_snapshot_incomplete(self) -> None:
        data = self.truncated()
        self.assertFalse(required_values_present(data))
        self.assertFalse(calculate_health_details(data).data_complete)
        self.assertIn("incomplete_data", [item.key for item in generate_recommendations(data)])

    def test_an_untruncated_scan_still_quotes_the_exact_size(self) -> None:
        data = make_analysis(temp_size=5 * GIB)
        charged = next(
            item for item in calculate_health_details(data).deductions if item.key == "large_temp"
        )
        self.assertEqual(charged.values["value"], "5.0 GB")
        self.assertTrue(required_values_present(data))


class ActionUriTests(unittest.TestCase):
    """The settings page a piece of advice is about: a pointer, never an action.

    Three things are asserted, and each of them has a way of going quietly wrong. The page
    has to be a Windows settings page and nothing else, or the button in the window becomes a
    launcher for whatever the string happens to name. Every producer has to take it from the
    one table, or two pieces of advice about the same setting can point at different pages.
    And the advice that deliberately has no page must carry None rather than a plausible
    guess - a wrong page is worse than none, because the user follows it and finds nothing.
    """

    #: Duplicated from the module on purpose: this is the agreed mapping, so a key that
    #: quietly gains or loses its page has to be an edit here as well.
    EXPECTED_ACTIONS: dict[str, str] = {
        "antivirus_off": "ms-settings:windowsdefender",
        "firewall_off": "ms-settings:windowsdefender",
        "stale_signatures": "ms-settings:windowsdefender",
        "reboot_pending": "ms-settings:windowsupdate",
        "battery_worn": "ms-settings:batterysaver",
        "many_startup_items": "ms-settings:startupapps",
        "low_disk": "ms-settings:storagesense",
        "disk_nearly_full": "ms-settings:storagesense",
        "large_temp": "ms-settings:storagesense",
        "medium_temp": "ms-settings:storagesense",
        "large_folder": "ms-settings:storagesense",
    }

    #: Advice that must carry no page at all, and why. Secure Boot's switch lives in the
    #: firmware, and no settings page anywhere changes a drive's wear.
    EXPECTED_NONE: frozenset[str] = frozenset(
        {"secure_boot_off", "drive_worn", "drive_failing", "all_good", "incomplete_data"}
    )

    def test_the_table_is_exactly_the_agreed_mapping(self) -> None:
        self.assertEqual(RECOMMENDATION_ACTIONS, self.EXPECTED_ACTIONS)

    def test_every_page_is_a_windows_settings_page(self) -> None:
        for key, uri in RECOMMENDATION_ACTIONS.items():
            with self.subTest(key=key):
                self.assertTrue(uri.startswith("ms-settings:"))
                # No space, no quote, no second scheme: the window refuses those anyway, and
                # advice must never produce a string it would have to refuse.
                self.assertEqual(uri, uri.strip())
                self.assertNotIn(" ", uri)
                self.assertRegex(uri, r"^ms-settings:[a-z0-9-]+$")

    def test_every_page_belongs_to_a_key_that_exists(self) -> None:
        self.assertLessEqual(set(RECOMMENDATION_ACTIONS), RECOMMENDATION_KEYS)
        self.assertLessEqual(set(RECOMMENDATION_ACTIONS), set(RECOMMENDATION_TEMPLATES))

    def test_the_advice_that_should_have_no_page_carries_none(self) -> None:
        for key in self.EXPECTED_NONE:
            with self.subTest(key=key):
                self.assertNotIn(key, RECOMMENDATION_ACTIONS)
                data = make_analysis(**TRIGGERS[key])  # type: ignore[arg-type]
                self.assertIsNone(only(data, key).action_uri)

    def test_generated_advice_carries_the_page_from_the_table(self) -> None:
        for key, uri in self.EXPECTED_ACTIONS.items():
            with self.subTest(key=key):
                data = make_analysis(**TRIGGERS[key])  # type: ignore[arg-type]
                self.assertEqual(only(data, key).action_uri, uri)

    def test_no_producer_invents_a_page_of_its_own(self) -> None:
        # Swept over every trigger, so a key that started attaching its own URI somewhere
        # other than the table is caught wherever it fires.
        for label, snapshot in TRIGGERS.items():
            advice = generate_recommendations(make_analysis(**snapshot))  # type: ignore[arg-type]
            for item in advice:
                with self.subTest(trigger=label, key=item.key):
                    self.assertEqual(item.action_uri, RECOMMENDATION_ACTIONS.get(item.key))

    def test_a_page_is_never_an_empty_string(self) -> None:
        # "" would render as a link to nowhere and pass a naive truthiness check.
        for label, snapshot in TRIGGERS.items():
            advice = generate_recommendations(make_analysis(**snapshot))  # type: ignore[arg-type]
            for item in advice:
                with self.subTest(trigger=label, key=item.key):
                    self.assertNotEqual(item.action_uri, "")
                    self.assertTrue(item.action_uri is None or item.action_uri.strip())

    def test_the_page_never_ends_up_inside_the_sentence(self) -> None:
        # It is machine-readable data for the interface, not something a reader should see.
        for label, snapshot in TRIGGERS.items():
            advice = generate_recommendations(make_analysis(**snapshot))  # type: ignore[arg-type]
            for item in advice:
                with self.subTest(trigger=label, key=item.key):
                    self.assertNotIn("ms-settings", item.text)
        for key, template in RECOMMENDATION_TEMPLATES.items():
            with self.subTest(key=key):
                self.assertNotIn("ms-settings", template)

    def test_the_advice_engine_never_opens_anything(self) -> None:
        # The URI is a pointer. Nothing in this module may launch it, at any point.
        with open(recommendations.__file__, "r", encoding="utf-8") as handle:
            source = handle.read()
        for forbidden in ("startfile", "subprocess", "os.system", "webbrowser", "ShellExecute"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


class AdviceSafetyTests(unittest.TestCase):
    """The advice must never tell a user to do something destructive."""

    FORBIDDEN = ("delete", "remove", "disable defender", "uninstall windows", "regedit", "format")

    def test_no_template_suggests_a_destructive_action(self) -> None:
        for key, template in RECOMMENDATION_TEMPLATES.items():
            lowered = template.lower()
            for phrase in self.FORBIDDEN:
                with self.subTest(key=key, phrase=phrase):
                    self.assertNotIn(phrase, lowered)


if __name__ == "__main__":
    unittest.main()
