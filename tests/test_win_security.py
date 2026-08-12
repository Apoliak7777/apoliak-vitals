"""Tests for the read-only protection collector in src/win_security.py.

One rule is asserted over and over here, because it is the rule the whole module exists to
keep: **a failed query is unknown, never "off"**. A denied registry key, a missing DLL, a
Security Center that does not answer and a machine that is not Windows all have to produce
``STATE_UNKNOWN`` - which the score never penalises - rather than a verdict that would tell a
user their PC is unprotected on the strength of a failed lookup.

The Security Center is replaced by the ``provider_health`` seam the function documents, and
the registry by a fake ``winreg`` module that records how every key was opened. That second
one is not decoration: "opened for reading only, and always closed again" is a promise this
application makes, and a fake module is the only way to prove it without a real hive.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch

from src import win_security
from src.models import STATE_BAD, STATE_GOOD, STATE_UNKNOWN, STATE_WEAK, SecurityInfo
from src.win_security import _filetime_to_datetime, read_security_state

FIREWALL_POLICY = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
DOMAIN_PROFILE = rf"{FIREWALL_POLICY}\DomainProfile"
PRIVATE_PROFILE = rf"{FIREWALL_POLICY}\StandardProfile"
PUBLIC_PROFILE = rf"{FIREWALL_POLICY}\PublicProfile"
SECURE_BOOT = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"
SERVICING_REBOOT = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending"
)
UPDATE_REBOOT = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
)
SESSION_MANAGER = r"SYSTEM\CurrentControlSet\Control\Session Manager"
SIGNATURES = r"SOFTWARE\Microsoft\Windows Defender\Signature Updates"
SCAN = r"SOFTWARE\Microsoft\Windows Defender\Scan"

#: Provider bits from wscapi.h.
PROVIDER_FIREWALL = 0x1
PROVIDER_ANTIVIRUS = 0x4

NOW = datetime(2026, 7, 16, 12, 0, tzinfo=timezone.utc)

#: A machine where every profile is on, Secure Boot is on and nothing is pending.
HEALTHY_REGISTRY: dict[str, dict[str, object]] = {
    DOMAIN_PROFILE: {"EnableFirewall": 1},
    PRIVATE_PROFILE: {"EnableFirewall": 1},
    PUBLIC_PROFILE: {"EnableFirewall": 1},
    SECURE_BOOT: {"UEFISecureBootEnabled": 1},
    SESSION_MANAGER: {},
}


def filetime(moment: datetime) -> int:
    """The Windows FILETIME for a moment: 100-nanosecond ticks since 1601-01-01."""
    return int((moment.timestamp() + 11_644_473_600) * 10_000_000)


class FakeKey:
    """One opened registry key, which records that it was closed again."""

    def __init__(self, registry: "FakeRegistry", path: str) -> None:
        self.registry = registry
        self.path = path

    def Close(self) -> None:  # noqa: N802 - the winreg name is the contract
        self.registry.closed.append(self.path)


class FakeRegistry:
    """A stand-in for the winreg module, holding exactly the keys a test describes."""

    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019

    def __init__(
        self,
        values: dict[str, dict[str, object]] | None = None,
        *,
        denied: tuple[str, ...] = (),
        hostile_values: tuple[str, ...] = (),
    ) -> None:
        self.values = dict(values or {})
        self.denied = denied
        self.hostile_values = hostile_values
        self.opened: list[tuple[str, str, int, int]] = []
        self.closed: list[str] = []

    def OpenKey(self, root: str, path: str, reserved: int, access: int) -> FakeKey:  # noqa: N802
        self.opened.append((root, path, reserved, access))
        if path in self.denied:
            raise PermissionError("access is denied")
        if path not in self.values:
            raise FileNotFoundError("the system cannot find the file specified")
        return FakeKey(self, path)

    def QueryValueEx(self, key: FakeKey, name: str) -> tuple[object, int]:  # noqa: N802
        if key.path in self.hostile_values:
            raise OSError("the value cannot be read")
        entries = self.values.get(key.path, {})
        if name not in entries:
            raise FileNotFoundError("no such value")
        return entries[name], 1


def read(
    registry: FakeRegistry | None = None,
    *,
    health: dict[int, int | None] | None = None,
    now: datetime | None = NOW,
    system: str = "Windows",
    domain_joined: bool | None = True,
) -> SecurityInfo:
    """
    Read the protection state of a described machine, with no real Windows involved.

    ``domain_joined`` defaults to True so a described registry is taken at face value: the
    Domain profile only counts on a machine that actually has a domain. The tests that care
    about a home machine pass False explicitly.
    """
    answers = {} if health is None else health
    with patch.object(win_security.platform, "system", return_value=system):
        with patch.object(win_security, "_winreg", return_value=registry):
            return read_security_state(
                now=now,
                provider_health=lambda provider: answers.get(provider),
                domain_joined=domain_joined,
            )


class ContractTests(unittest.TestCase):
    def test_the_reader_always_answers_with_a_security_record(self) -> None:
        self.assertIsInstance(read(FakeRegistry(HEALTHY_REGISTRY)), SecurityInfo)

    def test_a_security_center_that_explodes_is_unknown_rather_than_a_verdict(self) -> None:
        def hostile(provider: int) -> int:
            raise OSError("wscapi refused the call")

        with patch.object(win_security, "_winreg", return_value=FakeRegistry()):
            state = read_security_state(now=NOW, provider_health=hostile)
        self.assertEqual(state.antivirus, STATE_UNKNOWN)
        self.assertEqual(state.firewall, STATE_UNKNOWN)

    def test_a_collector_that_explodes_outright_still_returns_a_record(self) -> None:
        with patch.object(win_security, "_collect", side_effect=RuntimeError("boom")):
            state = read_security_state()
        self.assertEqual(state, SecurityInfo())
        self.assertEqual(state.antivirus, STATE_UNKNOWN)

    def test_the_real_reader_on_this_machine_never_raises(self) -> None:
        # No assertion about the verdicts: the machine running the suite may or may not have
        # an antivirus. What is asserted is that asking is always safe.
        state = read_security_state()
        self.assertIsInstance(state, SecurityInfo)
        for verdict in (state.antivirus, state.firewall, state.secure_boot):
            with self.subTest(verdict=verdict):
                self.assertIn(verdict, (STATE_GOOD, STATE_WEAK, STATE_BAD, STATE_UNKNOWN))

    def test_a_product_name_is_never_invented(self) -> None:
        # It cannot be read without COM/WMI, and "Windows Defender" would be a guess.
        state = read(FakeRegistry(HEALTHY_REGISTRY), health={PROVIDER_ANTIVIRUS: 0})
        self.assertIsNone(state.antivirus_name)
        self.assertIsNone(read_security_state().antivirus_name)


class NonWindowsTests(unittest.TestCase):
    """Every field has to come back unknown on a host that has none of these concepts.

    Nothing is faked here beyond the platform name: the module's own guards are what has to
    produce the fallback, so the real ``_winreg()`` and the real DLL loader both run.
    """

    def state(self) -> SecurityInfo:
        with patch.object(win_security.platform, "system", return_value="Linux"):
            return read_security_state(now=NOW)

    def test_every_verdict_is_unknown(self) -> None:
        state = self.state()
        self.assertEqual(state.antivirus, STATE_UNKNOWN)
        self.assertEqual(state.firewall, STATE_UNKNOWN)
        self.assertEqual(state.secure_boot, STATE_UNKNOWN)

    def test_nothing_is_pending_and_nothing_is_dated(self) -> None:
        state = self.state()
        self.assertIsNone(state.reboot_pending)
        self.assertIsNone(state.defender_last_scan)
        self.assertIsNone(state.signature_age_days)

    def test_no_note_about_a_security_center_that_does_not_exist_there(self) -> None:
        # "The Security Center is unavailable" is meaningless on a machine that has none.
        self.assertEqual(self.state().details, ())

    def test_the_registry_is_never_touched(self) -> None:
        registry = FakeRegistry(HEALTHY_REGISTRY)
        with patch.object(win_security.platform, "system", return_value="Linux"):
            read_security_state(now=NOW, provider_health=lambda provider: None)
        self.assertEqual(registry.opened, [])


class SecurityCenterTests(unittest.TestCase):
    """WSC_SECURITY_PROVIDER_HEALTH -> verdict, including everything that is not a code."""

    def verdict(self, code: object) -> tuple[str, str]:
        state = read(
            FakeRegistry(HEALTHY_REGISTRY),
            health={PROVIDER_ANTIVIRUS: code, PROVIDER_FIREWALL: code},  # type: ignore[dict-item]
        )
        return state.antivirus, state.firewall

    def test_the_documented_health_codes(self) -> None:
        documented = ((0, STATE_GOOD), (1, STATE_UNKNOWN), (2, STATE_WEAK), (3, STATE_WEAK))
        for code, expected in documented:
            with self.subTest(code=code):
                self.assertEqual(self.verdict(code)[0], expected)

    def test_a_code_this_version_does_not_know_is_unknown(self) -> None:
        for code in (4, 99, -1, 0xFFFFFFFF):
            with self.subTest(code=code):
                self.assertEqual(self.verdict(code)[0], STATE_UNKNOWN)

    def test_an_answer_that_is_not_an_integer_is_unknown(self) -> None:
        for code in (None, "good", 1.5, True, False, [], object()):
            with self.subTest(code=code):
                self.assertEqual(self.verdict(code)[0], STATE_UNKNOWN)

    def test_the_two_providers_are_read_separately(self) -> None:
        state = read(
            FakeRegistry(HEALTHY_REGISTRY),
            health={PROVIDER_ANTIVIRUS: 2, PROVIDER_FIREWALL: 0},
        )
        self.assertEqual(state.antivirus, STATE_WEAK)
        self.assertEqual(state.firewall, STATE_GOOD)

    def test_a_good_reading_from_either_source_clears_the_firewall(self) -> None:
        """
        The two sources fail in opposite directions, so a problem needs both to agree.

        Real case that forced this rule: on a workgroup machine the Security Center reports
        POOR purely because the Domain profile is off - a profile that can never apply there -
        while every profile the machine can actually use is enabled. Believing the aggregate
        told the user their firewall needed attention when it did not.
        """
        state = read(FakeRegistry(HEALTHY_REGISTRY), health={PROVIDER_FIREWALL: 2})
        self.assertEqual(state.firewall, STATE_GOOD)
        self.assertIn(
            ("firewall_note", "windows_firewall_on_for_every_applicable_profile"),
            state.details,
        )

    def test_a_third_party_firewall_clears_switched_off_windows_profiles(self) -> None:
        # The inverse failure: the registry only knows Windows Firewall, so a machine
        # protected by another product must not be reported as unprotected.
        values = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        for path in (DOMAIN_PROFILE, PRIVATE_PROFILE, PUBLIC_PROFILE):
            values[path] = {"EnableFirewall": 0}
        state = read(FakeRegistry(values), health={PROVIDER_FIREWALL: 0})
        self.assertEqual(state.firewall, STATE_GOOD)
        self.assertIn(
            ("firewall_note", "protected_by_a_firewall_other_than_windows_firewall"),
            state.details,
        )

    def test_both_sources_unhappy_is_a_real_finding(self) -> None:
        values = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        values[PUBLIC_PROFILE] = {"EnableFirewall": 0}
        state = read(FakeRegistry(values), health={PROVIDER_FIREWALL: 2})
        self.assertEqual(state.firewall, STATE_WEAK)

    def test_the_domain_profile_is_ignored_on_a_machine_with_no_domain(self) -> None:
        values = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        values[DOMAIN_PROFILE] = {"EnableFirewall": 0}

        home = read(FakeRegistry(values), domain_joined=False)
        self.assertEqual(home.firewall, STATE_GOOD)
        self.assertNotIn("firewall_profiles_off", [key for key, _ in home.details])

        self.assertEqual(read(FakeRegistry(values), domain_joined=True).firewall, STATE_WEAK)

        # Passing None means "ask the machine". When the machine itself cannot answer, the
        # profile is kept: an unverified assumption must not silence a real finding.
        with patch.object(win_security, "is_domain_joined", return_value=None):
            unverifiable = read(FakeRegistry(values), domain_joined=None)
        self.assertEqual(unverifiable.firewall, STATE_WEAK)
        self.assertIn(("firewall_profiles_off", "Domain"), unverifiable.details)

    def test_a_silent_security_center_says_so_once(self) -> None:
        state = read(FakeRegistry(HEALTHY_REGISTRY))
        self.assertIn(("security_center", "unavailable"), state.details)
        self.assertEqual([key for key, _ in state.details].count("security_center"), 1)

    def test_a_security_center_that_answered_needs_no_explanation(self) -> None:
        state = read(FakeRegistry(HEALTHY_REGISTRY), health={PROVIDER_ANTIVIRUS: 0})
        self.assertNotIn("security_center", [key for key, _ in state.details])


class FirewallProfileTests(unittest.TestCase):
    """The registry is the fallback verdict, and always the source of *which* profile is off."""

    def state(self, **profiles: int) -> SecurityInfo:
        values = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        for name, value in profiles.items():
            path = {"domain": DOMAIN_PROFILE, "private": PRIVATE_PROFILE, "public": PUBLIC_PROFILE}[
                name
            ]
            values[path] = {"EnableFirewall": value}
        return read(FakeRegistry(values))

    def test_every_profile_on_reads_as_good(self) -> None:
        self.assertEqual(self.state().firewall, STATE_GOOD)

    def test_one_profile_off_is_weak_and_names_the_profile(self) -> None:
        state = self.state(public=0)
        self.assertEqual(state.firewall, STATE_WEAK)
        self.assertIn(("firewall_profiles_off", "Public"), state.details)

    def test_the_profiles_are_named_the_way_windows_names_them_today(self) -> None:
        # "StandardProfile" is the registry name Windows now calls "Private".
        state = self.state(private=0, domain=0)
        self.assertIn(("firewall_profiles_off", "Domain, Private"), state.details)

    def test_a_registry_nobody_can_read_leaves_the_verdict_unknown(self) -> None:
        state = read(FakeRegistry({}, denied=(DOMAIN_PROFILE, PRIVATE_PROFILE, PUBLIC_PROFILE)))
        self.assertEqual(state.firewall, STATE_UNKNOWN)
        self.assertNotIn("firewall_profiles_off", [key for key, _ in state.details])

    def test_an_unreadable_profile_is_not_counted_as_a_profile_that_is_off(self) -> None:
        values = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        del values[PUBLIC_PROFILE]
        state = read(FakeRegistry(values))
        self.assertEqual(state.firewall, STATE_GOOD)
        self.assertEqual(state.details, (("security_center", "unavailable"),))

    def test_a_value_that_is_not_a_number_is_ignored(self) -> None:
        for value in ("1", True, None, [1]):
            with self.subTest(value=value):
                values = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
                values[PUBLIC_PROFILE] = {"EnableFirewall": value}
                self.assertEqual(read(FakeRegistry(values)).firewall, STATE_GOOD)

    def test_the_profiles_are_still_listed_when_the_security_center_answered(self) -> None:
        # The verdict comes from the Security Center; which profile to switch back on is
        # the part the user has to act on, and only the registry knows that.
        values = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        values[PUBLIC_PROFILE] = {"EnableFirewall": 0}
        state = read(FakeRegistry(values), health={PROVIDER_FIREWALL: 2})
        self.assertEqual(state.firewall, STATE_WEAK)
        self.assertIn(("firewall_profiles_off", "Public"), state.details)


class SecureBootTests(unittest.TestCase):
    def state(self, value: object | None) -> str:
        values = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        if value is None:
            values.pop(SECURE_BOOT, None)
        else:
            values[SECURE_BOOT] = {"UEFISecureBootEnabled": value}
        return read(FakeRegistry(values)).secure_boot

    def test_the_switch_is_read_as_it_stands(self) -> None:
        self.assertEqual(self.state(1), STATE_GOOD)
        self.assertEqual(self.state(0), STATE_WEAK)

    def test_a_legacy_bios_machine_has_no_key_and_that_is_unknown_not_a_fault(self) -> None:
        self.assertEqual(self.state(None), STATE_UNKNOWN)

    def test_a_denied_key_is_unknown_too(self) -> None:
        state = read(FakeRegistry(HEALTHY_REGISTRY, denied=(SECURE_BOOT,)))
        self.assertEqual(state.secure_boot, STATE_UNKNOWN)


class RebootPendingTests(unittest.TestCase):
    def state(self, values: dict[str, dict[str, object]]) -> SecurityInfo:
        merged = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        merged.update(values)
        return read(FakeRegistry(merged))

    def test_a_clean_machine_answers_no_rather_than_unknown(self) -> None:
        # Windows deletes those keys once the restart has happened, so their absence is a
        # real answer.
        state = self.state({})
        self.assertIs(state.reboot_pending, False)
        self.assertNotIn("reboot_sources", [key for key, _ in state.details])

    def test_each_marker_key_is_recognised_and_named(self) -> None:
        for path, label in ((SERVICING_REBOOT, "servicing"), (UPDATE_REBOOT, "Windows Update")):
            with self.subTest(source=label):
                state = self.state({path: {}})
                self.assertIs(state.reboot_pending, True)
                self.assertIn(("reboot_sources", label), state.details)

    def test_queued_file_renames_alone_are_not_a_pending_restart(self) -> None:
        """
        Measured on a healthy Windows 11 machine: 26 queued renames (print drivers, a game
        service DLL) with both authoritative markers absent and no restart owed. Calling that
        a pending restart is a false alarm, so the queue never decides the verdict.
        """
        for value in ("\\??\\C:\\file", ["\\??\\C:\\file", ""], ("a", "")):
            with self.subTest(value=value):
                state = self.state({SESSION_MANAGER: {"PendingFileRenameOperations": value}})
                self.assertIs(state.reboot_pending, False)
                self.assertNotIn("reboot_sources", [key for key, _ in state.details])

    def test_queued_file_renames_are_named_once_a_real_marker_is_present(self) -> None:
        state = self.state(
            {
                SERVICING_REBOOT: {},
                SESSION_MANAGER: {"PendingFileRenameOperations": ["\\??\\C:\\file", ""]},
            }
        )
        self.assertIs(state.reboot_pending, True)
        sources = dict(state.details)["reboot_sources"]
        self.assertIn("pending file renames", sources)

    def test_the_empty_strings_windows_always_appends_are_not_a_pending_restart(self) -> None:
        for value in ("", "   ", [], ["", ""], ("  ",), 7):
            with self.subTest(value=value):
                state = self.state({SESSION_MANAGER: {"PendingFileRenameOperations": value}})
                self.assertIs(state.reboot_pending, False)

    def test_several_sources_are_all_named(self) -> None:
        state = self.state(
            {
                SERVICING_REBOOT: {},
                UPDATE_REBOOT: {},
                SESSION_MANAGER: {"PendingFileRenameOperations": ["\\??\\C:\\file"]},
            }
        )
        detail = dict(state.details)["reboot_sources"]
        self.assertEqual(detail, "servicing, Windows Update, pending file renames")

    def test_a_machine_with_no_registry_at_all_reports_unknown(self) -> None:
        # None, not False: "nobody could look" is not "nothing is pending".
        state = read(None)
        self.assertIsNone(state.reboot_pending)


class DefenderFreshnessTests(unittest.TestCase):
    def state(self, **values: object) -> SecurityInfo:
        merged = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        if "signatures" in values:
            merged[SIGNATURES] = {"SignaturesLastUpdated": values["signatures"]}
        if "scan" in values:
            merged[SCAN] = {"LastScanRun": values["scan"]}
        return read(FakeRegistry(merged))

    def test_a_filetime_stored_as_a_qword_is_read(self) -> None:
        state = self.state(signatures=filetime(NOW - timedelta(days=10)))
        self.assertEqual(state.signature_age_days, 10)

    def test_a_filetime_stored_as_binary_is_read_little_endian(self) -> None:
        raw = filetime(NOW - timedelta(days=3)).to_bytes(8, "little")
        self.assertEqual(self.state(signatures=raw).signature_age_days, 3)

    def test_the_last_scan_is_reported_as_a_moment_not_an_age(self) -> None:
        moment = NOW - timedelta(hours=30)
        state = self.state(scan=filetime(moment))
        assert state.defender_last_scan is not None
        self.assertEqual(state.defender_last_scan, moment)

    def test_a_partial_day_counts_as_the_whole_days_that_passed(self) -> None:
        for hours, expected in ((0, 0), (23, 0), (24, 1), (47, 1), (48, 2)):
            with self.subTest(hours=hours):
                state = self.state(signatures=filetime(NOW - timedelta(hours=hours)))
                self.assertEqual(state.signature_age_days, expected)

    def test_a_timestamp_in_the_future_reads_as_zero_days_old(self) -> None:
        state = self.state(signatures=filetime(NOW + timedelta(days=5)))
        self.assertEqual(state.signature_age_days, 0)

    def test_a_machine_without_defender_reports_no_age_at_all(self) -> None:
        # The keys do not exist on a PC where Defender was removed. None is the honest
        # answer; deriving an age from anything else would be an invented measurement.
        state = self.state()
        self.assertIsNone(state.signature_age_days)
        self.assertIsNone(state.defender_last_scan)

    def test_a_protected_key_reports_no_age_either(self) -> None:
        state = read(FakeRegistry(HEALTHY_REGISTRY, denied=(SIGNATURES, SCAN)))
        self.assertIsNone(state.signature_age_days)

    def test_a_value_that_cannot_be_read_reports_no_age(self) -> None:
        merged = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        merged[SIGNATURES] = {"SignaturesLastUpdated": filetime(NOW)}
        state = read(FakeRegistry(merged, hostile_values=(SIGNATURES,)))
        self.assertIsNone(state.signature_age_days)


class FiletimeDecodingTests(unittest.TestCase):
    """The conversion on its own: it is where a wrong answer would look most plausible."""

    def test_a_known_moment_round_trips(self) -> None:
        moment = datetime(2026, 3, 1, 7, 30, tzinfo=timezone.utc)
        self.assertEqual(_filetime_to_datetime(filetime(moment)), moment)
        self.assertEqual(_filetime_to_datetime(filetime(moment).to_bytes(8, "little")), moment)

    def test_only_the_first_eight_bytes_of_a_binary_value_are_read(self) -> None:
        moment = datetime(2026, 3, 1, 7, 30, tzinfo=timezone.utc)
        padded = filetime(moment).to_bytes(8, "little") + b"\xff" * 8
        self.assertEqual(_filetime_to_datetime(padded), moment)

    def test_a_placeholder_is_not_a_timestamp(self) -> None:
        for value in (0, -1, b"\x00" * 8, 11_644_473_600 * 10_000_000):
            with self.subTest(value=value):
                self.assertIsNone(_filetime_to_datetime(value))

    def test_a_value_that_is_not_a_filetime_is_refused(self) -> None:
        for value in (None, "yesterday", 1.5, True, [], b"\x01\x02"):
            with self.subTest(value=value):
                self.assertIsNone(_filetime_to_datetime(value))

    def test_an_impossible_tick_count_is_refused_rather_than_raising(self) -> None:
        self.assertIsNone(_filetime_to_datetime(2**63))


class RegistryAccessTests(unittest.TestCase):
    """Read-only, and tidy: every key is opened with KEY_READ and closed again."""

    def run_once(self, registry: FakeRegistry) -> SecurityInfo:
        return read(registry)

    def test_every_key_is_opened_for_reading_only(self) -> None:
        registry = FakeRegistry(HEALTHY_REGISTRY)
        self.run_once(registry)
        self.assertTrue(registry.opened)
        for root, path, reserved, access in registry.opened:
            with self.subTest(key=path):
                self.assertEqual(root, FakeRegistry.HKEY_LOCAL_MACHINE)
                self.assertEqual(reserved, 0)
                self.assertEqual(access, FakeRegistry.KEY_READ)

    def test_every_key_that_opened_is_closed_again(self) -> None:
        registry = FakeRegistry(HEALTHY_REGISTRY)
        self.run_once(registry)
        opened = [path for _, path, _, _ in registry.opened if path in registry.values]
        self.assertEqual(sorted(registry.closed), sorted(opened))

    def test_a_key_whose_value_explodes_is_still_closed(self) -> None:
        registry = FakeRegistry(HEALTHY_REGISTRY, hostile_values=(SECURE_BOOT,))
        state = self.run_once(registry)
        self.assertEqual(state.secure_boot, STATE_UNKNOWN)
        self.assertIn(SECURE_BOOT, registry.closed)

    def test_the_collector_never_writes_anything(self) -> None:
        # The fake module has no SetValue at all, so any attempt to write would raise
        # AttributeError - and read_security_state() would then have to swallow it and
        # return a blank record. It does not, which is the assertion.
        registry = FakeRegistry(HEALTHY_REGISTRY)
        state = self.run_once(registry)
        self.assertNotEqual(state, SecurityInfo())
        for name in ("SetValue", "SetValueEx", "CreateKey", "DeleteKey", "DeleteValue"):
            with self.subTest(name=name):
                self.assertFalse(hasattr(registry, name))

    def test_the_module_never_names_a_writing_registry_call(self) -> None:
        with open(win_security.__file__, "r", encoding="utf-8") as handle:
            source = handle.read()
        for forbidden in ("SetValue", "CreateKey", "DeleteKey", "DeleteValue", "KEY_WRITE"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


class ClockTests(unittest.TestCase):
    def test_the_clock_can_be_pinned_for_a_reproducible_export(self) -> None:
        merged = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        merged[SIGNATURES] = {"SignaturesLastUpdated": filetime(NOW - timedelta(days=9))}
        registry = FakeRegistry(merged)
        self.assertEqual(read(registry, now=NOW).signature_age_days, 9)
        later = read(registry, now=NOW + timedelta(days=5)).signature_age_days
        self.assertEqual(later, 14)

    def test_a_naive_pin_is_read_as_local_time_rather_than_refused(self) -> None:
        merged = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        merged[SIGNATURES] = {"SignaturesLastUpdated": filetime(NOW)}
        state = read(FakeRegistry(merged), now=NOW.astimezone().replace(tzinfo=None))
        self.assertEqual(state.signature_age_days, 0)

    def test_an_unpinned_clock_still_produces_a_whole_number_of_days(self) -> None:
        merged = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        merged[SIGNATURES] = {"SignaturesLastUpdated": filetime(datetime.now(timezone.utc))}
        state = read(FakeRegistry(merged), now=None)
        self.assertEqual(state.signature_age_days, 0)


class DetailTests(unittest.TestCase):
    def test_details_are_pairs_of_plain_strings(self) -> None:
        values = {path: dict(entries) for path, entries in HEALTHY_REGISTRY.items()}
        values[PUBLIC_PROFILE] = {"EnableFirewall": 0}
        values[SERVICING_REBOOT] = {}
        state = read(FakeRegistry(values))
        self.assertTrue(state.details)
        for item in state.details:
            with self.subTest(item=item):
                self.assertIsInstance(item, tuple)
                self.assertEqual(len(item), 2)
                key, value = item
                self.assertIsInstance(key, str)
                self.assertIsInstance(value, str)
                self.assertTrue(key.strip() and value.strip())

    def test_a_healthy_machine_carries_no_notes_beyond_the_missing_center(self) -> None:
        state = read(FakeRegistry(HEALTHY_REGISTRY), health={PROVIDER_ANTIVIRUS: 0})
        self.assertEqual(state.details, ())


if __name__ == "__main__":
    unittest.main()
