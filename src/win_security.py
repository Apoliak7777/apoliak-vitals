"""Read-only view of the Windows protection state.

Answers four questions a user can act on: is something guarding this machine (antivirus),
is the firewall on, is Secure Boot on, and is a restart still owed to Windows. Everything
is read through the Security Center API and ``KEY_READ`` registry lookups - no WMI, no COM,
no PowerShell, no elevation, and nothing is ever written.

Two rules shape every verdict here:

* A failed query is *unknown*, never *bad*. A denied key, a missing API and a machine that
  simply does not report a figure all produce ``STATE_UNKNOWN``, which the score never
  penalises. Telling a user "you are unprotected" because a DLL failed to load would be a lie.
* Nothing is guessed. ``antivirus_name`` stays None unless it can be read reliably, and it
  cannot be read without COM/WMI - so it is always None. Reporting "Windows Defender" merely
  because Defender ships with Windows would be an invention (this very machine has no
  Defender installed at all).

The Security Center is the authoritative source: it also covers third-party antivirus, which
a Defender-specific registry probe would miss entirely.
"""

from __future__ import annotations

import ctypes
import platform
from datetime import datetime, timezone
from typing import Any, Callable

from .models import STATE_BAD, STATE_GOOD, STATE_UNKNOWN, STATE_WEAK, SecurityInfo

#: Provider bits accepted by ``WscGetSecurityProviderHealth`` (wscapi.h).
#: Verified on Windows 11 Pro 24H2 (build 26100.8875): every documented bit returns S_OK,
#: 0x1 tracked the firewall (POOR while the Domain profile was off, matching the registry)
#: and 0x4 tracked the antivirus (POOR on a machine with no antivirus registered at all).
_PROVIDER_FIREWALL = 0x1
_PROVIDER_ANTIVIRUS = 0x4

#: ``WSC_SECURITY_PROVIDER_HEALTH`` -> our verdict. Confirmed empirically: the providers that
#: are healthy on this machine (auto-update, internet settings, UAC, the WSC service itself)
#: all return 0, and the two that the Security Center UI flags return 2.
#: NOTMONITORED means nobody reports on that area, which is genuinely unknown - not a fault.
#: SNOOZE means protection is paused by the user, which is weak but not absent.
_HEALTH_STATES: dict[int, str] = {
    0: STATE_GOOD,  # WSC_SECURITY_PROVIDER_HEALTH_GOOD
    1: STATE_UNKNOWN,  # WSC_SECURITY_PROVIDER_HEALTH_NOTMONITORED
    2: STATE_WEAK,  # WSC_SECURITY_PROVIDER_HEALTH_POOR
    3: STATE_WEAK,  # WSC_SECURITY_PROVIDER_HEALTH_SNOOZE
}

_FIREWALL_POLICY_KEY = (
    r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"
)

#: (registry subkey, label shown to the user). "StandardProfile" is the profile Windows now
#: calls "Private" - the registry name predates the rename and was never changed.
_FIREWALL_PROFILES: tuple[tuple[str, str], ...] = (
    ("DomainProfile", "Domain"),
    ("StandardProfile", "Private"),
    ("PublicProfile", "Public"),
)

_SECURE_BOOT_KEY = r"SYSTEM\CurrentControlSet\Control\SecureBoot\State"

#: (key that only exists while a restart is owed, why it is owed).
_REBOOT_KEYS: tuple[tuple[str, str], ...] = (
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "servicing",
    ),
    (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
        "Windows Update",
    ),
)

_SESSION_MANAGER_KEY = r"SYSTEM\CurrentControlSet\Control\Session Manager"

_DEFENDER_SIGNATURES_KEY = r"SOFTWARE\Microsoft\Windows Defender\Signature Updates"
_DEFENDER_SCAN_KEY = r"SOFTWARE\Microsoft\Windows Defender\Scan"

#: Seconds between the FILETIME epoch (1601-01-01) and the Unix epoch (1970-01-01).
_FILETIME_EPOCH_DELTA = 11_644_473_600
#: FILETIME counts 100-nanosecond ticks.
_FILETIME_TICKS_PER_SECOND = 10_000_000

_SECONDS_PER_DAY = 86_400


def read_security_state(
    *,
    now: datetime | None = None,
    provider_health: Callable[[int], int | None] | None = None,
    domain_joined: bool | None = None,
) -> SecurityInfo:
    """
    Describe how well this machine is protected right now.

    Never raises and never blocks: on a non-Windows host, on a locked-down machine, or when
    ``wscapi.dll`` cannot be loaded, every field simply comes back unknown.

    ``now`` pins the clock used to age the antivirus signatures (tests and reproducible
    exports need that); ``provider_health`` replaces the Security Center lookup with a fake;
    ``domain_joined`` overrides the domain-membership probe, which decides whether the Domain
    firewall profile can apply at all. All three default to asking the real machine.
    """
    try:
        return _collect(
            now=now, provider_health=provider_health, domain_joined=domain_joined
        )
    except Exception:  # A snapshot must survive anything the platform throws at it.
        return SecurityInfo()


def _collect(
    *,
    now: datetime | None,
    provider_health: Callable[[int], int | None] | None,
    domain_joined: bool | None = None,
) -> SecurityInfo:
    query = provider_health if callable(provider_health) else _security_center_reader()

    antivirus_health = _provider_health(query, _PROVIDER_ANTIVIRUS)
    firewall_health = _provider_health(query, _PROVIDER_FIREWALL)
    security_center_down = antivirus_health is None and firewall_health is None

    antivirus = _health_state(antivirus_health)
    firewall = _health_state(firewall_health)

    # The profile list is read even when the Security Center answered, because "which profile
    # is off" is the part the user has to act on.
    registry_firewall, profiles_off = _read_firewall_profiles(domain_joined)
    firewall, firewall_note = _combine_firewall(firewall, registry_firewall)

    reboot_pending, reboot_sources = _read_reboot_pending()
    last_scan, signature_age_days = _read_defender_freshness(now)

    details: list[tuple[str, str]] = []
    if security_center_down and _is_windows():
        # Tells the reader why the antivirus verdict is N/A instead of leaving them guessing.
        # Pointless off Windows, where there is no Security Center to be unavailable.
        details.append(("security_center", "unavailable"))
    if profiles_off:
        details.append(("firewall_profiles_off", ", ".join(profiles_off)))
    if firewall_note:
        details.append(("firewall_note", firewall_note))
    if reboot_sources:
        details.append(("reboot_sources", ", ".join(reboot_sources)))

    return SecurityInfo(
        antivirus=antivirus,
        # Deliberately None: the product name cannot be read without COM/WMI, and guessing it
        # would be an invented measurement. See the module docstring.
        antivirus_name=None,
        firewall=firewall,
        secure_boot=_read_secure_boot(),
        reboot_pending=reboot_pending,
        defender_last_scan=last_scan,
        signature_age_days=signature_age_days,
        details=tuple(details),
    )


# --------------------------------------------------------------------------------------
# Windows Security Center (wscapi.dll)
# --------------------------------------------------------------------------------------


def _security_center_reader() -> Callable[[int], int | None]:
    """Build a Security Center lookup. The returned callable answers None when unavailable."""
    function = _load_wsc_function()

    def query(provider: int) -> int | None:
        if function is None:
            return None
        health = ctypes.c_ulong(0xFFFFFFFF)
        try:
            result = function(ctypes.c_ulong(provider), ctypes.byref(health))
        except Exception:
            return None
        # Any failed HRESULT means "we could not ask", which is unknown - never "unprotected".
        if int(result) != 0:
            return None
        return int(health.value)

    return query


def _is_windows() -> bool:
    """Checked per call, never cached, so a test can pretend the platform is something else."""
    return platform.system() == "Windows"


def _load_wsc_function() -> Any | None:
    """Resolve ``WscGetSecurityProviderHealth``, or None on any platform that lacks it."""
    if not _is_windows():
        return None
    try:
        # WinDLL only exists on Windows; the attribute lookup itself fails elsewhere.
        library = ctypes.WinDLL("wscapi.dll")  # type: ignore[attr-defined]
        function = library.WscGetSecurityProviderHealth
        # HRESULT WscGetSecurityProviderHealth(DWORD Providers, PDWORD pHealth) - a pure
        # query: it reports what the Security Center already knows and changes nothing.
        function.argtypes = [ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        function.restype = ctypes.c_long
    except Exception:  # Missing DLL, missing export, or a non-Windows ctypes build.
        return None
    return function


def _provider_health(query: Callable[[int], int | None], provider: int) -> int | None:
    """Ask one provider for its health code. A fake that raises is treated as unavailable."""
    try:
        health = query(provider)
    except Exception:
        return None
    if isinstance(health, bool) or not isinstance(health, int):
        return None
    return health


def _health_state(health: int | None) -> str:
    if health is None:
        return STATE_UNKNOWN
    return _HEALTH_STATES.get(health, STATE_UNKNOWN)


# --------------------------------------------------------------------------------------
# Registry helpers - the same read-only idiom as win_registry.py
# --------------------------------------------------------------------------------------


def _winreg() -> Any | None:
    """Return the winreg module, or None when it cannot be used on this platform."""
    if not _is_windows():
        return None
    try:
        import winreg
    except ImportError:  # Non-Windows Python builds simply do not ship winreg.
        return None
    return winreg


def _open_key(path: str) -> Any | None:
    """Open an HKLM key for reading. Returns None instead of raising."""
    winreg = _winreg()
    if winreg is None:
        return None
    try:
        return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_READ)
    except Exception:
        # Wider than the OSError the API documents on purpose: one unhappy key must never
        # cost the caller the verdicts that were already read successfully.
        return None


def _key_exists(path: str) -> bool:
    key = _open_key(path)
    if key is None:
        return False
    _close(key)
    return True


def _read_value(key: Any, name: str) -> object | None:
    """Query one value, returning None when it is absent or unreadable."""
    winreg = _winreg()
    if winreg is None:
        return None
    try:
        value, _ = winreg.QueryValueEx(key, name)
    except (OSError, ValueError):
        return None
    return value


def _close(key: Any) -> None:
    try:
        key.Close()
    except Exception:
        pass


def _read_dword(path: str, name: str) -> int | None:
    """Read a single DWORD from HKLM, or None when the key or value is unreadable."""
    key = _open_key(path)
    if key is None:
        return None
    try:
        raw = _read_value(key, name)
    except Exception:
        return None
    finally:
        _close(key)
    if isinstance(raw, bool) or not isinstance(raw, int):
        return None
    return raw


# --------------------------------------------------------------------------------------
# Firewall, Secure Boot, pending restart
# --------------------------------------------------------------------------------------


def _combine_firewall(center: str, registry: str) -> tuple[str, str]:
    """
    Reconcile the Security Center's aggregate verdict with the per-profile switches.

    The two sources fail in opposite directions, so neither can be trusted alone:

    * The Security Center reports the firewall as POOR when the Domain profile is off, even on
      a workgroup machine where that profile can never apply. Believing it there tells a home
      user their firewall needs attention while all three networks they can be on are covered.
    * The registry only knows about Windows Firewall. Where a third-party firewall has taken
      over, the Windows profiles can legitimately read as off while the machine is protected.

    So a "good" from either source wins, and a problem is reported only when the aggregate and
    the specific reading both fail to show protection. The returned note explains a
    disagreement rather than hiding it.
    """
    if center == STATE_GOOD or registry == STATE_GOOD:
        if center in (STATE_WEAK, STATE_BAD) and registry == STATE_GOOD:
            return STATE_GOOD, "windows_firewall_on_for_every_applicable_profile"
        if registry in (STATE_WEAK, STATE_BAD) and center == STATE_GOOD:
            return STATE_GOOD, "protected_by_a_firewall_other_than_windows_firewall"
        return STATE_GOOD, ""
    if registry != STATE_UNKNOWN:
        return registry, ""
    return center, ""


def is_domain_joined() -> bool | None:
    """
    Whether this machine belongs to a Windows domain.

    ``netapi32.NetGetJoinInformation`` answers 1 unjoined, 2 workgroup, 3 domain. Returns None
    when the answer cannot be obtained, so callers can tell "not in a domain" from "no idea".
    """
    if not _is_windows():
        return None
    try:
        import ctypes

        netapi32 = ctypes.WinDLL("netapi32.dll")  # type: ignore[attr-defined]
        name = ctypes.c_wchar_p()
        status = ctypes.c_int()
        if netapi32.NetGetJoinInformation(None, ctypes.byref(name), ctypes.byref(status)) != 0:
            return None
        try:
            return status.value == 3
        finally:
            netapi32.NetApiBufferFree(name)
    except Exception:
        return None


def _read_firewall_profiles(domain_joined: bool | None = None) -> tuple[str, list[str]]:
    """
    Read ``EnableFirewall`` for each profile that can actually apply to this machine.

    Returns the registry verdict plus the labels of the profiles that are switched off.
    Unreadable profiles are ignored rather than counted as off.

    The Domain profile is skipped on a machine that is not domain-joined: Windows ships it
    switched off there, it can never become the active profile, and counting it would tell a
    home user their firewall needs attention when all three networks they can ever be on are
    protected. When domain membership itself cannot be determined, the profile is kept - an
    unverified assumption must not silence a real finding.
    """
    if domain_joined is None:
        domain_joined = is_domain_joined()
    off: list[str] = []
    readable = 0
    for subkey, label in _FIREWALL_PROFILES:
        if subkey == "DomainProfile" and domain_joined is False:
            continue
        value = _read_dword(f"{_FIREWALL_POLICY_KEY}\\{subkey}", "EnableFirewall")
        if value is None:
            continue
        readable += 1
        if value == 0:
            off.append(label)

    if readable == 0:
        return STATE_UNKNOWN, []
    return (STATE_WEAK if off else STATE_GOOD), off


def _read_secure_boot() -> str:
    """
    Read the UEFI Secure Boot switch.

    A legacy-BIOS machine has no such key at all, and that is genuinely unknown - not a fault,
    which is why a missing key never becomes STATE_WEAK.
    """
    value = _read_dword(_SECURE_BOOT_KEY, "UEFISecureBootEnabled")
    if value is None:
        return STATE_UNKNOWN
    return STATE_GOOD if value else STATE_WEAK


def _read_reboot_pending() -> tuple[bool | None, list[str]]:
    """
    Detect an owed restart from the places Windows records one.

    Returns None on a platform where the registry cannot be read at all; on Windows an absent
    marker key is a real answer ("nothing pending"), because Windows deletes those keys once
    the restart has happened.

    Only the Component Based Servicing and Windows Update markers decide the verdict.
    ``PendingFileRenameOperations`` deliberately does NOT: it is routinely non-empty on a
    perfectly healthy machine - a print-driver update or an installer leaves entries behind
    that Windows will apply silently at some later boot without ever asking for a restart.
    Measured on a healthy test machine: 26 queued renames with both authoritative markers
    absent. Treating that as "Windows is waiting for a restart" is a false alarm, so the
    queue is reported as context only, never as the reason.
    """
    if _winreg() is None:
        return None, []

    sources: list[str] = []
    for path, label in _REBOOT_KEYS:
        if _key_exists(path):
            sources.append(label)

    pending = bool(sources)
    if pending and _has_pending_file_renames():
        sources.append("pending file renames")
    return pending, sources


def _has_pending_file_renames() -> bool:
    """True when Session Manager still holds a file operation queued for the next boot."""
    key = _open_key(_SESSION_MANAGER_KEY)
    if key is None:
        return False
    try:
        raw = _read_value(key, "PendingFileRenameOperations")
    except Exception:
        return False
    finally:
        _close(key)

    if isinstance(raw, str):
        return bool(raw.strip())
    if isinstance(raw, (list, tuple)):
        # REG_MULTI_SZ always carries trailing empty strings; only real entries count.
        return any(str(item).strip() for item in raw)
    return False


# --------------------------------------------------------------------------------------
# Microsoft Defender freshness (best effort - these keys are often absent or protected)
# --------------------------------------------------------------------------------------


def _read_defender_freshness(now: datetime | None) -> tuple[datetime | None, int | None]:
    """
    Read the last scan time and the age of the signatures.

    Both keys live under a hive that Defender protects, and on a machine where Defender was
    removed they do not exist at all. None is the honest answer in either case; the age is
    never estimated from anything else.
    """
    signatures = _read_filetime(_DEFENDER_SIGNATURES_KEY, "SignaturesLastUpdated")
    last_scan = _read_filetime(_DEFENDER_SCAN_KEY, "LastScanRun")
    return last_scan, _age_in_days(signatures, now)


def _read_filetime(path: str, name: str) -> datetime | None:
    """Read a FILETIME stored either as REG_BINARY or as REG_QWORD."""
    key = _open_key(path)
    if key is None:
        return None
    try:
        raw = _read_value(key, name)
    except Exception:
        return None
    finally:
        _close(key)
    return _filetime_to_datetime(raw)


def _filetime_to_datetime(value: object) -> datetime | None:
    """Convert a Windows FILETIME into an aware local datetime, or None when it is not one."""
    if isinstance(value, (bytes, bytearray)):
        if len(value) < 8:
            return None
        ticks = int.from_bytes(bytes(value[:8]), "little", signed=False)
    elif isinstance(value, int) and not isinstance(value, bool):
        ticks = value
    else:
        return None

    if ticks <= 0:
        return None
    seconds = ticks / _FILETIME_TICKS_PER_SECOND - _FILETIME_EPOCH_DELTA
    if seconds <= 0:  # Anything at or before 1970 is a placeholder, not a timestamp.
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).astimezone()
    except (OSError, OverflowError, ValueError):
        return None


def _age_in_days(moment: datetime | None, now: datetime | None) -> int | None:
    """Whole days between ``moment`` and ``now``. A future timestamp reads as zero days old."""
    if moment is None:
        return None
    current = now if isinstance(now, datetime) else datetime.now().astimezone()
    try:
        if current.tzinfo is None:  # A naive pin from a test means local time.
            current = current.astimezone()
        if moment.tzinfo is None:
            moment = moment.astimezone()
        elapsed = (current - moment).total_seconds()
    except (OSError, OverflowError, ValueError):
        return None
    return max(0, int(elapsed // _SECONDS_PER_DAY))
