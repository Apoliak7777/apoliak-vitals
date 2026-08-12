"""Read-only Windows registry lookups.

Every key is opened with ``KEY_READ`` only, so this module can never modify the machine.
Nothing here raises: a missing key, a denied permission, or a non-Windows platform simply
produces an empty result, which the caller renders as "N/A".

The registry is used instead of WMI/PowerShell on purpose - spawning a subprocess would be
slower, would flash a console window in the packaged GUI, and would break the promise that
the tool only ever reads.
"""

from __future__ import annotations

import os
import platform
from datetime import datetime, timezone
from typing import Any

from .models import GPUInfo, StartupItem

_CURRENT_VERSION_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
_BIOS_KEY = r"HARDWARE\DESCRIPTION\System\BIOS"
_PROCESSOR_KEY = r"HARDWARE\DESCRIPTION\System\CentralProcessor\0"
#: Device class GUID of "Display adapters"; its numbered subkeys describe every GPU driver.
_DISPLAY_CLASS_KEY = (
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
)

_MAX_GPUS = 4
_MAX_STARTUP_ITEMS = 60
_MAX_DISPLAY_SUBKEYS = 32

#: 1 MiB .. 128 GiB. Adapter memory outside this range is a driver placeholder, not a size.
_MIN_GPU_MEMORY = 1024 * 1024
_MAX_GPU_MEMORY = 128 * 1024**3

#: OEM strings that mean "the vendor left the field empty". Reporting them would be a lie.
_PLACEHOLDERS = frozenset(
    {
        "",
        "-",
        "0123456789",
        "chassis manufacturer",
        "default string",
        "n/a",
        "na",
        "none",
        "not applicable",
        "not specified",
        "oem",
        "system manufacturer",
        "system name",
        "system product name",
        "system version",
        "to be filled by o.e.m.",
        "to be filled by oem",
        "unknown",
    }
)


def _winreg() -> Any | None:
    """Return the winreg module, or None when it cannot be used on this platform."""
    if platform.system() != "Windows":
        return None
    try:
        import winreg
    except ImportError:  # Non-Windows Python builds simply do not ship winreg.
        return None
    return winreg


def _clean(value: object) -> str | None:
    """Normalise a registry value to a trimmed string, or None when it carries no data."""
    if value is None:
        return None
    if isinstance(value, (list, tuple)):  # REG_MULTI_SZ arrives as a list of strings.
        parts = [str(item).strip() for item in value if str(item).strip()]
        value = " ".join(parts)
    text = " ".join(str(value).split())
    return text or None


def _meaningful(value: object) -> str | None:
    """Like :func:`_clean`, but drops OEM placeholder strings such as "Default string"."""
    text = _clean(value)
    if text is None or text.lower() in _PLACEHOLDERS:
        return None
    return text


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


def _open_key(root_name: str, path: str) -> Any | None:
    """Open a registry key for reading. Returns None instead of raising."""
    winreg = _winreg()
    if winreg is None:
        return None
    root = getattr(winreg, root_name, None)
    if root is None:
        return None
    try:
        return winreg.OpenKey(root, path, 0, winreg.KEY_READ)
    except OSError:
        return None


def windows_edition_details() -> dict[str, object]:
    """
    Read the Windows product identity from ``SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion``.

    ``product_name`` is returned raw: on Windows 11 it still says "Windows 10 Pro", so the
    marketing name has to be derived from the build number by the caller.
    """
    details: dict[str, object] = {
        "product_name": None,
        "edition": None,
        "display_version": None,
        "build": None,
        "install_date": None,
    }

    key = _open_key("HKEY_LOCAL_MACHINE", _CURRENT_VERSION_KEY)
    if key is None:
        return details

    try:
        details["product_name"] = _meaningful(_read_value(key, "ProductName"))
        details["edition"] = _meaningful(_read_value(key, "EditionID"))
        # DisplayVersion ("24H2") replaced ReleaseId ("2009") in Windows 10 20H2.
        details["display_version"] = _meaningful(
            _read_value(key, "DisplayVersion")
        ) or _meaningful(_read_value(key, "ReleaseId"))
        details["build"] = _compose_build(
            _clean(_read_value(key, "CurrentBuild")),
            _read_value(key, "UBR"),
        )
        details["install_date"] = _to_local_datetime(_read_value(key, "InstallDate"))
    except Exception:  # A malformed hive must not break the whole analysis.
        pass
    finally:
        _close(key)
    return details


def _compose_build(current_build: str | None, update_revision: object) -> str | None:
    """Join build and update-revision into the familiar "26100.4652" form."""
    if not current_build:
        return None
    try:
        revision = int(update_revision)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return current_build
    return f"{current_build}.{revision}"


def _to_local_datetime(value: object) -> datetime | None:
    """Convert a registry unix timestamp into an aware local datetime."""
    try:
        seconds = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc).astimezone()
    except (OSError, OverflowError, ValueError):
        return None


def _close(key: Any) -> None:
    try:
        key.Close()
    except Exception:
        pass


def read_gpus() -> list[GPUInfo]:
    """List display adapters from their driver class key. Returns [] when unavailable."""
    winreg = _winreg()
    root = _open_key("HKEY_LOCAL_MACHINE", _DISPLAY_CLASS_KEY)
    if winreg is None or root is None:
        return []

    adapters: list[GPUInfo] = []
    seen: set[str] = set()
    try:
        for index in range(_MAX_DISPLAY_SUBKEYS):
            try:
                name = winreg.EnumKey(root, index)
            except OSError:  # Raised as soon as the subkeys run out.
                break
            # Only the numbered subkeys are adapters; "Properties" and friends are not.
            if not name.isdigit():
                continue
            adapter = _read_adapter(root, name)
            if adapter is None or adapter.name.lower() in seen:
                continue
            seen.add(adapter.name.lower())
            adapters.append(adapter)
            if len(adapters) >= _MAX_GPUS:
                break
    except Exception:
        pass
    finally:
        _close(root)
    return adapters


def _read_adapter(root: Any, subkey_name: str) -> GPUInfo | None:
    winreg = _winreg()
    if winreg is None:
        return None
    try:
        key = winreg.OpenKey(root, subkey_name, 0, winreg.KEY_READ)
    except OSError:
        return None

    try:
        name = _meaningful(_read_value(key, "DriverDesc"))
        if name is None:  # Subkeys without a description are not real adapters.
            return None
        return GPUInfo(
            name=name,
            driver_version=_clean(_read_value(key, "DriverVersion")),
            driver_date=_normalise_driver_date(_clean(_read_value(key, "DriverDate"))),
            memory_bytes=_read_adapter_memory(key),
        )
    except Exception:
        return None
    finally:
        _close(key)


def _normalise_driver_date(value: str | None) -> str | None:
    """Turn the registry's "6-21-2006" into ISO "2006-06-21"; keep the raw text otherwise."""
    if not value:
        return None
    parts = value.split(" ")[0].split("-")
    if len(parts) == 3:
        try:
            month, day, year = (int(part) for part in parts)
            return f"{year:04d}-{month:02d}-{day:02d}"
        except ValueError:
            return value
    return value


def _read_adapter_memory(key: Any) -> int | None:
    """Read adapter memory, which drivers store either as REG_BINARY or as a number."""
    for value_name in ("HardwareInformation.qwMemorySize", "HardwareInformation.MemorySize"):
        raw = _read_value(key, value_name)
        size: int | None = None
        if isinstance(raw, (bytes, bytearray)):
            if 0 < len(raw) <= 8:
                size = int.from_bytes(bytes(raw), "little", signed=False)
        elif isinstance(raw, int):
            size = raw
        if size is not None and _MIN_GPU_MEMORY <= size <= _MAX_GPU_MEMORY:
            return size
    return None


#: (registry root, subkey, human label) triples scanned for auto-started programs.
_RUN_LOCATIONS: tuple[tuple[str, str, str], ...] = (
    ("HKEY_CURRENT_USER", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    ("HKEY_CURRENT_USER", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
    ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    ("HKEY_LOCAL_MACHINE", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
)

_STARTUP_SUBPATH = r"Microsoft\Windows\Start Menu\Programs\Startup"


def read_startup_items() -> list[StartupItem]:
    """List programs Windows launches at sign-in. Purely informational - nothing is changed."""
    items: list[StartupItem] = []
    for root_name, path, label in _RUN_LOCATIONS:
        items.extend(_read_run_key(root_name, path, label))
        if len(items) >= _MAX_STARTUP_ITEMS:
            return items[:_MAX_STARTUP_ITEMS]

    for env_var, label in (("APPDATA", "Startup folder (user)"),
                           ("ProgramData", "Startup folder (all users)")):
        items.extend(_read_startup_folder(env_var, label))
        if len(items) >= _MAX_STARTUP_ITEMS:
            break
    return items[:_MAX_STARTUP_ITEMS]


def _read_run_key(root_name: str, path: str, label: str) -> list[StartupItem]:
    winreg = _winreg()
    key = _open_key(root_name, path)
    if winreg is None or key is None:
        return []

    found: list[StartupItem] = []
    try:
        for index in range(_MAX_STARTUP_ITEMS):
            try:
                name, value, _ = winreg.EnumValue(key, index)
            except OSError:
                break
            clean_name = _clean(name)
            if not clean_name:
                continue
            found.append(StartupItem(name=clean_name, source=label, command=_clean(value)))
    except Exception:
        pass
    finally:
        _close(key)
    return found


def _read_startup_folder(env_var: str, label: str) -> list[StartupItem]:
    base = os.environ.get(env_var)
    if not base:
        return []
    folder = os.path.join(base, _STARTUP_SUBPATH)

    found: list[StartupItem] = []
    try:
        with os.scandir(folder) as entries:
            for entry in entries:
                if entry.name.lower() == "desktop.ini":
                    continue
                name = _clean(os.path.splitext(entry.name)[0])
                if not name:
                    continue
                found.append(StartupItem(name=name, source=label, command=entry.path))
                if len(found) >= _MAX_STARTUP_ITEMS:
                    break
    except (OSError, ValueError):
        return found
    return found


def read_firmware() -> dict[str, object]:
    """Read board/BIOS identity. Vendor placeholder strings are reported as None."""
    firmware: dict[str, object] = {"manufacturer": None, "model": None, "bios_version": None}

    key = _open_key("HKEY_LOCAL_MACHINE", _BIOS_KEY)
    if key is None:
        return firmware

    try:
        firmware["manufacturer"] = _meaningful(_read_value(key, "SystemManufacturer"))
        firmware["model"] = _meaningful(_read_value(key, "SystemProductName"))
        firmware["bios_version"] = _meaningful(_read_value(key, "BIOSVersion"))
    except Exception:
        pass
    finally:
        _close(key)
    return firmware


def read_processor_name() -> str | None:
    """Read the marketing CPU name. The caller keeps its own non-registry fallbacks."""
    key = _open_key("HKEY_LOCAL_MACHINE", _PROCESSOR_KEY)
    if key is None:
        return None
    try:
        return _meaningful(_read_value(key, "ProcessorNameString"))
    except Exception:
        return None
    finally:
        _close(key)
