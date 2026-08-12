"""Read-only system data collection for Windows PCs.

Every function here observes the machine and nothing else: no file is written, no registry
value is set, no process is touched. A collector that cannot read something returns None
and the orchestrator turns the failure into a human-readable warning, because a partial
snapshot is always more useful than a traceback.
"""

from __future__ import annotations

import os
import platform
import re
import tempfile
import time
from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

from . import win_registry
from .folder_usage import read_folder_usage
from .models import (
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
from .processes import top_processes
from .utils import DEFAULT_SCAN_SECONDS, safe_get_folder_size, scan_folder
from .win_battery import read_battery_health
from .win_security import read_security_state
from .win_storage import read_drive_health

try:
    import psutil as _psutil
except ImportError:  # A clear error is raised when analysis actually starts.
    _psutil = None

#: Upper bounds that keep the report readable and the run short on unusual machines.
_MAX_PARTITIONS = 12
_MAX_NETWORK_INTERFACES = 8

#: Wall-clock ceiling for all folder measuring in one analysis - the TEMP folders and the
#: well-known user folders together. Walking a disk is the only part of the run whose cost
#: depends on what is stored on the machine rather than on the machine itself, so it is the
#: only part that needs a ceiling; everything else costs about a second and a half, which
#: keeps even a worst-case run comfortably inside ten seconds.
TOTAL_SCAN_SECONDS = 8.0

#: The share of that budget the TEMP folders may claim. TEMP is measured first because its
#: size is the number the report leads with, and it normally finishes in a fraction of its
#: share - whatever it leaves behind is handed to the folder scan, which can always use more.
_TEMP_SCAN_SHARE = 0.5

#: Floor for the folder scan, so a caller who asks for a very long TEMP scan cannot reduce it
#: to an instant "0 bytes, truncated" - a measurement nobody could act on.
_MIN_FOLDER_SCAN_SECONDS = 1.0

#: Progress callback: (step key, fraction between 0.0 and 1.0). The key is one of
#: :data:`PROGRESS_LABELS`, never a sentence: only the caller knows which language its
#: interface speaks, and a collector must not hand it English prose it then has to guess at.
ProgressCallback = Callable[[str, float], None]

#: Every step :func:`analyze_pc` reports, in the order it reports them, with the English
#: label of each. Consumers render ``translator.t(f"progress.{key}", PROGRESS_LABELS[key])``,
#: so a catalogue that has no entry for a step still shows readable English.
PROGRESS_LABELS: dict[str, str] = {
    "system": "Reading system information",
    "cpu": "Measuring CPU usage",
    "ram": "Reading memory usage",
    "disk": "Reading drives",
    "partitions": "Reading partitions",
    "drive_health": "Reading drive health",
    "processes": "Counting processes",
    "top_processes": "Ranking processes",
    "temp": "Measuring temporary files",
    "folders": "Measuring the biggest folders",
    "security": "Reading protection settings",
    "extras": "Reading hardware details",
    "done": "Analysis complete",
}


class MissingDependencyError(RuntimeError):
    """Raised when a runtime dependency required for analysis is unavailable."""


def _psutil_module(candidate: ModuleType | Any | None = None) -> Any:
    module = candidate if candidate is not None else _psutil
    if module is None:
        raise MissingDependencyError(
            "The 'psutil' package is required. Run: python -m pip install -r requirements.txt"
        )
    return module


def _notify(progress: ProgressCallback | None, step_key: str, fraction: float) -> None:
    """Report a step to the caller. A broken callback must never abort the analysis."""
    if progress is None:
        return
    try:
        progress(step_key, max(0.0, min(1.0, float(fraction))))
    except Exception:
        pass


def _windows_release(version: str, fallback: str) -> str:
    try:
        build = int(version.split(".")[-1])
    except (ValueError, IndexError):
        return fallback or "Unknown"
    if build >= 22000:
        return "11"
    if build >= 10240:
        return "10"
    return fallback or "Unknown"


def _processor_name() -> str:
    registry_name = win_registry.read_processor_name()
    if registry_name:
        return registry_name

    candidates = (
        platform.processor(),
        getattr(platform.uname(), "processor", ""),
        os.environ.get("PROCESSOR_IDENTIFIER", ""),
        platform.machine(),
    )
    return next((" ".join(item.split()) for item in candidates if item and item.strip()), "Unknown")


#: EditionID values are compact ("Professional"); these are the names users recognise.
_EDITION_NAMES = {
    "core": "Home",
    "coren": "Home N",
    "coresinglelanguage": "Home Single Language",
    "education": "Education",
    "enterprise": "Enterprise",
    "enterprises": "Enterprise LTSC",
    "professional": "Pro",
    "professionaleducation": "Pro Education",
    "professionaln": "Pro N",
    "professionalworkstation": "Pro for Workstations",
    "serverstandard": "Server Standard",
}

_PRODUCT_NAME_PATTERN = re.compile(r"(?i)^windows\s+(?:\d+|vista|xp)\s+(.+)$")


def _edition_label(product_name: str | None, edition_id: str | None) -> str | None:
    """
    Derive a friendly edition such as "Pro".

    ProductName is preferred because it already carries the localised marketing suffix;
    EditionID is the fallback for hives where ProductName is missing.
    """
    if product_name:
        match = _PRODUCT_NAME_PATTERN.match(product_name)
        if match:
            return match.group(1).strip() or None
    if edition_id:
        return _EDITION_NAMES.get(edition_id.lower(), edition_id)
    return None


def get_system_info() -> SystemInfo:
    """Identify the operating system and the machine it runs on, from registry data."""
    system = platform.system() or "Unknown"
    version = platform.version() or "Unknown"
    release = platform.release() or "Unknown"

    edition: str | None = None
    display_version: str | None = None
    build: str | None = None
    install_date: datetime | None = None
    firmware: dict[str, object] = {}

    if system == "Windows":
        # ProductName still reads "Windows 10" on Windows 11, so the marketing number is
        # taken from the build and only the edition suffix comes from the registry.
        release = _windows_release(version, release)
        details = win_registry.windows_edition_details()
        edition = _edition_label(
            details.get("product_name"),  # type: ignore[arg-type]
            details.get("edition"),  # type: ignore[arg-type]
        )
        display_version = details.get("display_version")  # type: ignore[assignment]
        build = details.get("build")  # type: ignore[assignment]
        install_date = details.get("install_date")  # type: ignore[assignment]
        firmware = win_registry.read_firmware()

        display_name = f"Windows {release}" if release != "Unknown" else "Windows"
        if edition:
            display_name = f"{display_name} {edition}"
    else:
        display_name = f"{system} {release}".strip()

    return SystemInfo(
        os_name=display_name,
        release=release,
        version=version,
        architecture=platform.machine() or platform.architecture()[0] or "Unknown",
        processor=_processor_name(),
        edition=edition,
        display_version=display_version,
        build=build,
        install_date=install_date,
        boot_time=None,  # Filled by analyze_pc, which already holds a psutil module.
        manufacturer=firmware.get("manufacturer"),  # type: ignore[arg-type]
        model=firmware.get("model"),  # type: ignore[arg-type]
        bios_version=firmware.get("bios_version"),  # type: ignore[arg-type]
    )


def get_cpu_info(psutil_module: Any | None = None, interval: float = 1.0) -> CPUInfo:
    """Sample CPU load once and describe the processor topology and clock."""
    psutil = _psutil_module(psutil_module)
    sample_interval = max(0.0, interval)

    per_core: tuple[float, ...] = ()
    usage: float | None
    try:
        # One percpu sample pays the interval only once; the overall load is its mean.
        readings = psutil.cpu_percent(interval=sample_interval, percpu=True)
        per_core = tuple(float(value) for value in readings)
        usage = sum(per_core) / len(per_core) if per_core else None
    except (TypeError, AttributeError):
        # Older or stubbed psutil modules without percpu support keep the v1.0 behaviour.
        per_core = ()
        usage = float(psutil.cpu_percent(interval=sample_interval))

    frequency, max_frequency = _cpu_frequency(psutil)
    return CPUInfo(
        physical_cores=psutil.cpu_count(logical=False),
        logical_cores=psutil.cpu_count(logical=True),
        usage_percent=usage,
        per_core_percent=per_core,
        frequency_mhz=frequency,
        max_frequency_mhz=max_frequency,
    )


def _cpu_frequency(psutil: Any) -> tuple[float | None, float | None]:
    """Read the current/maximum clock. Virtual machines often expose neither."""
    try:
        frequency = psutil.cpu_freq()
    except Exception:  # Raises NotImplementedError or OSError on several platforms.
        return None, None
    if frequency is None:
        return None, None

    current = getattr(frequency, "current", None)
    maximum = getattr(frequency, "max", None)
    current = float(current) if current else None
    maximum = float(maximum) if maximum else None
    return current, maximum


def get_ram_info(psutil_module: Any | None = None) -> RAMInfo:
    """Report physical memory plus the page file, which hides real memory pressure."""
    psutil = _psutil_module(psutil_module)
    memory = psutil.virtual_memory()

    swap_total: int | None = None
    swap_used: int | None = None
    swap_percent: float | None = None
    try:
        swap = psutil.swap_memory()
        swap_total = int(swap.total)
        swap_used = int(swap.used)
        swap_percent = float(swap.percent)
    except Exception:
        pass

    return RAMInfo(
        total_bytes=int(memory.total),
        available_bytes=int(memory.available),
        used_bytes=int(memory.used),
        usage_percent=float(memory.percent),
        swap_total_bytes=swap_total,
        swap_used_bytes=swap_used,
        swap_percent=swap_percent,
    )


def get_system_drive() -> str:
    if os.name == "nt":
        drive = (os.environ.get("SystemDrive") or "C:").rstrip("\\/")
        return f"{drive}\\"
    return Path.home().anchor or os.sep


def _same_mount(left: str, right: str) -> bool:
    return os.path.normcase(left.rstrip("\\/")) == os.path.normcase(right.rstrip("\\/"))


def _partition_entry(psutil: Any, target: str) -> Any | None:
    """Find the psutil partition record describing a mount point, if it is listed."""
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception:
        return None
    for partition in partitions or ():
        try:
            if _same_mount(str(partition.mountpoint), target):
                return partition
        except Exception:
            continue
    return None


def get_disk_info(psutil_module: Any | None = None, drive: str | None = None) -> DiskInfo:
    """Measure one drive and label it with its filesystem and rotational media type."""
    psutil = _psutil_module(psutil_module)
    target = drive or get_system_drive()
    usage = psutil.disk_usage(target)

    partition = _partition_entry(psutil, target)
    filesystem = None
    if partition is not None:
        filesystem = str(getattr(partition, "fstype", "") or "").strip() or None

    return DiskInfo(
        drive=target,
        total_bytes=int(usage.total),
        used_bytes=int(usage.used),
        free_bytes=int(usage.free),
        usage_percent=float(usage.percent),
        filesystem=filesystem,
        media_type=detect_media_type(target),
        is_system=_same_mount(target, get_system_drive()),
    )


def get_partitions(psutil_module: Any | None = None) -> list[DiskInfo]:
    """List every fixed drive. Optical drives and unreadable mounts are skipped."""
    psutil = _psutil_module(psutil_module)
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception:
        return []

    system_drive = get_system_drive()
    results: list[DiskInfo] = []
    for partition in partitions or ():
        try:
            mountpoint = str(getattr(partition, "mountpoint", "") or "").strip()
            options = str(getattr(partition, "opts", "") or "").lower()
            if not mountpoint or "cdrom" in options:
                continue
            usage = psutil.disk_usage(mountpoint)
            if int(usage.total) <= 0:  # Empty card readers and unmounted media.
                continue
            results.append(
                DiskInfo(
                    drive=mountpoint,
                    total_bytes=int(usage.total),
                    used_bytes=int(usage.used),
                    free_bytes=int(usage.free),
                    usage_percent=float(usage.percent),
                    filesystem=str(getattr(partition, "fstype", "") or "").strip() or None,
                    media_type=detect_media_type(mountpoint),
                    is_system=_same_mount(mountpoint, system_drive),
                )
            )
        except Exception:
            # A drive that refuses to answer is left out rather than reported as empty.
            continue
        if len(results) >= _MAX_PARTITIONS:
            break
    return results


#: Media type per drive letter. Hardware does not change under a running analysis and the
#: device round trip costs a millisecond or two, so the answer is remembered per process.
_MEDIA_TYPE_CACHE: dict[str, str | None] = {}


def detect_media_type(drive: str) -> str | None:
    """
    Best-effort "SSD" / "HDD" classification, or None when Windows will not say.

    The classification is read by :mod:`win_storage`, which is the single source for
    everything this application learns from a physical disk. That matters for more than tidy
    code: until v2.1 the seek-penalty IOCTL was implemented twice, and two implementations of
    one measurement are two chances for the same drive to read "SSD" beside its free space and
    something else beside its wear figures. The device is still opened with
    ``dwDesiredAccess = 0`` - metadata queries only, no administrator rights, nothing written.
    """
    letter = _drive_letter(drive)
    if letter is None or platform.system() != "Windows":
        return None
    if letter in _MEDIA_TYPE_CACHE:
        return _MEDIA_TYPE_CACHE[letter]

    try:
        entries = read_drive_health([f"{letter}:\\"])
    except Exception:  # read_drive_health is defensive already; this is belt and braces.
        entries = []
    media_type = entries[0].media_type if entries else None
    _MEDIA_TYPE_CACHE[letter] = media_type
    return media_type


def _drive_letter(drive: str) -> str | None:
    text = (drive or "").strip()
    if len(text) >= 2 and text[0].isalpha() and text[1] == ":":
        return text[0].upper()
    return None


def _fixed_mountpoints(psutil_module: Any | None = None) -> list[str] | None:
    """
    The mount points psutil lists, or None when it cannot say.

    None is not "no drives": it means the caller should let :mod:`win_storage` enumerate the
    fixed drives itself, which is a better answer than an empty health table.
    """
    module = psutil_module if psutil_module is not None else _psutil
    if module is None:
        return None
    try:
        partitions = module.disk_partitions(all=False)
    except Exception:
        return None

    mountpoints: list[str] = []
    for partition in partitions or ():
        try:
            mountpoint = str(getattr(partition, "mountpoint", "") or "").strip()
            options = str(getattr(partition, "opts", "") or "").lower()
        except Exception:
            continue
        if mountpoint and "cdrom" not in options:
            mountpoints.append(mountpoint)
    return mountpoints or None


def get_drive_health(
    psutil_module: Any | None = None,
    *,
    drives: Sequence[str] | None = None,
) -> list[DriveHealth]:
    """
    Read wear and lifetime figures for the drives behind this machine's volumes.

    ``drives`` holds mount points such as ``"C:\\"`` - normally the ones the snapshot already
    lists, so the health table describes exactly the drives the partition table does. When it
    is None the drives psutil reports are used, and when psutil cannot say either,
    :mod:`win_storage` enumerates the fixed drives itself.

    One physical disk answers once, however many volumes it carries, and a disk that reports
    nothing at all is left out rather than padding the report with a row of N/A.
    """
    targets = list(drives) if drives is not None else _fixed_mountpoints(psutil_module)
    return read_drive_health(targets)


def get_process_count(psutil_module: Any | None = None) -> int:
    psutil = _psutil_module(psutil_module)
    return len(psutil.pids())


def get_battery(
    psutil_module: Any | None = None,
    *,
    battery_health: Callable[[], dict[str, object]] | None = None,
) -> BatteryInfo | None:
    """
    Return battery state, or None on a desktop that simply has no battery.

    Two independent sources, on purpose. psutil owns what the battery is doing right now -
    charge, plug state, estimated time left - and :mod:`win_battery` owns what the pack has
    become: its design and full-charge capacity, its cycle count, its chemistry. Neither can
    cost the other: a machine whose firmware reports no capacity at all still shows its charge,
    and a wear read that fails leaves four N/A fields rather than an unreported battery.

    ``battery_health`` replaces the wear reader, so a test can describe a worn pack without one.
    """
    psutil = _psutil_module(psutil_module)
    sensors_battery = getattr(psutil, "sensors_battery", None)
    if not callable(sensors_battery):
        return None

    battery = sensors_battery()
    if battery is None:
        return None

    seconds_left = getattr(battery, "secsleft", None)
    unlimited = getattr(psutil, "POWER_TIME_UNLIMITED", -2)
    unknown = getattr(psutil, "POWER_TIME_UNKNOWN", -1)
    if seconds_left in (unlimited, unknown) or seconds_left is None or int(seconds_left) < 0:
        seconds_left = None
    else:
        seconds_left = int(seconds_left)

    plugged = getattr(battery, "power_plugged", None)
    info = BatteryInfo(
        percent=float(battery.percent) if battery.percent is not None else None,
        plugged_in=bool(plugged) if plugged is not None else None,
        seconds_left=seconds_left,
    )

    wear = _battery_wear(battery_health)
    if not wear:
        return info
    return replace(
        info,
        # A capacity of zero is a firmware placeholder, not a pack that holds nothing, so it
        # is unknown. A cycle count of zero is a real answer: the battery is new.
        design_capacity_mwh=_wear_figure(wear.get("design_capacity_mwh"), minimum=1),
        full_charge_capacity_mwh=_wear_figure(wear.get("full_charge_capacity_mwh"), minimum=1),
        cycle_count=_wear_figure(wear.get("cycle_count")),
        chemistry=_wear_text(wear.get("chemistry")),
    )


def _battery_wear(reader: Callable[[], dict[str, object]] | None) -> dict[str, object]:
    """
    Read the wear figures. Anything other than a mapping is treated as "not reported".

    A failure here is deliberately not turned into a warning: a battery that does not publish
    its capacity is the normal case on plenty of hardware, and the charge reading beside it is
    still true. Absent figures render as N/A and are never scored.
    """
    read = reader if callable(reader) else read_battery_health
    try:
        wear = read()
    except Exception:
        return {}
    return wear if isinstance(wear, dict) else {}


def _wear_figure(value: object, *, minimum: int = 0) -> int | None:
    """Keep a whole number the battery reported; anything under ``minimum`` stays unknown."""
    # bool is an int in Python, and a True capacity is a bug, not a measurement.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = int(value)
    return number if number >= minimum else None


def _wear_text(value: object) -> str | None:
    """Normalise a short label such as the battery chemistry, or None when there is none."""
    if not isinstance(value, str):
        return None
    return " ".join(value.split()) or None


def _is_loopback(name: str) -> bool:
    lowered = name.lower()
    return "loopback" in lowered or lowered in {"lo", "lo0"}


def get_network(psutil_module: Any | None = None) -> NetworkInfo:
    """Summarise traffic counters and link state. IP addresses are deliberately not read."""
    psutil = _psutil_module(psutil_module)

    sent: int | None = None
    received: int | None = None
    counters = getattr(psutil, "net_io_counters", None)
    if callable(counters):
        try:
            totals = counters()
            if totals is not None:
                sent = int(totals.bytes_sent)
                received = int(totals.bytes_recv)
        except Exception:
            pass

    interfaces: list[NetworkInterface] = []
    stats = getattr(psutil, "net_if_stats", None)
    if callable(stats):
        try:
            for name, info in (stats() or {}).items():
                if _is_loopback(str(name)):
                    continue
                speed = getattr(info, "speed", None)
                interfaces.append(
                    NetworkInterface(
                        name=str(name),
                        is_up=bool(getattr(info, "isup", False)),
                        speed_mbps=int(speed) if speed else None,
                    )
                )
        except Exception:
            interfaces = []

    interfaces.sort(key=lambda item: (not item.is_up, -(item.speed_mbps or 0), item.name.lower()))
    return NetworkInfo(
        bytes_sent=sent,
        bytes_received=received,
        interfaces=tuple(interfaces[:_MAX_NETWORK_INTERFACES]),
    )


#: Checked in this order, matching what the C runtime and Windows itself hand to programs.
_TEMP_ENVIRONMENT_VARIABLES = ("TMP", "TEMP", "TMPDIR")


def _default_temp_path() -> str:
    """
    Resolve the temp folder without touching the disk.

    ``tempfile.gettempdir()`` proves a candidate is usable by creating, writing and then
    deleting a probe file inside it. That is a real write, and this application promises
    it performs none, so the environment is read first and only an environment with no
    temp variable at all falls through to the standard library.

    The accepted trade-off: ``gettempdir()`` validates writability and silently moves on
    to the next candidate when a folder is unusable, whereas the environment value is
    taken as-is. A broken TMP therefore surfaces as an unreadable folder with an unknown
    size, which is the honest answer, instead of a size measured somewhere else entirely.
    :func:`get_temp_locations` is where that promise is kept: it refuses to scan a path
    that is not an accessible directory, so the size stays unknown rather than zero.
    """
    for variable in _TEMP_ENVIRONMENT_VARIABLES:
        value = (os.environ.get(variable) or "").strip()
        if value:
            return value
    return tempfile.gettempdir()


def get_temp_size(temp_path: str | os.PathLike[str] | None = None) -> tuple[str, int]:
    """
    v1.0 compatibility wrapper: ``(path, size_bytes)`` for one folder.

    Its ``int`` return has no way to say "unknown", so a folder that is missing or cannot be
    listed still comes back as 0 bytes here. Nothing in the application reads this function -
    :func:`get_temp_locations` is what the snapshot is built from, and that one reports an
    unmeasurable folder as ``None``.
    """
    path = os.fspath(temp_path) if temp_path is not None else _default_temp_path()
    return path, safe_get_folder_size(path)


def _is_listable_directory(path: str) -> bool:
    """
    Whether ``path`` is a directory this account is actually allowed to list.

    ``scan_folder`` answers "0 bytes, 0 files" for a folder that is missing or refuses to
    open, and that is indistinguishable from a genuinely empty one - a TEMP folder that does
    not exist would be scored as a spotlessly clean one. Opening the directory and asking for
    its first entry costs one listing and turns "cannot look" back into "unknown", which is
    the only answer the app is entitled to give.
    """
    try:
        if not os.path.isdir(path):
            return False
        with os.scandir(path) as entries:  # Listing is the permission that matters here.
            next(iter(entries), None)
    except (OSError, ValueError):
        return False
    return True


def _windows_temp_folder() -> str | None:
    """The machine-wide temp folder, when this account is allowed to list it."""
    root = os.environ.get("SystemRoot") or os.environ.get("windir")
    if not root:
        return None
    folder = os.path.join(root, "Temp")
    return folder if _is_listable_directory(folder) else None


def _resolved(path: str) -> str:
    try:
        return os.path.normcase(os.path.realpath(path))
    except (OSError, ValueError):
        return os.path.normcase(path)


def get_temp_locations(
    psutil_module: Any | None = None,
    *,
    temp_path: str | os.PathLike[str] | None = None,
    max_seconds: float | None = None,
) -> list[TempLocation]:
    """
    Measure the temp folders, sharing one time budget between them.

    ``psutil_module`` is accepted for call-site symmetry with the other collectors; folder
    scanning needs no psutil. The user TEMP entry always comes first: the rest of the app
    treats it as the primary measurement.

    A candidate that is not an accessible directory is listed with ``size_bytes=None``: it
    was never measured, and reporting it as 0 bytes would invent a spotless TEMP folder out
    of a broken TMP variable.
    """
    del psutil_module  # Intentionally unused; kept so every collector has one call shape.

    user_temp = os.fspath(temp_path) if temp_path is not None else _default_temp_path()
    candidates: list[tuple[str, str]] = [("User TEMP", user_temp)]

    windows_temp = _windows_temp_folder()
    if windows_temp and _resolved(windows_temp) != _resolved(user_temp):
        candidates.append(("Windows TEMP", windows_temp))

    budget = DEFAULT_SCAN_SECONDS if max_seconds is None else max(0.0, float(max_seconds))
    per_location = budget / len(candidates)

    locations: list[TempLocation] = []
    for label, path in candidates:
        if not _is_listable_directory(path):
            # Missing, not a folder, or not listable by this account: unknown, not empty.
            locations.append(TempLocation(label=label, path=path))
            continue
        try:
            size, files, truncated = scan_folder(path, max_seconds=per_location)
            locations.append(
                TempLocation(
                    label=label,
                    path=path,
                    size_bytes=size,
                    file_count=files,
                    truncated=truncated,
                )
            )
        except Exception:
            # An unreadable folder is reported without a size instead of as "0 bytes".
            locations.append(TempLocation(label=label, path=path))
    return locations


def get_folder_usage(*, max_seconds: float | None = None, limit: int = 8) -> list[FolderUsage]:
    """
    Measure the well-known user folders, biggest first.

    The whole set shares one time budget, so a machine with a huge Downloads folder cannot
    make the analysis long. A folder that could not be measured comes back with
    ``size_bytes=None``: unknown, never "empty".
    """
    return read_folder_usage(max_seconds=max_seconds, limit=limit)


def get_security(reader: Callable[[], SecurityInfo] | None = None) -> SecurityInfo | None:
    """
    Read the Windows protection state: antivirus, firewall, Secure Boot, pending restart.

    Delegates to :func:`win_security.read_security_state`, which answers "unknown" for
    anything it may not read - a failed query never becomes "this machine is unprotected".
    None means no state could be produced at all, which is also what the snapshot carries when
    the caller skipped the step.

    ``reader`` replaces the Windows lookup, so a test can describe a machine without owning one.
    """
    read = reader if callable(reader) else read_security_state
    state = read()
    return state if isinstance(state, SecurityInfo) else None


def _temp_budget(temp_scan_seconds: float | None) -> float:
    """The seconds the TEMP measurement may spend: the caller's figure, or its share."""
    if temp_scan_seconds is None:
        return TOTAL_SCAN_SECONDS * _TEMP_SCAN_SHARE
    return max(0.0, float(temp_scan_seconds))


def _folder_budget(folder_scan_seconds: float | None, temp_elapsed: float) -> float:
    """
    What is left of the shared scan budget once TEMP has had its turn.

    TEMP normally finishes well inside its share, and handing the remainder on is what keeps
    the folder sizes worth reading without letting the two scans add up to a long analysis.
    """
    if folder_scan_seconds is not None:
        return max(0.0, float(folder_scan_seconds))
    return max(_MIN_FOLDER_SCAN_SECONDS, TOTAL_SCAN_SECONDS - max(0.0, temp_elapsed))


def get_uptime(psutil_module: Any | None = None, now: float | None = None) -> float:
    psutil = _psutil_module(psutil_module)
    current = time.time() if now is None else now
    return max(0.0, current - float(psutil.boot_time()))


def _boot_time(psutil: Any) -> datetime | None:
    try:
        return datetime.fromtimestamp(float(psutil.boot_time()), tz=timezone.utc).astimezone()
    except Exception:
        return None


def analyze_pc(
    *,
    psutil_module: Any | None = None,
    cpu_interval: float = 1.0,
    drive: str | None = None,
    temp_path: str | os.PathLike[str] | None = None,
    analyzed_at: datetime | None = None,
    top_process_limit: int = 5,
    scan_temp: bool = True,
    temp_scan_seconds: float | None = None,
    include_startup: bool = True,
    include_gpu: bool = True,
    include_security: bool = True,
    include_drive_health: bool = True,
    scan_folders: bool = True,
    folder_scan_seconds: float | None = None,
    progress: ProgressCallback | None = None,
) -> AnalysisData:
    """
    Collect all metrics. Individual collection failures become visible warnings.

    ``progress`` is called as ``(step_key, fraction)``: the key is one of
    :data:`PROGRESS_LABELS` and the fraction runs from 0.0 to 1.0. Passing the key rather
    than a sentence is what lets the console and the GUI show the step in the language the
    user chose; ``PROGRESS_LABELS[step_key]`` is the English wording to fall back on. A
    callback that raises is ignored, so a broken indicator never costs the analysis.

    Every optional step can be switched off - ``scan_temp``, ``scan_folders``,
    ``include_security``, ``include_drive_health``, ``include_startup``, ``include_gpu`` -
    and a step that did not run leaves its field empty instead of guessing at it. The two
    folder measurements share one budget (:data:`TOTAL_SCAN_SECONDS`), so measuring the user's
    folders as well as TEMP cannot double the length of a run.
    """
    psutil = _psutil_module(psutil_module)
    warnings: list[str] = []
    started = time.monotonic()

    _notify(progress, "system", 0.05)
    try:
        system = get_system_info()
    except Exception as error:
        system = SystemInfo("Unknown", "Unknown", "Unknown", "Unknown", "Unknown")
        warnings.append(f"System information could not be collected: {error}")
    system = replace(system, boot_time=_boot_time(psutil))

    _notify(progress, "cpu", 0.25)
    try:
        cpu = get_cpu_info(psutil, cpu_interval)
    except Exception as error:  # psutil may surface platform-specific OS errors.
        cpu = CPUInfo(None, None, None)
        warnings.append(f"CPU information could not be collected: {error}")

    _notify(progress, "ram", 0.35)
    try:
        ram = get_ram_info(psutil)
    except Exception as error:
        ram = RAMInfo(None, None, None, None)
        warnings.append(f"RAM information could not be collected: {error}")

    _notify(progress, "disk", 0.5)
    target_drive = drive or get_system_drive()
    try:
        disk = get_disk_info(psutil, target_drive)
    except Exception as error:
        disk = DiskInfo(target_drive, None, None, None, None)
        warnings.append(f"Disk information could not be collected: {error}")

    # Its own step: a machine with several drives spends real time here, and a progress line
    # that sat on "Reading drives" for seconds looked stuck rather than busy.
    _notify(progress, "partitions", 0.55)
    try:
        partitions = get_partitions(psutil)
    except Exception as error:
        partitions = []
        warnings.append(f"Drive list could not be collected: {error}")

    _notify(progress, "drive_health", 0.58)
    drive_health: list[DriveHealth] = []
    if include_drive_health:
        try:
            # The drives the snapshot already lists, so the wear figures and the partition
            # table describe one and the same set of drives. An empty list would mean "no
            # drives at all", so None - "work them out yourself" - is passed instead.
            drive_health = get_drive_health(
                psutil, drives=[item.drive for item in partitions] or None
            )
        except Exception as error:
            warnings.append(f"Drive health could not be read: {error}")

    _notify(progress, "processes", 0.6)
    try:
        process_count: int | None = get_process_count(psutil)
    except Exception as error:
        process_count = None
        warnings.append(f"Running processes could not be counted: {error}")

    _notify(progress, "top_processes", 0.7)
    try:
        # Memory is the ranking users act on, but the CPU column has to hold real numbers
        # for the report to be worth reading. Sampling it costs one shared pause of about
        # 0.15 s for the whole list, and a limit of zero skips the work entirely.
        processes: list[ProcessInfo] = top_processes(
            psutil, limit=top_process_limit, sort_by="memory", sample_cpu=True
        )
    except Exception as error:
        processes = []
        warnings.append(f"Process details could not be collected: {error}")

    _notify(progress, "temp", 0.78)
    resolved_temp = os.fspath(temp_path) if temp_path is not None else _default_temp_path()
    temp_size: int | None = None
    temp_truncated = False
    temp_locations: list[TempLocation] = []
    scan_started = time.monotonic()
    if scan_temp:
        try:
            temp_locations = get_temp_locations(
                temp_path=resolved_temp, max_seconds=_temp_budget(temp_scan_seconds)
            )
            if temp_locations:  # The first entry is the user TEMP folder by construction.
                resolved_temp = temp_locations[0].path
                temp_size = temp_locations[0].size_bytes
                # A budget-limited scan only ever undercounts, so the snapshot has to say
                # so; consumers must treat the size as a lower bound, not a measurement.
                temp_truncated = bool(temp_locations[0].truncated)
            for location in temp_locations:
                # A folder that was never measured leaves an unknown size behind, and an
                # unknown measurement the user cannot see is indistinguishable from a clean
                # one - so the folder the app could not look inside is named here.
                if location.size_bytes is None:
                    warnings.append(
                        f"Temporary folder {location.label} could not be measured: "
                        f"{location.path}"
                    )
        except Exception as error:
            warnings.append(f"Temporary files could not be measured: {error}")

    _notify(progress, "folders", 0.86)
    folder_usage: list[FolderUsage] = []
    if scan_folders:
        try:
            # Whatever the TEMP scan did not need is handed on here, which is why this step
            # is measured from when that one started rather than from a fresh clock.
            folder_usage = get_folder_usage(
                max_seconds=_folder_budget(
                    folder_scan_seconds, time.monotonic() - scan_started
                )
            )
        except Exception as error:
            warnings.append(f"Folder sizes could not be measured: {error}")

    _notify(progress, "security", 0.9)
    security: SecurityInfo | None = None
    if include_security:
        try:
            security = get_security()
        except Exception as error:
            warnings.append(f"Windows protection status could not be read: {error}")

    _notify(progress, "extras", 0.95)
    try:
        uptime: float | None = get_uptime(psutil)
    except Exception as error:
        uptime = None
        warnings.append(f"System uptime could not be collected: {error}")

    try:
        battery = get_battery(psutil)
    except Exception as error:
        battery = None
        warnings.append(f"Battery status could not be collected: {error}")

    try:
        network: NetworkInfo | None = get_network(psutil)
    except Exception as error:
        network = None
        warnings.append(f"Network information could not be collected: {error}")

    gpus: list[GPUInfo] = []
    if include_gpu:
        try:
            gpus = win_registry.read_gpus()
        except Exception as error:
            warnings.append(f"Graphics adapters could not be listed: {error}")

    startup_items: list[StartupItem] = []
    if include_startup:
        try:
            startup_items = win_registry.read_startup_items()
        except Exception as error:
            warnings.append(f"Startup programs could not be listed: {error}")

    _notify(progress, "done", 1.0)
    return AnalysisData(
        analyzed_at=analyzed_at or datetime.now().astimezone(),
        system=system,
        cpu=cpu,
        ram=ram,
        disk=disk,
        process_count=process_count,
        temp_path=resolved_temp,
        temp_size_bytes=temp_size,
        uptime_seconds=uptime,
        warnings=tuple(warnings),
        partitions=tuple(partitions),
        top_processes=tuple(processes),
        battery=battery,
        network=network,
        gpus=tuple(gpus),
        startup_items=tuple(startup_items),
        temp_locations=tuple(temp_locations),
        duration_seconds=round(max(0.0, time.monotonic() - started), 3),
        temp_truncated=temp_truncated,
        security=security,
        drive_health=tuple(drive_health),
        folder_usage=tuple(folder_usage),
    )
