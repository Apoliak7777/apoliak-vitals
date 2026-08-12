"""Snapshot builders shared by every test module.

``make_analysis`` keeps all v1.0 keyword names working and adds one keyword per v2.0 and
v2.1 field, so a test can describe exactly the machine it needs and leave the rest healthy.
Calling it with no arguments must always produce a snapshot that scores 100/100.

The v2.1 state fields default to "nobody looked": no security record, no drive health, no
measured folders. That is deliberate - an unknown verdict is never penalised, so a builder
that invented a healthy one would hide exactly the rule this project cares most about.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

from src.models import (
    STATE_GOOD,
    STATE_UNKNOWN,
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
from src.utils import GIB

DEFAULT_ANALYZED_AT = datetime(2026, 7, 16, 12, 30, tzinfo=timezone.utc)
DEFAULT_TEMP_PATH = r"C:\Users\Test\AppData\Local\Temp"
DEFAULT_DRIVE = "C:\\"
DEFAULT_RAM_TOTAL = 16 * GIB
DEFAULT_DISK_TOTAL = 512 * GIB


class _Unset:
    """Marker meaning "derive this value from the other arguments"."""

    def __repr__(self) -> str:  # pragma: no cover - debugging aid only
        return "<unset>"


#: Distinguishes "caller said nothing" from "caller explicitly asked for None".
UNSET = _Unset()


def make_system(**overrides: object) -> SystemInfo:
    """Build a SystemInfo. The five v1.0 fields keep their historical values."""
    fields: dict[str, object] = {
        "os_name": "Windows 11",
        "release": "11",
        "version": "10.0.26100",
        "architecture": "AMD64",
        "processor": "Test CPU",
        "edition": "Pro",
        "display_version": "24H2",
        "build": "26100.4652",
        "install_date": datetime(2025, 1, 5, 9, 0, tzinfo=timezone.utc),
        "boot_time": datetime(2026, 7, 16, 11, 30, tzinfo=timezone.utc),
        "manufacturer": "Test Systems",
        "model": "TS-1000",
        "bios_version": "1.24",
    }
    fields.update(overrides)
    return SystemInfo(**fields)  # type: ignore[arg-type]


def make_process(
    pid: int = 1000,
    name: str = "app.exe",
    *,
    cpu_percent: float | None = None,
    memory_bytes: int | None = GIB,
    memory_percent: float | None = None,
) -> ProcessInfo:
    return ProcessInfo(
        pid=pid,
        name=name,
        cpu_percent=cpu_percent,
        memory_bytes=memory_bytes,
        memory_percent=memory_percent,
    )


def make_partition(
    drive: str = "D:\\",
    *,
    total: int | None = 1024 * GIB,
    free: int | None = 512 * GIB,
    filesystem: str | None = "NTFS",
    media_type: str | None = "SSD",
    is_system: bool = False,
) -> DiskInfo:
    used = total - free if total is not None and free is not None else None
    percent = used / total * 100 if used is not None and total else None
    return DiskInfo(
        drive=drive,
        total_bytes=total,
        used_bytes=used,
        free_bytes=free,
        usage_percent=percent,
        filesystem=filesystem,
        media_type=media_type,
        is_system=is_system,
    )


def make_battery(
    percent: float | None = 80.0,
    plugged_in: bool | None = True,
    seconds_left: int | None = None,
    *,
    design_capacity_mwh: int | None = None,
    full_charge_capacity_mwh: int | None = None,
    cycle_count: int | None = None,
    chemistry: str | None = None,
) -> BatteryInfo:
    """A battery. The wear figures stay unreported unless a test asks for them."""
    return BatteryInfo(
        percent=percent,
        plugged_in=plugged_in,
        seconds_left=seconds_left,
        design_capacity_mwh=design_capacity_mwh,
        full_charge_capacity_mwh=full_charge_capacity_mwh,
        cycle_count=cycle_count,
        chemistry=chemistry,
    )


def make_worn_battery(health_percent: float, **overrides: object) -> BatteryInfo:
    """A pack whose remaining capacity is exactly ``health_percent`` of its design.

    The design capacity is a round 100 000 mWh, so ``full_charge_capacity_mwh`` reads as the
    percentage itself and a test can name the wear it wants instead of doing the division.
    """
    fields: dict[str, object] = {
        "design_capacity_mwh": 100_000,
        "full_charge_capacity_mwh": int(round(health_percent * 1_000)),
    }
    fields.update(overrides)
    return make_battery(**fields)  # type: ignore[arg-type]


def make_security(**overrides: object) -> SecurityInfo:
    """A protection record. Everything is healthy unless the test says otherwise."""
    fields: dict[str, object] = {
        "antivirus": STATE_GOOD,
        "antivirus_name": None,
        "firewall": STATE_GOOD,
        "secure_boot": STATE_GOOD,
        "reboot_pending": False,
        "defender_last_scan": datetime(2026, 7, 16, 6, 0, tzinfo=timezone.utc),
        "signature_age_days": 0,
        "details": (),
    }
    fields.update(overrides)
    return SecurityInfo(**fields)  # type: ignore[arg-type]


def unreadable_security() -> SecurityInfo:
    """A machine that answered nothing at all: every verdict unknown, nothing penalised."""
    return SecurityInfo(
        antivirus=STATE_UNKNOWN,
        firewall=STATE_UNKNOWN,
        secure_boot=STATE_UNKNOWN,
        reboot_pending=None,
        signature_age_days=None,
    )


def make_drive(
    drive: str = "C:\\",
    *,
    model: str | None = "Test NVMe 1TB",
    bus_type: str | None = "NVMe",
    media_type: str | None = "SSD",
    percentage_used: int | None = 5,
    temperature_celsius: int | None = 40,
    power_on_hours: int | None = 2_400,
    data_written_bytes: int | None = 40 * GIB,
    critical_warning: bool | None = False,
    source: str | None = "NVMe SMART log",
) -> DriveHealth:
    """One drive's wear figures. The defaults describe a healthy, nearly new SSD."""
    return DriveHealth(
        drive=drive,
        model=model,
        bus_type=bus_type,
        media_type=media_type,
        percentage_used=percentage_used,
        temperature_celsius=temperature_celsius,
        power_on_hours=power_on_hours,
        data_written_bytes=data_written_bytes,
        critical_warning=critical_warning,
        source=source,
    )


def silent_drive(drive: str = "C:\\", **overrides: object) -> DriveHealth:
    """A drive that names itself and reports no figure at all - unknown, never healthy."""
    fields: dict[str, object] = {
        "model": "Test SATA 1TB",
        "bus_type": "SATA",
        "media_type": None,
        "percentage_used": None,
        "temperature_celsius": None,
        "power_on_hours": None,
        "data_written_bytes": None,
        "critical_warning": None,
        "source": None,
    }
    fields.update(overrides)
    return make_drive(drive, **fields)  # type: ignore[arg-type]


def make_folder(
    key: str = "downloads",
    label: str | None = None,
    path: str | None = None,
    *,
    size_bytes: int | None = 4 * GIB,
    file_count: int | None = 120,
    truncated: bool = False,
) -> FolderUsage:
    """One measured user folder; the label and path follow the key unless overridden."""
    return FolderUsage(
        key=key,
        label=label if label is not None else key.replace("_", " ").title(),
        path=path if path is not None else rf"C:\Users\Test\{key}",
        size_bytes=size_bytes,
        file_count=file_count,
        truncated=truncated,
    )


def make_network(
    *,
    bytes_sent: int | None = 12 * GIB,
    bytes_received: int | None = 48 * GIB,
    interfaces: Sequence[NetworkInterface] | None = None,
) -> NetworkInfo:
    if interfaces is None:
        interfaces = (
            NetworkInterface("Ethernet", True, 1000),
            NetworkInterface("Wi-Fi", False, None),
        )
    return NetworkInfo(
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        interfaces=tuple(interfaces),
    )


def make_gpu(name: str = "Test Graphics 700", **overrides: object) -> GPUInfo:
    fields: dict[str, object] = {
        "name": name,
        "driver_version": "31.0.15.4601",
        "driver_date": "2025-03-14",
        "memory_bytes": 8 * GIB,
    }
    fields.update(overrides)
    return GPUInfo(**fields)  # type: ignore[arg-type]


def make_startup_items(count: int, *, source: str = "HKCU Run") -> tuple[StartupItem, ...]:
    """Build ``count`` distinct startup entries, which is all the score ever counts."""
    return tuple(
        StartupItem(name=f"Autostart {index + 1}", source=source, command=f"app{index + 1}.exe")
        for index in range(max(0, int(count)))
    )


def make_temp_location(
    label: str = "User TEMP",
    path: str = DEFAULT_TEMP_PATH,
    *,
    size_bytes: int | None = GIB // 2,
    file_count: int | None = 128,
    truncated: bool = False,
) -> TempLocation:
    return TempLocation(
        label=label,
        path=path,
        size_bytes=size_bytes,
        file_count=file_count,
        truncated=truncated,
    )


def make_analysis(
    *,
    # --- v1.0 keywords, unchanged names, values and defaults ---
    cpu_percent: float | None = 20,
    ram_percent: float | None = 40,
    disk_free: int | None = 100 * GIB,
    process_count: int | None = 100,
    temp_size: int | None = GIB // 2,
    uptime: float | None = 60 * 60,
    warnings: tuple[str, ...] = (),
    # --- v2.0 additions, all optional ---
    physical_cores: int | None = 6,
    logical_cores: int | None = 12,
    per_core: Sequence[float] | None | _Unset = UNSET,
    frequency_mhz: float | None = 2400.0,
    max_frequency_mhz: float | None = 3600.0,
    ram_total: int | None | _Unset = UNSET,
    swap_total: int | None = 8 * GIB,
    swap_used: int | None | _Unset = UNSET,
    swap_percent: float | None = 10.0,
    drive: str = DEFAULT_DRIVE,
    disk_total: int | None | _Unset = UNSET,
    disk_percent: float | None | _Unset = UNSET,
    filesystem: str | None = "NTFS",
    media_type: str | None = "SSD",
    disk_is_system: bool = True,
    system: SystemInfo | None = None,
    partitions: Sequence[DiskInfo] = (),
    top_processes: Sequence[ProcessInfo] = (),
    battery: BatteryInfo | None = None,
    battery_percent: float | None = None,
    battery_plugged: bool | None = None,
    battery_health: float | None = None,
    network: NetworkInfo | None = None,
    gpus: Sequence[GPUInfo] = (),
    startup_items: Sequence[StartupItem] | None = None,
    startup_count: int = 0,
    temp_locations: Sequence[TempLocation] = (),
    temp_path: str = DEFAULT_TEMP_PATH,
    temp_truncated: bool = False,
    # --- v2.1 additions: durable state. All absent by default, which is "nobody looked" ---
    security: SecurityInfo | None = None,
    drive_health: Sequence[DriveHealth] = (),
    folder_usage: Sequence[FolderUsage] = (),
    analyzed_at: datetime | None = None,
    duration_seconds: float | None = None,
    schema_version: str | None = None,
) -> AnalysisData:
    """Build one AnalysisData. Every default describes a healthy, fully measurable PC."""
    resolved_ram_total = DEFAULT_RAM_TOTAL if ram_percent is not None else None
    if not isinstance(ram_total, _Unset):
        resolved_ram_total = ram_total
    ram_used = (
        int(resolved_ram_total * ram_percent / 100)
        if resolved_ram_total is not None and ram_percent is not None
        else None
    )
    ram_available = (
        resolved_ram_total - ram_used
        if resolved_ram_total is not None and ram_used is not None
        else None
    )

    resolved_swap_used: int | None
    if isinstance(swap_used, _Unset):
        resolved_swap_used = (
            int(swap_total * swap_percent / 100)
            if swap_total is not None and swap_percent is not None
            else None
        )
    else:
        resolved_swap_used = swap_used

    resolved_disk_total = DEFAULT_DISK_TOTAL if disk_free is not None else None
    if not isinstance(disk_total, _Unset):
        resolved_disk_total = disk_total
    disk_used = (
        resolved_disk_total - disk_free
        if resolved_disk_total is not None and disk_free is not None
        else None
    )
    resolved_disk_percent: float | None
    if isinstance(disk_percent, _Unset):
        resolved_disk_percent = (
            disk_used / resolved_disk_total * 100
            if disk_used is not None and resolved_disk_total
            else None
        )
    else:
        resolved_disk_percent = disk_percent

    if isinstance(per_core, _Unset):
        # Four cores whose mean is exactly ``cpu_percent`` keeps derived values honest.
        resolved_per_core: tuple[float, ...] = (
            ()
            if cpu_percent is None
            else (
                max(0.0, float(cpu_percent) - 5.0),
                float(cpu_percent),
                float(cpu_percent),
                float(cpu_percent) + 5.0,
            )
        )
    else:
        resolved_per_core = tuple(per_core or ())

    resolved_battery = battery
    if resolved_battery is None and (battery_percent is not None or battery_health is not None):
        wear: dict[str, object] = {}
        if battery_health is not None:
            # One round design capacity, so the caller names the wear instead of dividing.
            wear = {
                "design_capacity_mwh": 100_000,
                "full_charge_capacity_mwh": int(round(battery_health * 1_000)),
            }
        resolved_battery = BatteryInfo(
            percent=battery_percent,
            plugged_in=battery_plugged,
            **wear,  # type: ignore[arg-type]
        )

    resolved_startup = (
        tuple(startup_items) if startup_items is not None else make_startup_items(startup_count)
    )

    extra = {} if schema_version is None else {"schema_version": schema_version}
    return AnalysisData(
        analyzed_at=analyzed_at or DEFAULT_ANALYZED_AT,
        system=system if system is not None else make_system(),
        cpu=CPUInfo(
            physical_cores=physical_cores,
            logical_cores=logical_cores,
            usage_percent=cpu_percent,
            per_core_percent=resolved_per_core,
            frequency_mhz=frequency_mhz,
            max_frequency_mhz=max_frequency_mhz,
        ),
        ram=RAMInfo(
            total_bytes=resolved_ram_total,
            available_bytes=ram_available,
            used_bytes=ram_used,
            usage_percent=ram_percent,
            swap_total_bytes=swap_total,
            swap_used_bytes=resolved_swap_used,
            swap_percent=swap_percent,
        ),
        disk=DiskInfo(
            drive=drive,
            total_bytes=resolved_disk_total,
            used_bytes=disk_used,
            free_bytes=disk_free,
            usage_percent=resolved_disk_percent,
            filesystem=filesystem,
            media_type=media_type,
            is_system=disk_is_system,
        ),
        process_count=process_count,
        temp_path=temp_path,
        temp_size_bytes=temp_size,
        uptime_seconds=uptime,
        warnings=tuple(warnings),
        partitions=tuple(partitions),
        top_processes=tuple(top_processes),
        battery=resolved_battery,
        network=network,
        gpus=tuple(gpus),
        startup_items=resolved_startup,
        temp_locations=tuple(temp_locations),
        security=security,
        drive_health=tuple(drive_health),
        folder_usage=tuple(folder_usage),
        duration_seconds=duration_seconds,
        # A truncated TEMP scan is a property of the snapshot, not of one location, because
        # every consumer has to treat ``temp_size_bytes`` as a floor once it is set.
        temp_truncated=bool(temp_truncated),
        **extra,  # type: ignore[arg-type]
    )
