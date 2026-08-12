"""Typed data models shared by the console app, GUI, exporters, and history store.

Every model is immutable. Collectors build a single snapshot; every other module in the
project reads that snapshot and never touches an operating-system API again.

Fields added after v1.0 carry defaults, so an older snapshot still constructs cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

#: Version of the exported snapshot structure. Raised when a field changes meaning.
SCHEMA_VERSION = "2.1"

#: Severity levels shared by deductions and recommendations, ordered least to most urgent.
SEVERITY_ORDER: tuple[str, ...] = ("info", "warning", "critical")

#: Stable category keys used by the score, the recommendations, and the interfaces.
CATEGORY_CPU = "cpu"
CATEGORY_MEMORY = "memory"
CATEGORY_STORAGE = "storage"
CATEGORY_MAINTENANCE = "maintenance"
CATEGORY_POWER = "power"
CATEGORY_SECURITY = "security"
CATEGORY_GENERAL = "general"

#: Health verdicts a collector may report. "unknown" means the value could not be read and,
#: per the project rule, is never penalised.
STATE_GOOD = "good"
STATE_WEAK = "weak"
STATE_BAD = "bad"
STATE_UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class SystemInfo:
    os_name: str
    release: str
    version: str
    architecture: str
    processor: str
    edition: str | None = None
    display_version: str | None = None
    build: str | None = None
    install_date: datetime | None = None
    boot_time: datetime | None = None
    manufacturer: str | None = None
    model: str | None = None
    bios_version: str | None = None


@dataclass(frozen=True, slots=True)
class CPUInfo:
    physical_cores: int | None
    logical_cores: int | None
    usage_percent: float | None
    per_core_percent: tuple[float, ...] = ()
    frequency_mhz: float | None = None
    max_frequency_mhz: float | None = None


@dataclass(frozen=True, slots=True)
class RAMInfo:
    total_bytes: int | None
    available_bytes: int | None
    used_bytes: int | None
    usage_percent: float | None
    swap_total_bytes: int | None = None
    swap_used_bytes: int | None = None
    swap_percent: float | None = None


@dataclass(frozen=True, slots=True)
class DiskInfo:
    drive: str
    total_bytes: int | None
    used_bytes: int | None
    free_bytes: int | None
    usage_percent: float | None
    filesystem: str | None = None
    media_type: str | None = None
    is_system: bool = False


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    pid: int
    name: str
    cpu_percent: float | None = None
    memory_bytes: int | None = None
    memory_percent: float | None = None


@dataclass(frozen=True, slots=True)
class BatteryInfo:
    percent: float | None
    plugged_in: bool | None
    seconds_left: int | None = None
    #: Battery wear: the pack's original capacity versus what it still holds today.
    design_capacity_mwh: int | None = None
    full_charge_capacity_mwh: int | None = None
    cycle_count: int | None = None
    chemistry: str | None = None

    @property
    def health_percent(self) -> float | None:
        """Remaining capacity as a share of the design capacity, or None when unknown."""
        design = self.design_capacity_mwh
        full = self.full_charge_capacity_mwh
        if not design or full is None or design <= 0:
            return None
        return max(0.0, min(100.0, full / design * 100.0))


@dataclass(frozen=True, slots=True)
class DriveHealth:
    """
    Wear and lifetime figures for one physical drive.

    Populated only from queries that work without administrator rights. Anything the drive
    does not report stays None — a missing figure is never estimated.
    """

    drive: str
    model: str | None = None
    bus_type: str | None = None
    media_type: str | None = None
    percentage_used: int | None = None
    temperature_celsius: int | None = None
    power_on_hours: int | None = None
    data_written_bytes: int | None = None
    critical_warning: bool | None = None
    source: str | None = None

    @property
    def life_left_percent(self) -> int | None:
        if self.percentage_used is None:
            return None
        return max(0, 100 - int(self.percentage_used))


@dataclass(frozen=True, slots=True)
class SecurityInfo:
    """
    Read-only view of the Windows protection settings a user can actually act on.

    Every field is a STATE_* verdict or None. The analyzer never changes any of them.
    """

    antivirus: str = STATE_UNKNOWN
    antivirus_name: str | None = None
    firewall: str = STATE_UNKNOWN
    secure_boot: str = STATE_UNKNOWN
    reboot_pending: bool | None = None
    defender_last_scan: datetime | None = None
    signature_age_days: int | None = None
    details: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class FolderUsage:
    """One well-known folder measured by the same defensive walker TEMP uses."""

    key: str
    label: str
    path: str
    size_bytes: int | None = None
    file_count: int | None = None
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class NetworkInterface:
    name: str
    is_up: bool
    speed_mbps: int | None = None


@dataclass(frozen=True, slots=True)
class NetworkInfo:
    bytes_sent: int | None = None
    bytes_received: int | None = None
    interfaces: tuple[NetworkInterface, ...] = ()


@dataclass(frozen=True, slots=True)
class GPUInfo:
    name: str
    driver_version: str | None = None
    driver_date: str | None = None
    memory_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class StartupItem:
    name: str
    source: str
    command: str | None = None


@dataclass(frozen=True, slots=True)
class TempLocation:
    label: str
    path: str
    size_bytes: int | None = None
    file_count: int | None = None
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class AnalysisData:
    """One immutable, read-only snapshot of a PC."""

    analyzed_at: datetime
    system: SystemInfo
    cpu: CPUInfo
    ram: RAMInfo
    disk: DiskInfo
    process_count: int | None
    temp_path: str
    temp_size_bytes: int | None
    uptime_seconds: float | None
    warnings: tuple[str, ...] = ()
    partitions: tuple[DiskInfo, ...] = ()
    top_processes: tuple[ProcessInfo, ...] = ()
    battery: BatteryInfo | None = None
    network: NetworkInfo | None = None
    gpus: tuple[GPUInfo, ...] = ()
    startup_items: tuple[StartupItem, ...] = ()
    temp_locations: tuple[TempLocation, ...] = ()
    duration_seconds: float | None = None
    #: True when the TEMP measurement hit its time budget, so the size is a lower bound only.
    temp_truncated: bool = False
    security: SecurityInfo | None = None
    drive_health: tuple[DriveHealth, ...] = ()
    folder_usage: tuple[FolderUsage, ...] = ()
    schema_version: str = SCHEMA_VERSION


@dataclass(frozen=True, slots=True)
class ScoreDeduction:
    key: str
    points: int
    reason: str
    category: str = CATEGORY_GENERAL
    severity: str = "warning"
    #: Values referenced by ``reason``, kept separately so translations can reuse them.
    params: tuple[tuple[str, str], ...] = ()

    @property
    def values(self) -> dict[str, str]:
        return dict(self.params)


@dataclass(frozen=True, slots=True)
class CategoryScore:
    """Sub-score for one area, so a single weak area is visible instead of averaged away."""

    key: str
    label: str
    score: int
    deductions: tuple[ScoreDeduction, ...] = ()
    available: bool = True

    @property
    def lost_points(self) -> int:
        return sum(item.points for item in self.deductions)


@dataclass(frozen=True, slots=True)
class HealthAssessment:
    score: int
    status: str
    deductions: tuple[ScoreDeduction, ...]
    data_complete: bool
    categories: tuple[CategoryScore, ...] = ()

    @property
    def total_deduction(self) -> int:
        return sum(item.points for item in self.deductions)

    def category(self, key: str) -> CategoryScore | None:
        return next((item for item in self.categories if item.key == key), None)


@dataclass(frozen=True, slots=True)
class Recommendation:
    """A safe suggestion. The engine never performs the action it describes."""

    key: str
    text: str
    severity: str = "info"
    category: str = CATEGORY_GENERAL
    detail: str | None = None
    #: Values already substituted into ``text``, kept so translations can reuse them.
    params: tuple[tuple[str, str], ...] = ()
    #: Optional Windows settings page this advice is about, e.g. "ms-settings:startupapps".
    #: Opening it is always a deliberate user click; nothing here is ever launched
    #: automatically, and opening a settings page never changes the setting.
    action_uri: str | None = None

    @property
    def values(self) -> dict[str, str]:
        return dict(self.params)

    def __str__(self) -> str:  # Keeps v1.0 call sites that treated advice as plain text.
        return self.text


def severity_rank(severity: str) -> int:
    """Sort helper: unknown severities rank lowest so output stays deterministic."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return -1
