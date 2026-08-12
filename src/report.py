"""Plain-text report rendering and export.

The renderer never touches the operating system. It formats one immutable snapshot, so the
same function serves the console, the GUI preview, and the text exporter.

Two rules shape the layout: a section that has no data is omitted instead of printed empty,
and an unknown measurement is written as "N/A" rather than guessed.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .models import (
    STATE_BAD,
    STATE_GOOD,
    STATE_UNKNOWN,
    STATE_WEAK,
    AnalysisData,
    CategoryScore,
    DiskInfo,
    DriveHealth,
    FolderUsage,
    HealthAssessment,
    Recommendation,
    ScoreDeduction,
    SecurityInfo,
)
from .utils import (
    Ansi,
    format_bytes,
    format_count,
    format_duration,
    format_frequency,
    format_percent,
    format_uptime,
    redact_text,
)

def _package_version() -> str:
    """
    Read the version from the package, which owns it.

    Guarded because report.py is deliberately importable on its own; a trimmed install falls
    back to the last version this file shipped with rather than failing to render.
    """
    try:
        from . import __version__

        return str(__version__)
    except Exception:  # pragma: no cover - only reachable in a broken install
        return "2.1.0"


APP_NAME = "Apoliak Vitals"
APP_VERSION = _package_version()

#: Long lists are trimmed so a console report stays readable.
_MAX_LIST_ITEMS = 10
_MAX_CORES_SHOWN = 16

# English fallbacks for the count-dependent phrases. They are only reached when the caller
# handed in a translator too old to offer t_plural(); the shipped catalogue owns the wording,
# and Slovak needs a third form ("few") that English does not.
_POINT_WORDS: Mapping[str, str] = {"one": "point", "many": "points"}
_MORE_ITEMS: Mapping[str, str] = {
    "one": "... and {count} more item",
    "many": "... and {count} more items",
}
_PHYSICAL_CORES: Mapping[str, str] = {"one": "{count} physical", "many": "{count} physical"}
_LOGICAL_CORES: Mapping[str, str] = {"one": "{count} logical", "many": "{count} logical"}
_DAY_WORDS: Mapping[str, str] = {"one": "{count} day", "many": "{count} days"}
_HOUR_WORDS: Mapping[str, str] = {"one": "{count} hour", "many": "{count} hours"}

#: One label per protection verdict. Spelled out as literals instead of being built from the
#: STATE_* value, so a verdict this table does not know lands on "unknown" - the one wording
#: that is never a lie - rather than on a key nobody ships.
_STATE_LABELS: Mapping[str, tuple[str, str]] = {
    STATE_GOOD: ("field.state_good", "On"),
    STATE_WEAK: ("field.state_weak", "Needs attention"),
    STATE_BAD: ("field.state_bad", "Off"),
    STATE_UNKNOWN: ("field.state_unknown", "Unknown"),
}

#: How a bounded measurement is worded, per value of the producer's ``bound`` parameter. A
#: producer that could only put a floor under a number says so in this parameter instead of
#: writing the qualifier into the number itself: "at least" is a sentence, not a measurement,
#: and a sentence has to be translated. Room is left for an upper bound the day one appears.
_BOUND_KEYS: Mapping[str, tuple[str, str]] = {"lower": ("report.at_least", "at least {value}")}


def _value(value: object | None) -> str:
    return "N/A" if value is None else str(value)


def _qualified(translator: object | None, params: Mapping[str, object]) -> dict[str, object]:
    """
    Word ``params["value"]`` as a bound when the producer marked it as one.

    The qualifier goes through the translator before it is substituted, so the finished
    sentence reads "aspoň 12.0 GB" in Slovak and "at least 12.0 GB" in English from one and
    the same snapshot. A bound nobody knows how to word, or a value that was never measured,
    leaves the parameters untouched - a missing qualifier is better than a wrong number.
    """
    entry = _BOUND_KEYS.get(str(params.get("bound", "")).strip().casefold())
    value = params.get("value")
    if entry is None or value is None:
        return dict(params)
    key, default = entry
    return {**params, "value": _text(translator, key, default, value=value)}


def _text(translator: object | None, key: str, default: str, **params: object) -> str:
    """
    Resolve one label.

    ``translator=None`` falls back to the caller's own default and touches no i18n table,
    which keeps this module importable on its own. Note that :func:`build_report` no longer
    reaches this path for its own labels - see :func:`_english_translator`.

    A deduction or a recommendation may carry a ``bound`` parameter next to its ``value``
    (today only ``"lower"``). Every format resolves it here, which is why text, JSON, HTML
    and Markdown cannot end up quoting the same measurement two different ways.
    """
    if params.get("bound") is not None:
        params = _qualified(translator, params)
    if translator is None:
        if not params:
            return default
        try:
            return default.format(**params)
        except Exception:
            return default
    try:
        # Accept both a Translator and any plain callable with the same signature.
        translate: Callable[..., str] = getattr(translator, "t", translator)
        return str(translate(key, default, **params))
    except Exception:
        return default


def _plural_text(
    translator: object | None,
    base_key: str,
    count: object,
    defaults: Mapping[str, str],
    /,
    **params: object,
) -> str:
    """
    Resolve a phrase whose wording depends on ``count``.

    Which form a number takes is a property of the language, not of the renderer: Slovak
    needs "1 bod", "3 body" and "5 bodov" where English needs two forms only. The decision
    therefore belongs to the translator, and ``defaults`` covers just the case of a
    translator that predates ``t_plural``.

    The fixed arguments are positional-only so that a caller may still pass ``count=`` as a
    template value - a pre-formatted "N/A", for instance - without colliding with them.
    """
    method = getattr(translator, "t_plural", None)
    if callable(method):
        try:
            return str(method(base_key, count, defaults.get("many"), **params))
        except Exception:
            pass
    # No t_plural(): ask for the form the English rule picks. A translator that happens to
    # carry the key still answers in its own language; one that does not gets the default.
    form = "one" if _is_singular(count) else "many"
    default = defaults.get(form) or defaults.get("many", "")
    return _text(translator, f"{base_key}.{form}", default, **{"count": count, **params})


def _is_singular(count: object) -> bool:
    """English fallback rule. A count that is not exactly one takes the plural."""
    try:
        return float(count) == 1.0  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return False


def _status_key(status: str) -> str:
    return "status." + str(status).strip().casefold().replace(" ", "_")


def _table(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    aligns: Sequence[str] | None = None,
) -> list[str]:
    """Render a plain ASCII table; column widths follow the widest cell."""
    columns = len(headers)
    widths = [len(str(item)) for item in headers]
    for row in rows:
        for index in range(columns):
            cell = str(row[index]) if index < len(row) else ""
            widths[index] = max(widths[index], len(cell))

    def line(cells: Sequence[str]) -> str:
        parts: list[str] = []
        for index in range(columns):
            cell = str(cells[index]) if index < len(cells) else ""
            align = aligns[index] if aligns and index < len(aligns) else "l"
            parts.append(cell.rjust(widths[index]) if align == "r" else cell.ljust(widths[index]))
        return "  ".join(parts).rstrip()

    rendered = [line(headers), "  ".join("-" * width for width in widths)]
    rendered.extend(line(row) for row in rows)
    return rendered


class _ReportBuilder:
    """Collects the report line by line so every section stays small and independent."""

    def __init__(
        self,
        data: AnalysisData,
        recommendations: Sequence[Recommendation | str],
        assessment: HealthAssessment,
        translator: object | None,
        redact: bool,
        colors: Ansi | None,
        width: int,
    ) -> None:
        self.data = data
        self.recommendations = list(recommendations or ())
        self.assessment = assessment
        self.translator = translator
        self.redact = bool(redact)
        self.colors = colors if colors is not None else Ansi(False)
        self.width = max(32, int(width))
        self.lines: list[str] = []

    # -- small helpers -------------------------------------------------------------------

    def t(self, key: str, default: str, **params: object) -> str:
        return _text(self.translator, key, default, **params)

    def plural(
        self, base_key: str, count: object, defaults: Mapping[str, str], /, **params: object
    ) -> str:
        """Count-aware label; see :func:`_plural_text` for why the translator decides."""
        return _plural_text(self.translator, base_key, count, defaults, **params)

    def add(self, line: str = "") -> None:
        self.lines.append(line)

    def field(self, label: str, value: str) -> None:
        self.add(f"{label}: {value}")

    def section(self, key: str, default: str, suffix: str = "") -> None:
        title = self.t(key, default)
        if suffix:
            title = f"{title} ({suffix})"
        self.add("")
        self.add(self.colors.paint(f"--- {title} ---", Ansi.BOLD, Ansi.CYAN))

    def hide(self, value: str | None) -> str:
        """Apply redaction to a path-like string when the caller asked for it."""
        if not self.redact:
            return _value(value)
        return _value(redact_text(value))

    def severity_color(self, severity: str) -> str:
        return {"critical": Ansi.RED, "warning": Ansi.YELLOW}.get(severity, Ansi.CYAN)

    def detail(self, key: str, default: str, value: object) -> None:
        """Indented "label: value" line, skipped for anything the hardware did not report."""
        if value is None or str(value) == "":
            return
        self.add(f"  {self.t(key, default)}: {value}")

    def state(self, value: object) -> str:
        """
        Word one STATE_* verdict.

        A verdict outside the known set is reported as unknown rather than guessed at. That
        is the same rule the collectors follow: a setting nobody could read is never shown as
        switched off, because that would be a measurement the analyser never made.
        """
        key, default = _STATE_LABELS.get(str(value), _STATE_LABELS[STATE_UNKNOWN])
        return self.t(key, default)

    def days(self, count: int) -> str:
        """A number of days with the noun form its count requires ("1 deň", "12 dní")."""
        return self.plural("report.days", count, _DAY_WORDS, count=format_count(count))

    def hours(self, count: int) -> str:
        """A number of hours, declined the same way. Drives report five-figure counts."""
        return self.plural("report.hours", count, _HOUR_WORDS, count=format_count(count))

    # -- sections ------------------------------------------------------------------------

    def header(self) -> None:
        rule = "=" * self.width
        title = self.t("report.title", APP_NAME)
        self.add(rule)
        self.add(self.colors.paint(title.center(self.width).rstrip(), Ansi.BOLD))
        self.add(rule)
        self.field(self.t("report.analysis_date", "Analysis Date"), self.timestamp())
        self.field(
            self.t("report.mode", "Mode"),
            self.t("report.mode_readonly", "Read-only analysis (no settings or files changed)"),
        )
        if self.data.duration_seconds is not None:
            self.field(
                self.t("report.duration", "Analysis Duration"),
                format_duration(self.data.duration_seconds),
            )

    def timestamp(self) -> str:
        moment = self.data.analyzed_at
        if not isinstance(moment, datetime):
            return _value(moment)
        try:
            return moment.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
        except Exception:
            return str(moment)

    def system(self) -> None:
        system = self.data.system
        self.section("section.system", "SYSTEM")
        self.field(self.t("field.os", "System"), _value(system.os_name))
        self.field(self.t("field.release", "Release"), _value(system.release))
        self.field(self.t("field.version", "Version"), _value(system.version))
        if system.edition:
            self.field(self.t("field.edition", "Edition"), system.edition)
        if system.display_version:
            self.field(self.t("field.display_version", "Windows Version"), system.display_version)
        if system.build:
            self.field(self.t("field.build", "Build"), system.build)
        self.field(self.t("field.architecture", "Architecture"), _value(system.architecture))
        self.field(self.t("field.processor", "Processor"), _value(system.processor))
        if system.manufacturer:
            self.field(self.t("field.manufacturer", "Manufacturer"), system.manufacturer)
        if system.model:
            self.field(self.t("field.model", "Model"), system.model)
        if system.bios_version:
            self.field(self.t("field.bios", "BIOS Version"), system.bios_version)
        if system.install_date is not None:
            label = self.t("field.install_date", "Windows Installed")
            self.field(label, _date(system.install_date))
        if system.boot_time is not None:
            self.field(self.t("field.boot_time", "Last Boot"), _date(system.boot_time, time=True))

    def cpu(self) -> None:
        cpu = self.data.cpu
        self.section("section.cpu", "CPU")
        self.field(
            self.t("field.cores", "CPU Cores"),
            self.t(
                "report.cores_value",
                "{physical} / {logical}",
                physical=self.cores("report.cores_physical", cpu.physical_cores, _PHYSICAL_CORES),
                logical=self.cores("report.cores_logical", cpu.logical_cores, _LOGICAL_CORES),
            ),
        )
        self.field(self.t("field.cpu_usage", "CPU Usage"), format_percent(cpu.usage_percent))
        if cpu.frequency_mhz is not None or cpu.max_frequency_mhz is not None:
            current = format_frequency(cpu.frequency_mhz)
            if cpu.max_frequency_mhz:
                current = self.t(
                    "report.frequency_value",
                    "{current} (max. {maximum})",
                    current=current,
                    maximum=format_frequency(cpu.max_frequency_mhz),
                )
            self.field(self.t("field.frequency", "CPU Frequency"), current)
        self.per_core()

    def cores(self, key: str, count: int | None, defaults: Mapping[str, str]) -> str:
        """
        One core count with the noun form its number requires.

        The number is formatted before it reaches the template, so an unmeasured count reads
        "N/A" instead of "None", while the raw value still picks the grammatical form.
        """
        return self.plural(key, count, defaults, count=_value(count))

    def per_core(self) -> None:
        values = [item for item in self.data.cpu.per_core_percent if item is not None]
        if not values:
            return
        summary = self.t(
            "report.per_core_value",
            "min {min} / avg {avg} / max {max}",
            min=format_percent(min(values)),
            avg=format_percent(sum(values) / len(values)),
            max=format_percent(max(values)),
        )
        self.field(self.t("field.per_core", "Per-core Usage"), summary)
        shown = [format_percent(item) for item in values[:_MAX_CORES_SHOWN]]
        line = "  " + ", ".join(shown)
        if len(values) > _MAX_CORES_SHOWN:
            line += " " + self.plural(
                "report.and_more", len(values) - _MAX_CORES_SHOWN, _MORE_ITEMS
            )
        self.add(line)

    def ram(self) -> None:
        ram = self.data.ram
        self.section("section.ram", "RAM")
        self.field(self.t("field.ram_total", "Total RAM"), format_bytes(ram.total_bytes))
        available = self.t("field.ram_available", "Available RAM")
        self.field(available, format_bytes(ram.available_bytes))
        self.field(self.t("field.ram_used", "Used RAM"), format_bytes(ram.used_bytes))
        self.field(self.t("field.ram_usage", "RAM Usage"), format_percent(ram.usage_percent))
        if ram.swap_total_bytes:
            self.field(
                self.t("field.swap", "Page File"),
                self.t(
                    "report.swap_value",
                    "{used} of {total} ({percent})",
                    used=format_bytes(ram.swap_used_bytes),
                    total=format_bytes(ram.swap_total_bytes),
                    percent=format_percent(ram.swap_percent),
                ),
            )

    def disk(self) -> None:
        disk = self.data.disk
        self.section("section.disk", "DISK", suffix=_value(disk.drive))
        self.field(self.t("field.disk_total", "Total Disk"), format_bytes(disk.total_bytes))
        self.field(self.t("field.disk_used", "Used Disk"), format_bytes(disk.used_bytes))
        self.field(self.t("field.disk_free", "Free Disk"), format_bytes(disk.free_bytes))
        self.field(self.t("field.disk_usage", "Disk Usage"), format_percent(disk.usage_percent))
        if disk.filesystem:
            self.field(self.t("field.filesystem", "File System"), disk.filesystem)
        if disk.media_type:
            self.field(self.t("field.media_type", "Media Type"), disk.media_type)

    def partitions(self) -> None:
        partitions = [item for item in self.data.partitions if isinstance(item, DiskInfo)]
        if not partitions:
            return
        self.section("section.partitions", "PARTITIONS")
        headers = [
            self.t("field.drive", "Drive"),
            self.t("field.total", "Total"),
            self.t("field.used", "Used"),
            self.t("field.free", "Free"),
            self.t("field.usage", "Usage"),
            self.t("field.media_type", "Media Type"),
        ]
        rows = []
        for item in partitions:
            name = _value(item.drive)
            if item.is_system:
                name = f"{name} ({self.t('report.system_drive', 'system')})"
            rows.append(
                [
                    name,
                    format_bytes(item.total_bytes),
                    format_bytes(item.used_bytes),
                    format_bytes(item.free_bytes),
                    format_percent(item.usage_percent),
                    _value(item.media_type or item.filesystem),
                ]
            )
        self.lines.extend(_table(headers, rows, aligns=["l", "r", "r", "r", "r", "l"]))

    def processes(self) -> None:
        self.section("section.processes", "PROCESSES")
        self.field(
            self.t("field.processes", "Running Processes"), _value(self.data.process_count)
        )

    def top_processes(self) -> None:
        top = list(self.data.top_processes)
        if not top:
            return
        self.section("section.top_processes", "TOP PROCESSES")
        headers = [
            self.t("field.pid", "PID"),
            self.t("field.name", "Name"),
            self.t("field.memory", "Memory"),
            self.t("field.memory_percent", "Memory %"),
            self.t("field.cpu_percent", "CPU %"),
        ]
        rows = [
            [
                _value(item.pid),
                _value(item.name),
                format_bytes(item.memory_bytes),
                format_percent(item.memory_percent),
                format_percent(item.cpu_percent),
            ]
            for item in top
        ]
        self.lines.extend(_table(headers, rows, aligns=["r", "l", "r", "r", "r"]))

    def temp(self) -> None:
        self.section("section.temp", "TEMP FILES")
        self.field(self.t("field.temp_path", "TEMP Folder"), self.hide(self.data.temp_path))
        # A scan that ran out of time only measured part of the folder, so this headline is a
        # floor. It carries the same label a truncated row in the table below carries: a reader
        # who stops at this line must not take the number for a finished total.
        size = format_bytes(self.data.temp_size_bytes)
        truncated = bool(getattr(self.data, "temp_truncated", False))
        if truncated:
            size = f"{size} ({self.t('report.partial_scan', 'partial scan')})"
        self.field(self.t("field.temp_size", "TEMP Folder Size"), size)
        if truncated:
            # The tag on the line above is two words; this line says what they mean, because
            # a reader who acts on the number has to know it can only grow, never shrink.
            self.add(
                self.t(
                    "report.temp_truncated",
                    "The TEMP scan ran out of time, so this size is a lower bound, not a "
                    "measurement.",
                )
            )
        locations = list(self.data.temp_locations)
        if not locations:
            return
        headers = [
            self.t("field.label", "Location"),
            self.t("field.folder_size", "Folder Size"),
            self.t("field.files", "Files"),
            self.t("field.path", "Path"),
        ]
        rows = []
        for item in locations:
            size = format_bytes(item.size_bytes)
            if item.truncated:
                size = f"{size} ({self.t('report.partial_scan', 'partial scan')})"
            rows.append(
                [
                    _value(item.label),
                    size,
                    format_count(item.file_count),
                    self.hide(item.path),
                ]
            )
        self.lines.extend(_table(headers, rows, aligns=["l", "r", "r", "l"]))

    def folders(self) -> None:
        """The well-known user folders, biggest first. Empty when nothing was measured."""
        folders = [
            item for item in getattr(self.data, "folder_usage", ()) if isinstance(item, FolderUsage)
        ]
        if not folders:
            return
        # Biggest first is a property of this table, not a favour asked of the collector. A
        # folder whose size could not be read sorts last: "unknown" is not "small".
        folders.sort(key=lambda item: _size_key(item.size_bytes), reverse=True)
        self.section("section.folders", "BIGGEST FOLDERS")
        headers = [
            self.t("field.folder", "Folder"),
            self.t("field.folder_size", "Folder Size"),
            self.t("field.files", "Files"),
            self.t("field.path", "Path"),
        ]
        rows = []
        for item in folders[:_MAX_LIST_ITEMS]:
            size = format_bytes(item.size_bytes)
            if item.truncated:
                # Exactly the qualifier the TEMP table uses, and taken from the same key, so
                # a partial measurement reads the same wherever the reader meets it.
                size = f"{size} ({self.t('report.partial_scan', 'partial scan')})"
            rows.append(
                [
                    _value(item.label),
                    size,
                    format_count(item.file_count),
                    self.hide(item.path),
                ]
            )
        self.lines.extend(_table(headers, rows, aligns=["l", "r", "r", "l"]))
        self.more(len(folders))

    def drive_health(self) -> None:
        """Wear figures per physical drive. Only what the drive actually answered is shown."""
        drives = [
            item
            for item in getattr(self.data, "drive_health", ())
            if isinstance(item, DriveHealth) and _has_drive_data(item)
        ]
        if not drives:
            return
        self.section("section.drive_health", "DRIVE HEALTH")
        for item in drives:
            self.add(f"- {_value(item.drive)}")
            self.detail("field.model", "Model", item.model)
            self.detail("field.bus_type", "Bus", item.bus_type)
            self.detail("field.media_type", "Media Type", item.media_type)
            if item.life_left_percent is not None:
                self.detail(
                    "field.life_left", "Life Left", format_percent(item.life_left_percent)
                )
            if item.temperature_celsius is not None:
                self.detail(
                    "field.temperature", "Temperature", _celsius(item.temperature_celsius)
                )
            if item.power_on_hours is not None:
                self.detail(
                    "field.power_on_hours", "Power-on Hours", self.hours(item.power_on_hours)
                )
            if item.data_written_bytes is not None:
                self.detail(
                    "field.data_written", "Data Written", format_bytes(item.data_written_bytes)
                )
            if item.critical_warning is not None:
                self.detail(
                    "field.critical_warning",
                    "Critical Warning",
                    self.yes_no(item.critical_warning),
                )

    def security(self) -> None:
        """
        The protection settings, as read.

        Nothing here is ever switched on or off by this program. An unreadable setting keeps
        the unknown label: reporting "Off" because a query failed would invent a measurement,
        and the score never penalises an unknown either.
        """
        security = getattr(self.data, "security", None)
        if not isinstance(security, SecurityInfo) or not _has_security_data(security):
            return
        self.section("section.security", "SECURITY")
        antivirus = self.state(security.antivirus)
        if security.antivirus_name:
            antivirus = f"{antivirus} ({security.antivirus_name})"
        self.field(self.t("field.antivirus", "Antivirus"), antivirus)
        self.field(self.t("field.firewall", "Firewall"), self.state(security.firewall))
        self.field(self.t("field.secure_boot", "Secure Boot"), self.state(security.secure_boot))
        if security.reboot_pending is not None:
            self.field(
                self.t("field.reboot_pending", "Restart Pending"),
                self.yes_no(security.reboot_pending),
            )
        if security.signature_age_days is not None:
            self.field(
                self.t("field.signature_age", "Definitions Age"),
                self.days(security.signature_age_days),
            )
        if security.defender_last_scan is not None:
            self.field(
                self.t("field.last_scan", "Last Scan"),
                _date(security.defender_last_scan, time=True),
            )
        if _security_center_down(security):
            # Names the reason for the N/A above. Without it the reader cannot tell "nobody
            # answered" from "the answer was no", and those two are not the same news.
            self.add(
                self.t(
                    "report.security_center_down",
                    "The Windows Security Center did not answer, so the antivirus and "
                    "firewall states are unknown rather than off.",
                )
            )

    def uptime(self) -> None:
        self.section("section.uptime", "UPTIME")
        self.field(self.t("field.uptime", "System Uptime"), format_uptime(self.data.uptime_seconds))

    def battery(self) -> None:
        battery = self.data.battery
        if battery is None:
            return
        self.section("section.battery", "BATTERY")
        self.field(self.t("field.battery", "Battery"), format_percent(battery.percent))
        if battery.plugged_in is not None:
            self.field(self.t("field.plugged_in", "Plugged In"), self.yes_no(battery.plugged_in))
        if battery.seconds_left is not None:
            self.field(
                self.t("field.time_left", "Time Left"), format_duration(battery.seconds_left)
            )
        # Wear, as opposed to charge: how much of the pack's original capacity is still
        # there. Each line appears only if the battery reported that figure - a pack that
        # keeps its design capacity to itself is left blank, never extrapolated.
        health = getattr(battery, "health_percent", None)
        if health is not None:
            self.field(self.t("field.battery_health", "Battery Health"), format_percent(health))
        if battery.design_capacity_mwh is not None:
            self.field(
                self.t("field.design_capacity", "Design Capacity"),
                _milliwatt_hours(battery.design_capacity_mwh),
            )
        if battery.full_charge_capacity_mwh is not None:
            self.field(
                self.t("field.full_charge_capacity", "Full Charge Capacity"),
                _milliwatt_hours(battery.full_charge_capacity_mwh),
            )
        if battery.cycle_count is not None:
            self.field(
                self.t("field.cycle_count", "Charge Cycles"), format_count(battery.cycle_count)
            )
        if battery.chemistry:
            self.field(self.t("field.chemistry", "Cell Chemistry"), str(battery.chemistry))

    def network(self) -> None:
        network = self.data.network
        if network is None:
            return
        interfaces = list(network.interfaces)
        if network.bytes_sent is None and network.bytes_received is None and not interfaces:
            return
        self.section("section.network", "NETWORK")
        if network.bytes_sent is not None:
            self.field(self.t("field.sent", "Sent"), format_bytes(network.bytes_sent))
        if network.bytes_received is not None:
            self.field(self.t("field.received", "Received"), format_bytes(network.bytes_received))
        if not interfaces:
            return
        self.field(self.t("field.interfaces", "Interfaces"), format_count(len(interfaces)))
        for item in interfaces[:_MAX_LIST_ITEMS]:
            state = self.t("field.up", "up") if item.is_up else self.t("field.down", "down")
            line = self.t(
                "report.interface_value", "{name}: {state}", name=_value(item.name), state=state
            )
            if item.speed_mbps:
                line = f"{line}, {format_count(item.speed_mbps)} Mbps"
            self.add(f"- {line}")
        self.more(len(interfaces))

    def gpus(self) -> None:
        gpus = list(self.data.gpus)
        if not gpus:
            return
        self.section("section.gpu", "GRAPHICS")
        for item in gpus:
            self.add(f"- {_value(item.name)}")
            if item.driver_version:
                driver = item.driver_version
                if item.driver_date:
                    driver = self.t(
                        "report.driver_value",
                        "{version} ({date})",
                        version=item.driver_version,
                        date=item.driver_date,
                    )
                self.add(f"  {self.t('field.driver', 'Driver')}: {driver}")
            if item.memory_bytes:
                self.add(
                    f"  {self.t('field.gpu_memory', 'Graphics Memory')}: "
                    f"{format_bytes(item.memory_bytes)}"
                )

    def startup(self) -> None:
        items = list(self.data.startup_items)
        if not items:
            return
        self.section("section.startup", "STARTUP ITEMS")
        self.field(self.t("field.startup_items", "Startup Items"), format_count(len(items)))
        for item in items[:_MAX_LIST_ITEMS]:
            self.add(f"- {_value(item.name)} ({_value(item.source)})")
        self.more(len(items))

    def more(self, total: int) -> None:
        if total > _MAX_LIST_ITEMS:
            self.add(self.plural("report.and_more", total - _MAX_LIST_ITEMS, _MORE_ITEMS))

    def yes_no(self, value: bool | None) -> str:
        if value is None:
            return "N/A"
        return self.t("field.yes", "Yes") if value else self.t("field.no", "No")

    def score(self) -> None:
        assessment = self.assessment
        self.section("section.score", "PC HEALTH SCORE")
        score_text = self.t("report.score_value", "{score}/100", score=assessment.score)
        color = _score_color(assessment.score)
        self.field(self.t("report.score", "Score"), self.colors.paint(score_text, Ansi.BOLD, color))
        status = _text(
            self.translator, _status_key(assessment.status), str(assessment.status)
        )
        self.field(self.t("report.status", "Status"), status)
        self.field(
            self.t("field.data_complete", "Data Complete"), self.yes_no(assessment.data_complete)
        )
        self.categories()
        self.deductions()

    def categories(self) -> None:
        categories = [
            item for item in self.assessment.categories if isinstance(item, CategoryScore)
        ]
        if not categories:
            return
        self.add("")
        self.add(self.t("report.categories", "Category scores:"))
        for item in categories:
            label = _text(self.translator, f"category.{item.key}", str(item.label))
            if not item.available:
                self.add(f"- {label}: {self.t('report.unavailable', 'not measured')}")
                continue
            value = self.t("report.score_value", "{score}/100", score=item.score)
            self.add(f"- {label}: {value}")

    def deductions(self) -> None:
        deductions = [
            item for item in self.assessment.deductions if isinstance(item, ScoreDeduction)
        ]
        if not deductions:
            return
        self.add("")
        self.add(self.t("report.deductions", "Score deductions:"))
        for item in deductions:
            reason = _text(
                self.translator, f"deduction.{item.key}", str(item.reason), **item.values
            )
            # The noun is resolved per row: Slovak says "1 bod", "3 body" and "18 bodov".
            word = self.plural("report.points", item.points, _POINT_WORDS)
            points = self.colors.paint(f"{item.points} {word}", self.severity_color(item.severity))
            self.add(f"- {points}: {reason}")

    def advice(self) -> None:
        self.section("section.recommendations", "RECOMMENDATIONS")
        if not self.recommendations:
            self.add(self.t("report.none_detected", "None detected."))
            return
        for item in self.recommendations:
            if isinstance(item, Recommendation):
                text = _text(
                    self.translator, f"recommendation.{item.key}", str(item.text), **item.values
                )
                bullet = self.colors.paint("-", self.severity_color(item.severity))
                # Advice can quote a path or a process name, so it is redacted exactly like
                # the other renderers do - otherwise --redact would depend on the format.
                self.add(f"{bullet} {self.hide(text)}")
                if item.detail:
                    self.add(f"  {self.hide(item.detail)}")
                continue
            self.add(f"- {self.hide(str(item))}")

    def warnings(self) -> None:
        warnings = list(self.data.warnings)
        if not warnings:
            return
        self.section("section.warnings", "ANALYSIS WARNINGS")
        for warning in warnings:
            self.add(f"- {self.hide(str(warning))}")

    def footer(self) -> None:
        self.add("")
        self.add(
            self.t(
                "report.footer",
                "This report is informational. Apoliak Vitals did not modify your PC.",
            )
        )

    # -- driver --------------------------------------------------------------------------

    def build(self) -> str:
        steps = (
            self.header,
            self.system,
            self.cpu,
            self.ram,
            self.disk,
            self.partitions,
            self.drive_health,
            self.processes,
            self.top_processes,
            self.temp,
            self.folders,
            self.uptime,
            self.battery,
            self.network,
            self.gpus,
            self.startup,
            self.security,
            self.score,
            self.advice,
            self.warnings,
            self.footer,
        )
        for step in steps:
            try:
                step()
            except Exception as error:  # A damaged snapshot must not cost the whole report.
                self.add(
                    self.t(
                        "report.section_failed",
                        "This section could not be rendered ({error}).",
                        error=error,
                    )
                )
        return "\n".join(self.lines) + "\n"


def _size_key(value: int | None) -> int:
    """Sort weight for a folder size. An unmeasured folder sorts below every measured one."""
    return -1 if value is None else int(value)


def _celsius(value: int | float) -> str:
    """A temperature with its unit symbol. "°C" is a symbol, not a word, so it is not a key."""
    return f"{int(value)} °C"


def _milliwatt_hours(value: int) -> str:
    """A battery capacity with its unit symbol, grouped like every other count."""
    return f"{format_count(int(value))} mWh"


def _has_drive_data(drive: DriveHealth) -> bool:
    """True when a drive answered at least one query; an entry with only a letter is noise."""
    return any(
        value is not None
        for value in (
            drive.model,
            drive.bus_type,
            drive.media_type,
            drive.percentage_used,
            drive.temperature_celsius,
            drive.power_on_hours,
            drive.data_written_bytes,
            drive.critical_warning,
        )
    )


def _security_center_down(security: SecurityInfo) -> bool:
    """True when the collector recorded that the Security Center itself did not answer."""
    return any(str(key) == "security_center" for key, _ in security.details)


def _has_security_data(security: SecurityInfo) -> bool:
    """
    True when the protection snapshot carries something worth printing.

    Three "Unknown" lines are not a finding. On a machine - or an operating system - where
    none of these settings could be read, the section is dropped entirely rather than
    suggesting the analyser looked and found trouble.
    """
    if any(
        state != STATE_UNKNOWN
        for state in (security.antivirus, security.firewall, security.secure_boot)
    ):
        return True
    if any(
        value is not None
        for value in (
            security.reboot_pending,
            security.defender_last_scan,
            security.signature_age_days,
        )
    ):
        return True
    return bool(security.details)


def _date(moment: datetime | None, *, time: bool = False) -> str:
    if not isinstance(moment, datetime):
        return _value(moment)
    try:
        return moment.strftime("%Y-%m-%d %H:%M" if time else "%Y-%m-%d")
    except Exception:
        return str(moment)


def _english_translator() -> object | None:
    """
    English straight from the shared catalogue, used when no translator was supplied.

    The producers keep their own English sentences, but a report must not print them: the
    same run would then be worded one way in the text report and another way in the JSON,
    and the reader has no way to tell which sentence describes their PC. The import is lazy
    and guarded so the v1.0 three-argument call still works even where i18n cannot load - it
    then degrades to exactly the old behaviour instead of raising.
    """
    try:
        from . import i18n

        return i18n.get_translator("en")
    except Exception:
        return None


def _score_color(score: int) -> str:
    if score >= 90:
        return Ansi.GREEN
    if score >= 75:
        return Ansi.CYAN
    if score >= 50:
        return Ansi.YELLOW
    return Ansi.RED


def build_report(
    data: AnalysisData,
    recommendations: Sequence[Recommendation | str],
    assessment: HealthAssessment,
    *,
    translator: object | None = None,
    redact: bool = False,
    colors: Ansi | None = None,
    width: int = 64,
) -> str:
    """
    Render the full plain-text report.

    With ``colors=None`` the result carries no escape sequences, which is what gets written
    to a file. ``translator=None`` renders English from the shared i18n catalogue, so one
    analysis reads the same whichever call path produced it.
    """
    if translator is None:
        translator = _english_translator()
    builder = _ReportBuilder(data, recommendations, assessment, translator, redact, colors, width)
    try:
        return builder.build()
    except Exception as error:  # Never raise from a renderer; a short report beats a traceback.
        return f"{APP_NAME}\nThe report could not be rendered safely ({error}).\n"


def export_report(
    data: AnalysisData,
    recommendations: Sequence[Recommendation | str],
    assessment: HealthAssessment,
    output_path: str | Path = "pc_report.txt",
    *,
    translator: object | None = None,
    redact: bool = False,
) -> Path:
    """Write the plain-text report as UTF-8 and return the resolved destination."""
    destination = Path(output_path).expanduser()
    if destination.exists() and destination.is_dir():
        destination = destination / "pc_report.txt"
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = build_report(
        data, recommendations, assessment, translator=translator, redact=redact, colors=None
    )
    destination.write_text(content, encoding="utf-8")
    return destination.resolve()
