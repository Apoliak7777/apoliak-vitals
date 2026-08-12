"""Snapshot serialisation into the four shipped report formats.

Every renderer reads the same immutable snapshot, so a JSON export and an HTML export can
never disagree. The HTML document is deliberately self-contained: no fonts, no scripts, no
images, nothing that would reach outside the file when the report is shared by e-mail.
"""

from __future__ import annotations

import json
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .models import (
    AnalysisData,
    CATEGORY_GENERAL,
    HealthAssessment,
    Recommendation,
    STATE_BAD,
    STATE_GOOD,
    STATE_UNKNOWN,
    STATE_WEAK,
)
from .report import APP_NAME, APP_VERSION, build_report
# One shared implementation of the "translate, or fall back to the English default" rule,
# and of "let the language decide which noun form a count takes".
from .report import _POINT_WORDS, _plural_text as _plural
from .report import _text as _label
from .utils import (
    format_bytes,
    format_count,
    format_duration,
    format_frequency,
    format_percent,
    format_uptime,
    redact_text,
)

try:  # A trimmed install may ship without the tables; an export must still work there.
    from . import i18n as _i18n
except Exception:  # pragma: no cover - only a broken installation reaches this
    _i18n = None  # type: ignore[assignment]

#: Export formats offered by the CLI and the GUI, in menu order.
FORMATS: tuple[str, ...] = ("text", "json", "html", "markdown")

_EXTENSIONS: dict[str, str] = {
    "text": "txt",
    "json": "json",
    "html": "html",
    "markdown": "md",
}

_SUFFIX_FORMATS: dict[str, str] = {
    ".txt": "text",
    ".text": "text",
    ".json": "json",
    ".html": "html",
    ".htm": "html",
    ".md": "markdown",
    ".markdown": "markdown",
}

_FILENAME_STEM = "apoliak_vitals_report"

#: Highest "_2", "_3", ... suffix tried before an auto-named export gives up.
_MAX_NAME_ATTEMPTS = 999

_SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ff6b6b",
    "warning": "#ffb454",
    "info": "#6fc3ff",
}

#: One colour per protection verdict, so "antivirus off" reads as serious at a glance and an
#: unreadable verdict reads as the muted nothing it is. Keys are exactly the four STATE_*
#: values, which is what :func:`_state_name` validates a foreign verdict against.
_STATE_COLORS: dict[str, str] = {
    STATE_GOOD: "#3ddc97",
    STATE_WEAK: "#ffb454",
    STATE_BAD: "#ff6b6b",
    STATE_UNKNOWN: "#8d97a8",
}

#: One label per protection verdict, shared verbatim with the plain-text report so a run
#: cannot say "Off" in one format and something else in another. A verdict outside this
#: table lands on "unknown" - the one wording that is never a lie.
_STATE_LABELS: dict[str, tuple[str, str]] = {
    STATE_GOOD: ("field.state_good", "On"),
    STATE_WEAK: ("field.state_weak", "Needs attention"),
    STATE_BAD: ("field.state_bad", "Off"),
    STATE_UNKNOWN: ("field.state_unknown", "Unknown"),
}

#: Count-dependent phrases, same contract as _POINT_WORDS: only reached when the translator
#: predates t_plural(). Slovak needs "1 deň", "3 dni", "5 dní" where English needs two forms.
_DAY_WORDS: Mapping[str, str] = {"one": "{count} day", "many": "{count} days"}
_HOUR_WORDS: Mapping[str, str] = {"one": "{count} hour", "many": "{count} hours"}


class _Tinted:
    """
    A table cell whose text carries one of the fixed severity colours into the HTML export.

    Markdown, the plain text report and the JSON payload only ever see ``str(cell)``, so one
    row builder can serve every format and the colour simply does not exist outside HTML.
    The colour always comes from a constant in this module and never from measured data, so
    nothing a PC reports can reach a style attribute.
    """

    __slots__ = ("text", "color")

    def __init__(self, text: str, color: str) -> None:
        self.text = str(text)
        self.color = str(color)

    def __str__(self) -> str:
        return self.text


# ----------------------------------------------------------------------------------------
# format helpers
# ----------------------------------------------------------------------------------------


def _english() -> object | None:
    """
    Translator used when a caller supplied none.

    The i18n catalogue is the single source of truth for wording, so a report rendered
    without an explicit language must still read like the translated one instead of quoting
    the producer's own sentence. A missing i18n module degrades to those defaults.
    """
    if _i18n is None:
        return None
    try:
        return _i18n.get_translator("en")
    except Exception:
        return None


def extension_for(fmt: str) -> str:
    """File extension used by one format."""
    try:
        return _EXTENSIONS[_normalize_format(fmt)]
    except KeyError:  # pragma: no cover - _normalize_format already raised for unknown names
        raise ValueError(f"Unknown export format: {fmt!r}")


def format_from_path(path: str | Path) -> str | None:
    """Guess the format from a file name, or None when the suffix means nothing here."""
    try:
        suffix = Path(str(path)).suffix.casefold()
    except Exception:
        return None
    return _SUFFIX_FORMATS.get(suffix)


def default_filename(fmt: str, when: datetime | None = None) -> str:
    """
    Timestamped file name for one format.

    The timestamp resolves to whole seconds, so two exports started inside the same second
    do get the same name. Callers that generate a name must run it through
    :func:`unique_path`; this function only proposes one.
    """
    moment = when if isinstance(when, datetime) else datetime.now()
    return f"{_FILENAME_STEM}_{moment:%Y%m%d_%H%M%S}.{extension_for(fmt)}"


def unique_path(path: str | Path) -> Path:
    """
    Free destination for an automatically named export.

    Returns the path unchanged when nothing is there, otherwise the first "name_2",
    "name_3", ... variant that does not exist yet. Only generated names belong here: a path
    the user typed or picked in a dialog has to overwrite, because that is what the user
    asked for.

    The answer describes this moment. Two analyzers started in the very same second in the
    same folder can still both be told the same name is free; guarding that would need an
    exclusive create, which is more machinery than a desktop report is worth.
    """
    candidate = Path(path)
    if not candidate.name:  # A bare drive or root has no name to vary.
        return candidate
    for index in range(1, _MAX_NAME_ATTEMPTS + 1):
        attempt = (
            candidate
            if index == 1
            else candidate.with_name(f"{candidate.stem}_{index}{candidate.suffix}")
        )
        try:
            if not attempt.exists():
                return attempt
        except OSError:  # A directory that cannot be probed is not worth a second guess.
            return attempt
    return candidate


def _normalize_format(fmt: str) -> str:
    name = str(fmt).strip().casefold()
    aliases = {"txt": "text", "plain": "text", "md": "markdown", "htm": "html"}
    name = aliases.get(name, name)
    if name not in FORMATS:
        raise ValueError(f"Unknown export format: {fmt!r}. Expected one of: {', '.join(FORMATS)}")
    return name


def _hide(value: str | None, redact: bool) -> str | None:
    return redact_text(value) if redact and value else value


def _iso(value: object) -> str | None:
    if isinstance(value, datetime):
        try:
            return value.isoformat()
        except Exception:
            return str(value)
    return None if value is None else str(value)


def _number(value: object) -> int | float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _text_or_none(value: object) -> str | None:
    """A plain string for the payload, or None when there is nothing to write."""
    return None if value is None else str(value)


def _bool_or_none(value: object) -> bool | None:
    """A JSON boolean, keeping "nobody could tell" distinct from "no"."""
    return None if value is None else bool(value)


def _state_name(value: object) -> str:
    """
    One protection verdict as a plain string for the JSON payload.

    Anything that is not one of the four published verdicts reads as "unknown": a value this
    module cannot interpret is exactly as good as a measurement nobody took, and inventing a
    third meaning for it would be worse than admitting that.
    """
    text = str(value).strip().casefold() if isinstance(value, str) else ""
    return text if text in _STATE_COLORS else STATE_UNKNOWN


def _state_text(value: object, translator: object | None) -> str:
    """Word one verdict, using the catalogue entry the text report uses."""
    key, default = _STATE_LABELS[_state_name(value)]
    return _label(translator, key, default)


def _tinted(text: str, state: object) -> str | _Tinted:
    """
    Colour a verdict for HTML, leaving every other format with the plain word.

    An unknown verdict is deliberately left uncoloured: a setting nobody could read is not a
    finding, and painting it would make the report look like it knows something it does not.
    """
    name = _state_name(state)
    return text if name == STATE_UNKNOWN else _Tinted(text, _STATE_COLORS[name])


def _flag_state(value: object, *, true_state: str) -> str:
    """Turn a yes/no finding into a verdict. Nothing measured stays unknown."""
    if value is None:
        return STATE_UNKNOWN
    return true_state if bool(value) else STATE_GOOD


def _yes_no(value: object, translator: object | None) -> str:
    if value is None:
        return "N/A"
    key, default = ("field.yes", "Yes") if bool(value) else ("field.no", "No")
    return _label(translator, key, default)


def _temperature(value: object) -> str:
    """A temperature with its unit symbol. "°C" is a symbol, not a word, so it is not a key."""
    number = _number(value)
    return "N/A" if number is None else f"{int(number)} °C"


def _milliwatt_hours(value: object) -> str:
    """A battery capacity in the unit the pack reports it in, grouped like every count."""
    number = _number(value)
    return "N/A" if number is None else f"{format_count(int(number))} mWh"


def _days(value: object, translator: object | None) -> str:
    """A day count with the noun form its number requires."""
    number = _number(value)
    if number is None:
        return "N/A"
    return _plural(translator, "report.days", number, _DAY_WORDS, count=format_count(int(number)))


def _hours(value: object, translator: object | None) -> str:
    number = _number(value)
    if number is None:
        return "N/A"
    return _plural(translator, "report.hours", number, _HOUR_WORDS, count=format_count(int(number)))


def _details(info: object) -> tuple[tuple[object, object], ...]:
    """The collector's own diagnostics, as a tuple this module can walk twice."""
    return tuple(getattr(info, "details", ()) or ())


def _security_center_down(info: object) -> bool:
    """True when the collector recorded that the Security Center itself did not answer."""
    return any(str(key) == "security_center" for key, _ in _details(info))


def _has_security_data(info: object) -> bool:
    """
    True when the protection snapshot carries something worth showing.

    Three "Unknown" lines are not a finding. The rule is the plain-text report's, applied
    here so the same run never grows a section in one format that it lacks in another.
    """
    if any(
        _state_name(state) != STATE_UNKNOWN
        for state in (
            getattr(info, "antivirus", None),
            getattr(info, "firewall", None),
            getattr(info, "secure_boot", None),
        )
    ):
        return True
    if any(
        value is not None
        for value in (
            getattr(info, "reboot_pending", None),
            getattr(info, "defender_last_scan", None),
            getattr(info, "signature_age_days", None),
        )
    ):
        return True
    return bool(_details(info))


def _has_drive_data(item: object) -> bool:
    """True when a drive answered at least one query; an entry with only a letter is noise."""
    return any(
        getattr(item, name, None) is not None
        for name in (
            "model",
            "bus_type",
            "media_type",
            "percentage_used",
            "temperature_celsius",
            "power_on_hours",
            "data_written_bytes",
            "critical_warning",
        )
    )


def _folder_size_key(item: object) -> int:
    """Sort weight for a folder. An unmeasured folder sorts below every measured one."""
    value = _number(getattr(item, "size_bytes", None))
    return -1 if value is None else int(value)


# ----------------------------------------------------------------------------------------
# JSON-safe snapshot
# ----------------------------------------------------------------------------------------


def _system_dict(data: AnalysisData) -> dict[str, object]:
    system = data.system
    return {
        "os_name": system.os_name,
        "release": system.release,
        "version": system.version,
        "architecture": system.architecture,
        "processor": system.processor,
        "edition": system.edition,
        "display_version": system.display_version,
        "build": system.build,
        "install_date": _iso(system.install_date),
        "boot_time": _iso(system.boot_time),
        "manufacturer": system.manufacturer,
        "model": system.model,
        "bios_version": system.bios_version,
    }


def _disk_dict(disk: object) -> dict[str, object]:
    return {
        "drive": getattr(disk, "drive", None),
        "total_bytes": getattr(disk, "total_bytes", None),
        "used_bytes": getattr(disk, "used_bytes", None),
        "free_bytes": getattr(disk, "free_bytes", None),
        "usage_percent": getattr(disk, "usage_percent", None),
        "filesystem": getattr(disk, "filesystem", None),
        "media_type": getattr(disk, "media_type", None),
        "is_system": bool(getattr(disk, "is_system", False)),
    }


def _process_dict(process: object) -> dict[str, object]:
    return {
        "pid": getattr(process, "pid", None),
        "name": getattr(process, "name", None),
        "cpu_percent": getattr(process, "cpu_percent", None),
        "memory_bytes": getattr(process, "memory_bytes", None),
        "memory_percent": getattr(process, "memory_percent", None),
    }


def _deduction_dict(item: object, translator: object | None) -> dict[str, object]:
    # The wording comes from the catalogue, exactly like every other format: a stored JSON
    # export and the text report of the same run must never phrase one finding differently.
    return {
        "key": getattr(item, "key", None),
        "points": getattr(item, "points", None),
        "reason": _deduction_text(item, translator),
        "category": getattr(item, "category", CATEGORY_GENERAL),
        "severity": getattr(item, "severity", "warning"),
        "params": dict(getattr(item, "params", ()) or ()),
    }


def _recommendation_dict(
    item: object, translator: object | None, redact: bool
) -> dict[str, object]:
    if isinstance(item, Recommendation):
        return {
            "key": item.key,
            "text": _recommendation_text(item, translator, redact),
            "severity": item.severity,
            "category": item.category,
            "detail": _hide(item.detail, redact),
            "params": dict(item.params),
            # The settings page this advice is about, as plain text a tool can read. It stays
            # a string on purpose: a report file that opens system settings when it is
            # clicked is not something to hand around, so no renderer turns it into a link.
            "action_uri": _text_or_none(getattr(item, "action_uri", None)),
        }
    return {
        "key": None,
        "text": _hide(str(item), redact),
        "severity": "info",
        "category": CATEGORY_GENERAL,
        "detail": None,
        "params": {},
        "action_uri": None,
    }


def _json_section(
    name: str,
    build: Callable[[], object],
    failures: list[dict[str, str]],
    translator: object | None,
) -> object | None:
    """
    Build one branch of the payload, keeping a failure inside the branch that caused it.

    This is the net the text, HTML and Markdown builders already have: one hostile value
    costs its own section, never the whole export, because an export that raises loses a
    completed analysis the user cannot repeat. A section that could not be built is written
    as null - unknown, exactly like every other value nobody could measure - and names
    itself in ``export_errors`` so a reader can tell "not measured" from "not written".

    The result is proved serialisable here as well. A value json cannot encode would
    otherwise raise in :func:`render`, outside the reach of every section, and the net would
    hold for hostile values but not for hostile types.
    """
    try:
        value = build()
        json.dumps(value)
        return value
    except Exception as error:
        try:
            failures.append(
                {
                    "section": name,
                    "error": _label(
                        translator,
                        "report.section_failed",
                        "This section could not be rendered ({error}).",
                        error=error,
                    ),
                }
            )
        except Exception:  # Even the apology failed; the null value still stands on its own.
            pass
        return None


def snapshot_to_dict(
    data: AnalysisData,
    recommendations: Sequence[Recommendation | str],
    assessment: HealthAssessment,
    *,
    redact: bool = False,
    translator: object | None = None,
) -> dict[str, object]:
    """
    Build the versioned, JSON-safe representation of one analysis.

    The layout is part of the published contract: keys stay stable across releases so a
    stored export can still be read by a later version. v2.1 adds three branches -
    ``security``, ``drive_health`` and ``folder_usage`` - plus the battery wear fields
    inside ``battery`` and ``action_uri`` on every recommendation.

    Deduction and recommendation wording is resolved through the same catalogue the other
    formats use - English when the caller passes no translator - so the JSON of one run can
    never disagree with its text, HTML, or Markdown twin.

    Every branch is built behind :func:`_json_section`, so a value that cannot be written
    degrades that one branch to null and is listed in ``export_errors`` - empty on a healthy
    export - instead of taking the whole file down.
    """
    translator = translator if translator is not None else _english()
    failures: list[dict[str, str]] = []

    def section(name: str, build: Callable[[], object]) -> object | None:
        return _json_section(name, build, failures, translator)

    def generated_by() -> dict[str, object]:
        return {
            "name": APP_NAME,
            "version": APP_VERSION,
            "duration_seconds": _number(data.duration_seconds),
        }

    def cpu() -> dict[str, object]:
        return {
            "physical_cores": data.cpu.physical_cores,
            "logical_cores": data.cpu.logical_cores,
            "usage_percent": data.cpu.usage_percent,
            "per_core_percent": list(data.cpu.per_core_percent),
            "frequency_mhz": data.cpu.frequency_mhz,
            "max_frequency_mhz": data.cpu.max_frequency_mhz,
        }

    def ram() -> dict[str, object]:
        return {
            "total_bytes": data.ram.total_bytes,
            "available_bytes": data.ram.available_bytes,
            "used_bytes": data.ram.used_bytes,
            "usage_percent": data.ram.usage_percent,
            "swap_total_bytes": data.ram.swap_total_bytes,
            "swap_used_bytes": data.ram.swap_used_bytes,
            "swap_percent": data.ram.swap_percent,
        }

    def processes() -> dict[str, object]:
        return {
            "count": data.process_count,
            "top": [_process_dict(item) for item in data.top_processes],
        }

    def temp() -> dict[str, object]:
        return {
            "path": _hide(data.temp_path, redact),
            "size_bytes": data.temp_size_bytes,
            # True when the scan hit its time budget: the size above is a lower bound only.
            "truncated": bool(getattr(data, "temp_truncated", False)),
            "locations": [
                {
                    "label": item.label,
                    "path": _hide(item.path, redact),
                    "size_bytes": item.size_bytes,
                    "file_count": item.file_count,
                    "truncated": bool(item.truncated),
                }
                for item in data.temp_locations
            ],
        }

    def battery() -> dict[str, object] | None:
        item = data.battery
        if item is None:
            return None
        return {
            "percent": item.percent,
            "plugged_in": item.plugged_in,
            "seconds_left": item.seconds_left,
            # v2.1 wear figures. A pack that reports no capacity leaves every one of them
            # null, and health_percent stays null with it rather than being extrapolated.
            "design_capacity_mwh": getattr(item, "design_capacity_mwh", None),
            "full_charge_capacity_mwh": getattr(item, "full_charge_capacity_mwh", None),
            "cycle_count": getattr(item, "cycle_count", None),
            "chemistry": getattr(item, "chemistry", None),
            "health_percent": _number(getattr(item, "health_percent", None)),
        }

    def security() -> dict[str, object] | None:
        info = getattr(data, "security", None)
        if info is None:
            return None
        return {
            "antivirus": _state_name(getattr(info, "antivirus", None)),
            "antivirus_name": _text_or_none(getattr(info, "antivirus_name", None)),
            "firewall": _state_name(getattr(info, "firewall", None)),
            "secure_boot": _state_name(getattr(info, "secure_boot", None)),
            "reboot_pending": _bool_or_none(getattr(info, "reboot_pending", None)),
            "defender_last_scan": _iso(getattr(info, "defender_last_scan", None)),
            "signature_age_days": _number(getattr(info, "signature_age_days", None)),
            # An ordered list rather than an object: the producer decides which diagnostics
            # are worth mentioning and in which order, and a reader should see exactly that.
            "details": [
                {"key": str(key), "value": _hide(str(value), redact)}
                for key, value in tuple(getattr(info, "details", ()) or ())
            ],
        }

    def drive_health() -> list[dict[str, object]]:
        return [
            {
                "drive": item.drive,
                "model": item.model,
                "bus_type": item.bus_type,
                "media_type": item.media_type,
                "percentage_used": item.percentage_used,
                # Derived from percentage_used, written out so a reader never has to guess
                # which direction the number runs. Null whenever the drive reported nothing.
                "life_left_percent": _number(getattr(item, "life_left_percent", None)),
                "temperature_celsius": item.temperature_celsius,
                "power_on_hours": item.power_on_hours,
                "data_written_bytes": item.data_written_bytes,
                "critical_warning": _bool_or_none(item.critical_warning),
                # Where the figures came from, so a stored export can still be judged later.
                "source": _text_or_none(item.source),
            }
            for item in getattr(data, "drive_health", ()) or ()
        ]

    def folder_usage() -> list[dict[str, object]]:
        return [
            {
                "key": str(item.key),
                "label": _hide(str(item.label), redact),
                "path": _hide(str(item.path), redact),
                "size_bytes": item.size_bytes,
                "file_count": item.file_count,
                # True when the scan hit its budget: the size is a lower bound, not a total.
                "truncated": bool(item.truncated),
            }
            for item in getattr(data, "folder_usage", ()) or ()
        ]

    def network() -> dict[str, object] | None:
        info = data.network
        if info is None:
            return None
        return {
            "bytes_sent": info.bytes_sent,
            "bytes_received": info.bytes_received,
            "interfaces": [
                {"name": item.name, "is_up": bool(item.is_up), "speed_mbps": item.speed_mbps}
                for item in info.interfaces
            ],
        }

    def gpus() -> list[dict[str, object]]:
        return [
            {
                "name": item.name,
                "driver_version": item.driver_version,
                "driver_date": item.driver_date,
                "memory_bytes": item.memory_bytes,
            }
            for item in data.gpus
        ]

    def startup_items() -> list[dict[str, object]]:
        return [
            {
                "name": item.name,
                "source": item.source,
                "command": _hide(item.command, redact),
            }
            for item in data.startup_items
        ]

    def health() -> dict[str, object]:
        return {
            "score": assessment.score,
            "status": assessment.status,
            "data_complete": bool(assessment.data_complete),
            "deductions": [_deduction_dict(item, translator) for item in assessment.deductions],
            "categories": [
                {
                    "key": item.key,
                    "label": item.label,
                    "score": item.score,
                    "available": bool(item.available),
                    "lost_points": item.lost_points,
                    "deductions": [
                        _deduction_dict(entry, translator) for entry in item.deductions
                    ],
                }
                for item in assessment.categories
            ],
        }

    def advice() -> list[dict[str, object]]:
        return [_recommendation_dict(item, translator, redact) for item in recommendations]

    def warnings() -> list[str | None]:
        return [_hide(str(item), redact) for item in data.warnings]

    return {
        "schema_version": section("schema_version", lambda: data.schema_version),
        "generated_by": section("generated_by", generated_by),
        "analyzed_at": section("analyzed_at", lambda: _iso(data.analyzed_at)),
        "system": section("system", lambda: _system_dict(data)),
        "cpu": section("cpu", cpu),
        "ram": section("ram", ram),
        "disk": section("disk", lambda: _disk_dict(data.disk)),
        "partitions": section(
            "partitions", lambda: [_disk_dict(item) for item in data.partitions]
        ),
        # v2.1: wear of the physical drives behind those partitions, empty when nothing
        # answered without administrator rights.
        "drive_health": section("drive_health", drive_health),
        "processes": section("processes", processes),
        "temp": section("temp", temp),
        # v2.1: the well-known folders that actually take up the space.
        "folder_usage": section("folder_usage", folder_usage),
        "uptime_seconds": section("uptime_seconds", lambda: _number(data.uptime_seconds)),
        "battery": section("battery", battery),
        "network": section("network", network),
        "gpus": section("gpus", gpus),
        "startup_items": section("startup_items", startup_items),
        # v2.1: null when protection was not inspected at all, which is not the same as a
        # machine whose every verdict came back "unknown".
        "security": section("security", security),
        "health": section("health", health),
        "recommendations": section("recommendations", advice),
        "warnings": section("warnings", warnings),
        # Empty on a healthy export; one entry per branch that could not be written, so a
        # reader can always tell a measurement nobody took from one nobody could write.
        "export_errors": failures,
    }


# ----------------------------------------------------------------------------------------
# shared view model for the Markdown and HTML documents
# ----------------------------------------------------------------------------------------


def _metric_sections(
    data: AnalysisData,
    translator: object | None,
    redact: bool,
) -> list[tuple[str, list[tuple[str, str]]]]:
    """Label/value groups shown as cards in HTML and as small tables in Markdown."""

    def t(key: str, default: str, **params: object) -> str:
        return _label(translator, key, default, **params)

    def value(item: object | None) -> str:
        return "N/A" if item is None else str(item)

    system = data.system
    sections: list[tuple[str, list[tuple[str, str]]]] = []

    rows: list[tuple[str, str]] = [
        (t("field.os", "System"), value(system.os_name)),
        (t("field.release", "Release"), value(system.release)),
        (t("field.version", "Version"), value(system.version)),
    ]
    for label, item in (
        (t("field.edition", "Edition"), system.edition),
        (t("field.display_version", "Windows Version"), system.display_version),
        (t("field.build", "Build"), system.build),
    ):
        if item:
            rows.append((label, str(item)))
    rows.append((t("field.architecture", "Architecture"), value(system.architecture)))
    rows.append((t("field.processor", "Processor"), value(system.processor)))
    for label, item in (
        (t("field.manufacturer", "Manufacturer"), system.manufacturer),
        (t("field.model", "Model"), system.model),
        (t("field.bios", "BIOS Version"), system.bios_version),
    ):
        if item:
            rows.append((label, str(item)))
    if system.install_date is not None:
        installed = _short_date(system.install_date)
        rows.append((t("field.install_date", "Windows Installed"), installed))
    if system.boot_time is not None:
        rows.append((t("field.boot_time", "Last Boot"), _short_date(system.boot_time, time=True)))
    sections.append((t("gui.card.system", "System"), rows))

    cpu = data.cpu
    rows = [
        (t("field.usage", "Usage"), format_percent(cpu.usage_percent)),
        (t("field.physical_cores", "Physical Cores"), value(cpu.physical_cores)),
        (t("field.logical_cores", "Logical Cores"), value(cpu.logical_cores)),
    ]
    if cpu.frequency_mhz is not None:
        rows.append((t("field.frequency", "CPU Frequency"), format_frequency(cpu.frequency_mhz)))
    if cpu.max_frequency_mhz is not None:
        rows.append(
            (t("field.max_frequency", "Max Frequency"), format_frequency(cpu.max_frequency_mhz))
        )
    sections.append((t("gui.card.cpu", "Processor"), rows))

    ram = data.ram
    rows = [
        (t("field.usage", "Usage"), format_percent(ram.usage_percent)),
        (t("field.installed", "Installed RAM"), format_bytes(ram.total_bytes)),
        (t("field.used", "Used"), format_bytes(ram.used_bytes)),
        (t("field.available", "Available"), format_bytes(ram.available_bytes)),
    ]
    if ram.swap_total_bytes:
        rows.append(
            (
                t("field.swap", "Page File"),
                t(
                    "report.swap_value",
                    "{used} of {total} ({percent})",
                    used=format_bytes(ram.swap_used_bytes),
                    total=format_bytes(ram.swap_total_bytes),
                    percent=format_percent(ram.swap_percent),
                ),
            )
        )
    sections.append((t("gui.card.ram", "Memory"), rows))

    disk = data.disk
    rows = [
        (t("field.drive", "Drive"), value(disk.drive)),
        (t("field.usage", "Usage"), format_percent(disk.usage_percent)),
        (t("field.free", "Free"), format_bytes(disk.free_bytes)),
        (t("field.used", "Used"), format_bytes(disk.used_bytes)),
        (t("field.total", "Total"), format_bytes(disk.total_bytes)),
    ]
    if disk.filesystem:
        rows.append((t("field.filesystem", "File System"), disk.filesystem))
    if disk.media_type:
        rows.append((t("field.media_type", "Media Type"), disk.media_type))
    sections.append((t("gui.card.disk", "System Drive"), rows))

    sections.append(
        (
            t("gui.card.activity", "Activity"),
            [
                (t("field.processes", "Running Processes"), value(data.process_count)),
                (t("field.uptime", "System Uptime"), format_uptime(data.uptime_seconds)),
            ],
        )
    )

    # A scan that ran out of time measured part of the folder, so the size is a floor. It is
    # labelled here exactly like a truncated single location is, never as an exact figure.
    temp_size = format_bytes(data.temp_size_bytes)
    if getattr(data, "temp_truncated", False):
        temp_size = f"{temp_size} ({t('report.partial_scan', 'partial scan')})"
    sections.append(
        (
            t("gui.card.temp", "Temporary Files"),
            [
                (t("field.folder_size", "Folder Size"), temp_size),
                (t("field.path", "Path"), value(_hide(data.temp_path, redact))),
            ],
        )
    )

    battery = data.battery
    if battery is not None:
        rows = [(t("field.battery", "Battery"), format_percent(battery.percent))]
        if battery.plugged_in is not None:
            rows.append(
                (
                    t("field.plugged_in", "Plugged In"),
                    t("field.yes", "Yes") if battery.plugged_in else t("field.no", "No"),
                )
            )
        if battery.seconds_left is not None:
            rows.append((t("field.time_left", "Time Left"), format_duration(battery.seconds_left)))
        # v2.1 wear. Every line is printed only when the pack actually reported the figure:
        # a battery that answers nothing shows the charge card it always showed, not a column
        # of N/A that looks like a fault.
        health = _number(getattr(battery, "health_percent", None))
        if health is not None:
            rows.append((t("field.battery_health", "Battery Health"), format_percent(health)))
        design = getattr(battery, "design_capacity_mwh", None)
        if design is not None:
            rows.append((t("field.design_capacity", "Design Capacity"), _milliwatt_hours(design)))
        full = getattr(battery, "full_charge_capacity_mwh", None)
        if full is not None:
            rows.append(
                (t("field.full_charge_capacity", "Full Charge Capacity"), _milliwatt_hours(full))
            )
        cycles = getattr(battery, "cycle_count", None)
        if cycles is not None:
            rows.append((t("field.cycle_count", "Charge Cycles"), format_count(cycles)))
        chemistry = getattr(battery, "chemistry", None)
        if chemistry:
            rows.append((t("field.chemistry", "Cell Chemistry"), str(chemistry)))
        sections.append((t("gui.card.battery", "Battery"), rows))

    network = data.network
    if network is not None:
        rows = []
        if network.bytes_sent is not None:
            rows.append((t("field.sent", "Sent"), format_bytes(network.bytes_sent)))
        if network.bytes_received is not None:
            rows.append((t("field.received", "Received"), format_bytes(network.bytes_received)))
        for item in network.interfaces:
            state = t("field.up", "up") if item.is_up else t("field.down", "down")
            if item.speed_mbps:
                state = f"{state}, {format_count(item.speed_mbps)} Mbps"
            rows.append((value(item.name), state))
        if rows:
            sections.append((t("gui.card.network", "Network"), rows))

    if data.gpus:
        rows = []
        for item in data.gpus:
            detail = item.driver_version or ""
            if item.driver_version and item.driver_date:
                detail = t(
                    "report.driver_value",
                    "{version} ({date})",
                    version=item.driver_version,
                    date=item.driver_date,
                )
            if item.memory_bytes:
                detail = f"{detail} - {format_bytes(item.memory_bytes)}".strip(" -")
            rows.append((value(item.name), detail or "N/A"))
        sections.append((t("gui.card.gpu", "Graphics"), rows))

    # Startup items are listed as a full table further down, so no summary card here.
    return sections


# ----------------------------------------------------------------------------------------
# v2.1 tables: state a user can act on, shared verbatim by Markdown and HTML
# ----------------------------------------------------------------------------------------


def _security_table(
    info: object,
    translator: object | None,
) -> tuple[list[str], list[list[object]]]:
    """
    Headers and rows for the protection summary.

    Same checks, same order and same wording as the plain-text report, because a reader who
    compares two exports of one run must find one machine described, not two. Verdict cells
    carry a colour that only HTML looks at. The collector's raw diagnostics are not listed
    here; they stay in the JSON payload, where nothing has to be worded at all.
    """

    def t(key: str, default: str, **params: object) -> str:
        return _label(translator, key, default, **params)

    antivirus = getattr(info, "antivirus", None)
    verdict = _state_text(antivirus, translator)
    name = getattr(info, "antivirus_name", None)
    if name:
        verdict = f"{verdict} ({name})"
    rows: list[list[object]] = [
        [t("field.antivirus", "Antivirus"), _tinted(verdict, antivirus)],
    ]
    for key, default, state in (
        ("field.firewall", "Firewall", getattr(info, "firewall", None)),
        ("field.secure_boot", "Secure Boot", getattr(info, "secure_boot", None)),
    ):
        rows.append([t(key, default), _tinted(_state_text(state, translator), state)])

    pending = getattr(info, "reboot_pending", None)
    if pending is not None:
        rows.append(
            [
                t("field.reboot_pending", "Restart Pending"),
                _tinted(_yes_no(pending, translator), _flag_state(pending, true_state=STATE_WEAK)),
            ]
        )

    age = getattr(info, "signature_age_days", None)
    if age is not None:
        rows.append([t("field.signature_age", "Definitions Age"), _days(age, translator)])

    last_scan = getattr(info, "defender_last_scan", None)
    if last_scan is not None:
        rows.append([t("field.last_scan", "Last Scan"), _short_date(last_scan, time=True)])

    headers = [t("field.name", "Name"), t("report.status", "Status")]
    return headers, rows


def _security_note(info: object, translator: object | None) -> str:
    """
    The sentence that explains an unknown verdict, or "" when there is nothing to explain.

    Without it a reader cannot tell "nobody answered" from "the answer was no", and those
    two are not the same news. Taken from the key the text report uses, word for word.
    """
    if not _security_center_down(info):
        return ""
    return _label(
        translator,
        "report.security_center_down",
        "The Windows Security Center did not answer, so the antivirus and firewall states "
        "are unknown rather than off.",
    )


def _drive_table(
    items: Sequence[object],
    translator: object | None,
) -> tuple[list[str], list[list[object]]]:
    """Headers and rows for the drive wear table. A figure a drive withholds stays N/A."""

    def t(key: str, default: str, **params: object) -> str:
        return _label(translator, key, default, **params)

    rows: list[list[object]] = []
    for item in items:
        life = _number(getattr(item, "life_left_percent", None))
        # The same colour ramp the health score uses, so "how much drive is left" reads like
        # every other share in the report instead of inventing a second visual language.
        life_cell: object = (
            "N/A" if life is None else _Tinted(format_percent(life), _score_color(int(life)))
        )
        warning = getattr(item, "critical_warning", None)
        rows.append(
            [
                getattr(item, "drive", None),
                getattr(item, "model", None),
                getattr(item, "bus_type", None),
                getattr(item, "media_type", None),
                life_cell,
                _temperature(getattr(item, "temperature_celsius", None)),
                _hours(getattr(item, "power_on_hours", None), translator),
                format_bytes(getattr(item, "data_written_bytes", None)),
                _tinted(
                    _yes_no(warning, translator), _flag_state(warning, true_state=STATE_BAD)
                ),
            ]
        )

    headers = [
        t("field.drive", "Drive"),
        t("field.model", "Model"),
        t("field.bus_type", "Bus"),
        t("field.media_type", "Media Type"),
        t("field.life_left", "Life Left"),
        t("field.temperature", "Temperature"),
        t("field.power_on_hours", "Power-on Hours"),
        t("field.data_written", "Data Written"),
        t("field.critical_warning", "Critical Warning"),
    ]
    return headers, rows


def _folder_table(
    items: Sequence[object],
    translator: object | None,
    redact: bool,
) -> tuple[list[str], list[list[object]]]:
    """
    Headers and rows for the biggest measured folders.

    Biggest first is a property of this table, not a favour asked of the collector - the
    text report sorts the very same way, and a folder whose size could not be read sorts
    last, because "unknown" is not "small".
    """

    def t(key: str, default: str, **params: object) -> str:
        return _label(translator, key, default, **params)

    partial = t("report.partial_scan", "partial scan")
    rows: list[list[object]] = []
    for item in sorted(items, key=_folder_size_key, reverse=True):
        size = format_bytes(getattr(item, "size_bytes", None))
        if getattr(item, "truncated", False):
            size = f"{size} ({partial})"
        rows.append(
            [
                _hide(str(getattr(item, "label", "")), redact),
                size,
                format_count(getattr(item, "file_count", None)),
                _hide(str(getattr(item, "path", "")), redact),
            ]
        )

    headers = [
        t("field.folder", "Folder"),
        t("field.folder_size", "Folder Size"),
        t("field.files", "Files"),
        t("field.path", "Path"),
    ]
    return headers, rows


def _short_date(moment: object, *, time: bool = False) -> str:
    if not isinstance(moment, datetime):
        return "N/A" if moment is None else str(moment)
    try:
        return moment.strftime("%Y-%m-%d %H:%M" if time else "%Y-%m-%d")
    except Exception:
        return str(moment)


def _timestamp(data: AnalysisData) -> str:
    moment = data.analyzed_at
    if not isinstance(moment, datetime):
        return "N/A" if moment is None else str(moment)
    try:
        return moment.strftime("%Y-%m-%d %H:%M:%S %Z").strip()
    except Exception:
        return str(moment)


def _status_text(assessment: HealthAssessment, translator: object | None) -> str:
    key = "status." + str(assessment.status).strip().casefold().replace(" ", "_")
    return _label(translator, key, str(assessment.status))


def _deduction_text(item: object, translator: object | None) -> str:
    values = dict(getattr(item, "params", ()) or ())
    key = str(getattr(item, "key", ""))
    return _label(translator, f"deduction.{key}", str(getattr(item, "reason", "")), **values)


def _recommendation_text(item: object, translator: object | None, redact: bool) -> str:
    if isinstance(item, Recommendation):
        text = _label(translator, f"recommendation.{item.key}", str(item.text), **item.values)
        return str(_hide(text, redact))
    return str(_hide(str(item), redact))


def _sections(
    steps: Sequence[Callable[[], list[str]]],
    note: Callable[[BaseException], str],
) -> list[str]:
    """
    Run one document's sections, keeping a failure inside the section that caused it.

    Each step builds its own lines and is merged only after it finished, so a value that
    raises halfway can never leave a half-open table or list behind. This is the same net
    the plain-text builder uses: one damaged measurement costs one section, not the export.
    """
    lines: list[str] = []
    for step in steps:
        try:
            lines.extend(step())
        except Exception as error:
            try:
                lines.append(note(error))
            except Exception:  # Even the apology failed; skip it rather than raise.
                pass
    return lines


# ----------------------------------------------------------------------------------------
# Markdown
# ----------------------------------------------------------------------------------------


def _md_cell(value: object) -> str:
    text = "N/A" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _md_table(headers: Sequence[str], rows: Sequence[Sequence[object]]) -> list[str]:
    lines = [
        "| " + " | ".join(_md_cell(item) for item in headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    lines.extend("| " + " | ".join(_md_cell(cell) for cell in row) + " |" for row in rows)
    return lines


def _render_markdown(
    data: AnalysisData,
    recommendations: Sequence[Recommendation | str],
    assessment: HealthAssessment,
    translator: object | None,
    redact: bool,
) -> str:
    def t(key: str, default: str, **params: object) -> str:
        return _label(translator, key, default, **params)

    def head() -> list[str]:
        score_text = t("report.score_value", "{score}/100", score=assessment.score)
        complete = t("field.yes", "Yes") if assessment.data_complete else t("field.no", "No")
        read_only = t("report.mode_readonly", "Read-only analysis (no settings or files changed)")
        return [
            f"# {t('report.title', APP_NAME)}",
            "",
            f"**{t('report.analysis_date', 'Analysis Date')}:** {_timestamp(data)}  ",
            f"**{t('report.mode', 'Mode')}:** {read_only}",
            "",
            f"## {t('gui.label.score', 'Health score')}",
            "",
            f"**{score_text} - {_status_text(assessment, translator)}**",
            "",
            f"{t('field.data_complete', 'Data Complete')}: {complete}",
        ]

    def categories() -> list[str]:
        if not assessment.categories:
            return []
        rows = [
            [
                _label(translator, f"category.{item.key}", str(item.label)),
                t("report.unavailable", "not measured")
                if not item.available
                else t("report.score_value", "{score}/100", score=item.score),
            ]
            for item in assessment.categories
        ]
        return [
            "",
            f"### {t('report.categories', 'Category scores:').rstrip(':')}",
            "",
            *_md_table([t("field.category", "Category"), t("field.score", "Score")], rows),
        ]

    def deductions() -> list[str]:
        if not assessment.deductions:
            return []
        rows = [
            [
                item.points,
                _label(translator, f"severity.{item.severity}", str(item.severity).title()),
                _deduction_text(item, translator),
            ]
            for item in assessment.deductions
        ]
        headers = [
            t("field.points", "Points"),
            t("field.severity", "Severity"),
            t("field.reason", "Reason"),
        ]
        return [
            "",
            f"### {t('report.deductions', 'Score deductions:').rstrip(':')}",
            "",
            *_md_table(headers, rows),
        ]

    def advice() -> list[str]:
        lines = ["", f"## {t('gui.section.recommendations', 'Recommendations')}", ""]
        if not recommendations:
            lines.append(t("report.none_detected", "None detected."))
            return lines
        for item in recommendations:
            text = _recommendation_text(item, translator, redact)
            severity = getattr(item, "severity", "info")
            marker = _label(translator, f"severity.{severity}", str(severity).title())
            lines.append(f"- **{marker}:** {text}")
            detail = getattr(item, "detail", None)
            if detail:
                lines.append(f"  - {_hide(str(detail), redact)}")
        return lines

    def overview() -> list[str]:
        lines: list[str] = []
        headers = [t("field.name", "Name"), t("field.value", "Value")]
        for title, rows in _metric_sections(data, translator, redact):
            lines.extend(["", f"## {title}", "", *_md_table(headers, rows)])
        return lines

    def partitions() -> list[str]:
        if not data.partitions:
            return []
        rows = [
            [
                item.drive,
                format_bytes(item.total_bytes),
                format_bytes(item.used_bytes),
                format_bytes(item.free_bytes),
                format_percent(item.usage_percent),
                item.media_type or item.filesystem or "N/A",
            ]
            for item in data.partitions
        ]
        headers = [
            t("field.drive", "Drive"),
            t("field.total", "Total"),
            t("field.used", "Used"),
            t("field.free", "Free"),
            t("field.usage", "Usage"),
            t("field.media_type", "Media Type"),
        ]
        return [
            "",
            f"## {t('gui.section.partitions', 'Partitions')}",
            "",
            *_md_table(headers, rows),
        ]

    def security() -> list[str]:
        info = getattr(data, "security", None)
        # Nothing readable is not a finding: three "Unknown" lines would look like one.
        if info is None or not _has_security_data(info):
            return []
        headers, rows = _security_table(info, translator)
        lines = [
            "",
            f"## {t('gui.card.security', 'Security')}",
            "",
            *_md_table(headers, rows),
        ]
        note = _security_note(info, translator)
        if note:
            lines.extend(["", f"*{note}*"])
        return lines

    def drive_health() -> list[str]:
        items = [item for item in getattr(data, "drive_health", ()) or () if _has_drive_data(item)]
        if not items:
            return []
        headers, rows = _drive_table(items, translator)
        return [
            "",
            f"## {t('gui.section.drive_health', 'Drive health')}",
            "",
            *_md_table(headers, rows),
        ]

    def folders() -> list[str]:
        items = list(getattr(data, "folder_usage", ()) or ())
        if not items:
            return []
        headers, rows = _folder_table(items, translator, redact)
        return [
            "",
            f"## {t('gui.section.folders', 'Biggest folders')}",
            "",
            *_md_table(headers, rows),
        ]

    def processes() -> list[str]:
        if not data.top_processes:
            return []
        rows = [
            [
                item.pid,
                item.name,
                format_bytes(item.memory_bytes),
                format_percent(item.memory_percent),
                format_percent(item.cpu_percent),
            ]
            for item in data.top_processes
        ]
        headers = [
            t("field.pid", "PID"),
            t("field.name", "Name"),
            t("field.memory", "Memory"),
            t("field.memory_percent", "Memory %"),
            t("field.cpu_percent", "CPU %"),
        ]
        return [
            "",
            f"## {t('gui.section.processes', 'Top processes')}",
            "",
            *_md_table(headers, rows),
        ]

    def temp() -> list[str]:
        if not data.temp_locations:
            return []
        partial = t("report.partial_scan", "partial scan")
        rows = [
            [
                item.label,
                format_bytes(item.size_bytes) + (f" ({partial})" if item.truncated else ""),
                format_count(item.file_count),
                _hide(item.path, redact),
            ]
            for item in data.temp_locations
        ]
        headers = [
            t("field.label", "Location"),
            t("field.folder_size", "Folder Size"),
            t("field.files", "Files"),
            t("field.path", "Path"),
        ]
        return ["", f"## {t('gui.card.temp', 'Temporary Files')}", "", *_md_table(headers, rows)]

    def startup() -> list[str]:
        if not data.startup_items:
            return []
        rows = [[item.name, item.source] for item in data.startup_items]
        headers = [t("field.name", "Name"), t("field.source", "Source")]
        return [
            "",
            f"## {t('field.startup_items', 'Startup Items')}",
            "",
            *_md_table(headers, rows),
        ]

    def warnings() -> list[str]:
        if not data.warnings:
            return []
        return [
            "",
            f"## {t('gui.section.warnings', 'Analysis warnings')}",
            "",
            *(f"- {_hide(str(item), redact)}" for item in data.warnings),
        ]

    def footer() -> list[str]:
        note = t(
            "report.footer",
            "This report is informational. Apoliak Vitals did not modify your PC.",
        )
        generated = t(
            "report.generated_by",
            "Generated by {name} {version}",
            name=APP_NAME,
            version=APP_VERSION,
        )
        return ["", "---", "", f"*{note}*", "", f"*{generated}*"]

    def failed(error: BaseException) -> str:
        return "\n*" + t(
            "report.section_failed",
            "This section could not be rendered ({error}).",
            error=error,
        ) + "*"

    lines = _sections(
        (
            head,
            categories,
            deductions,
            advice,
            overview,
            security,
            partitions,
            drive_health,
            processes,
            temp,
            folders,
            startup,
            warnings,
            footer,
        ),
        failed,
    )
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------------------------------
# HTML
# ----------------------------------------------------------------------------------------

_HTML_STYLE = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0; padding: 32px 20px 56px;
  background: #14161a; color: #e6e8ec;
  font-family: "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif;
  font-size: 15px; line-height: 1.55;
}
main { max-width: 1040px; margin: 0 auto; }
h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: .2px; }
h2 { font-size: 18px; margin: 34px 0 12px; color: #f2f4f8; }
p.meta { margin: 2px 0; color: #99a1b3; font-size: 13px; }
.score {
  display: flex; align-items: center; gap: 22px; flex-wrap: wrap;
  margin: 26px 0 8px; padding: 22px 26px;
  background: #1b1e24; border: 1px solid #262b34; border-radius: 14px;
}
.score .value { font-size: 54px; font-weight: 700; line-height: 1; }
.score .of { font-size: 18px; color: #7d8698; font-weight: 400; }
.score .status { font-size: 20px; font-weight: 600; }
.score .hint { color: #99a1b3; font-size: 13px; margin-top: 4px; }
.bar { height: 8px; border-radius: 99px; background: #262b34; overflow: hidden; margin-top: 12px; }
.bar span { display: block; height: 100%; border-radius: 99px; }
.grid { display: grid; gap: 14px; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); }
.card { background: #1b1e24; border: 1px solid #262b34; border-radius: 12px; padding: 16px 18px; }
.card h3 { margin: 0 0 10px; font-size: 13px; text-transform: uppercase;
  letter-spacing: .8px; color: #8d97a8; font-weight: 600; }
.card dl { display: grid; grid-template-columns: auto 1fr; gap: 6px 14px; margin: 0; }
.card dt { color: #99a1b3; font-size: 13px; }
.card dd { margin: 0; text-align: right; word-break: break-word;
  font-variant-numeric: tabular-nums; }
ul.items { list-style: none; margin: 0; padding: 0; }
ul.items li {
  background: #1b1e24; border: 1px solid #262b34; border-left-width: 4px;
  border-radius: 10px; padding: 12px 16px; margin-bottom: 10px;
}
ul.items li .tag { font-size: 11px; text-transform: uppercase; letter-spacing: .7px; }
ul.items li .detail { color: #99a1b3; font-size: 13px; margin-top: 4px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #262b34; }
th { color: #8d97a8; font-weight: 600; font-size: 12px; text-transform: uppercase;
  letter-spacing: .6px; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
.table-wrap { overflow-x: auto; background: #1b1e24; border: 1px solid #262b34;
  border-radius: 12px; padding: 4px 8px; }
footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid #262b34;
  color: #7d8698; font-size: 13px; }
@media print { body { background: #fff; color: #111; } .card, ul.items li, .score,
  .table-wrap { background: #fff; border-color: #ccc; } }
"""


def _score_color(score: int) -> str:
    if score >= 90:
        return "#3ddc97"
    if score >= 75:
        return "#6fc3ff"
    if score >= 50:
        return "#ffb454"
    return "#ff6b6b"


def _html_table(
    headers: Sequence[str],
    rows: Sequence[Sequence[object]],
    numeric: Sequence[int] = (),
) -> str:
    head = "".join(f"<th>{escape(str(item))}</th>" for item in headers)
    body: list[str] = []
    for row in rows:
        cells = []
        for index, cell in enumerate(row):
            text = escape("N/A" if cell is None else str(cell))
            # A tinted cell carries a colour from this module's own table, never from the
            # measurement, so the escaped text is all that a PC can put inside the element.
            if isinstance(cell, _Tinted):
                text = f'<span style="color:{cell.color}">{text}</span>'
            cells.append(f'<td class="num">{text}</td>' if index in numeric else f"<td>{text}</td>")
        body.append("<tr>" + "".join(cells) + "</tr>")
    return (
        '<div class="table-wrap"><table><thead><tr>'
        + head
        + "</tr></thead><tbody>"
        + "".join(body)
        + "</tbody></table></div>"
    )


def _render_html(
    data: AnalysisData,
    recommendations: Sequence[Recommendation | str],
    assessment: HealthAssessment,
    translator: object | None,
    redact: bool,
) -> str:
    def t(key: str, default: str, **params: object) -> str:
        return _label(translator, key, default, **params)

    def e(value: object) -> str:
        return escape("N/A" if value is None else str(value))

    def document_open() -> list[str]:
        language = str(getattr(translator, "language", "en") or "en")
        title = e(t("report.title", APP_NAME))
        return [
            "<!DOCTYPE html>",
            f'<html lang="{escape(language)}">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{title}</title>",
            f"<style>{_HTML_STYLE}</style>",
            "</head>",
            "<body><main>",
            f"<h1>{title}</h1>",
        ]

    def intro() -> list[str]:
        read_only = t("report.mode_readonly", "Read-only analysis (no settings or files changed)")
        return [
            f'<p class="meta">{e(t("report.subtitle", "PC health report"))}</p>',
            f'<p class="meta">{e(t("report.analysis_date", "Analysis Date"))}: '
            f"{e(_timestamp(data))}</p>",
            f'<p class="meta">{e(t("report.mode", "Mode"))}: {e(read_only)}</p>',
        ]

    def score() -> list[str]:
        color = _score_color(assessment.score)
        hint = e(t("gui.label.score_hint", "100 points minus every issue listed below."))
        complete_label = e(t("field.data_complete", "Data Complete"))
        complete = e(t("field.yes", "Yes") if assessment.data_complete else t("field.no", "No"))
        width = max(0, min(100, int(assessment.score)))
        return [
            '<section class="score">',
            f'<div><div class="value" style="color:{color}">{assessment.score}'
            f'<span class="of">/100</span></div></div>',
            "<div>",
            f'<div class="status" style="color:{color}">'
            f"{e(_status_text(assessment, translator))}</div>",
            f'<div class="hint">{hint}</div>',
            f'<div class="hint">{complete_label}: {complete}</div>',
            f'<div class="bar"><span style="width:{width}%;background:{color}"></span></div>',
            "</div>",
            "</section>",
        ]

    def categories() -> list[str]:
        if not assessment.categories:
            return []
        rows = [
            [
                _label(translator, f"category.{item.key}", str(item.label)),
                t("report.unavailable", "not measured")
                if not item.available
                else t("report.score_value", "{score}/100", score=item.score),
                item.lost_points,
            ]
            for item in assessment.categories
        ]
        headers = [
            t("field.category", "Category"),
            t("field.score", "Score"),
            t("field.points", "Points"),
        ]
        return [
            f"<h2>{e(t('gui.section.categories', 'Category scores'))}</h2>",
            _html_table(headers, rows, numeric=(1, 2)),
        ]

    def deductions() -> list[str]:
        heading = f"<h2>{e(t('gui.section.deductions', 'Score deductions'))}</h2>"
        if not assessment.deductions:
            empty = e(t("report.no_deductions", "No deductions were applied."))
            return [heading, f'<p class="meta">{empty}</p>']
        items = []
        for item in assessment.deductions:
            accent = _SEVERITY_COLORS.get(str(item.severity), "#6fc3ff")
            marker = _label(translator, f"severity.{item.severity}", str(item.severity).title())
            # The noun is resolved per row: Slovak says "1 bod", "3 body" and "18 bodov".
            word = e(_plural(translator, "report.points", item.points, _POINT_WORDS))
            items.append(
                f'<li style="border-left-color:{accent}">'
                f'<span class="tag" style="color:{accent}">{e(marker)}</span> '
                f"<strong>-{item.points} {word}</strong><br>"
                f"{e(_deduction_text(item, translator))}</li>"
            )
        return [heading, '<ul class="items">' + "".join(items) + "</ul>"]

    def advice() -> list[str]:
        heading = f"<h2>{e(t('gui.section.recommendations', 'Recommendations'))}</h2>"
        if not recommendations:
            none = e(t("report.none_detected", "None detected."))
            return [heading, f'<p class="meta">{none}</p>']
        items = []
        for item in recommendations:
            severity = str(getattr(item, "severity", "info"))
            accent = _SEVERITY_COLORS.get(severity, "#6fc3ff")
            marker = _label(translator, f"severity.{severity}", severity.title())
            detail = getattr(item, "detail", None)
            detail_html = (
                f'<div class="detail">{e(_hide(str(detail), redact))}</div>' if detail else ""
            )
            items.append(
                f'<li style="border-left-color:{accent}">'
                f'<span class="tag" style="color:{accent}">{e(marker)}</span><br>'
                f"{e(_recommendation_text(item, translator, redact))}{detail_html}</li>"
            )
        return [heading, '<ul class="items">' + "".join(items) + "</ul>"]

    def overview() -> list[str]:
        cards = []
        for title, rows in _metric_sections(data, translator, redact):
            entries = "".join(f"<dt>{e(label)}</dt><dd>{e(value)}</dd>" for label, value in rows)
            cards.append(f'<div class="card"><h3>{e(title)}</h3><dl>{entries}</dl></div>')
        if not cards:
            return []
        return [
            f"<h2>{e(t('gui.section.overview', 'Overview'))}</h2>",
            '<div class="grid">' + "".join(cards) + "</div>",
        ]

    def partitions() -> list[str]:
        if not data.partitions:
            return []
        rows = [
            [
                item.drive,
                format_bytes(item.total_bytes),
                format_bytes(item.used_bytes),
                format_bytes(item.free_bytes),
                format_percent(item.usage_percent),
                item.media_type or item.filesystem,
            ]
            for item in data.partitions
        ]
        headers = [
            t("field.drive", "Drive"),
            t("field.total", "Total"),
            t("field.used", "Used"),
            t("field.free", "Free"),
            t("field.usage", "Usage"),
            t("field.media_type", "Media Type"),
        ]
        return [
            f"<h2>{e(t('gui.section.partitions', 'Partitions'))}</h2>",
            _html_table(headers, rows, numeric=(1, 2, 3, 4)),
        ]

    def security() -> list[str]:
        info = getattr(data, "security", None)
        # Nothing readable is not a finding: three "Unknown" rows would look like one.
        if info is None or not _has_security_data(info):
            return []
        headers, rows = _security_table(info, translator)
        parts = [
            f"<h2>{e(t('gui.card.security', 'Security'))}</h2>",
            _html_table(headers, rows),
        ]
        note = _security_note(info, translator)
        if note:
            parts.append(f'<p class="meta">{e(note)}</p>')
        return parts

    def drive_health() -> list[str]:
        items = [item for item in getattr(data, "drive_health", ()) or () if _has_drive_data(item)]
        if not items:
            return []
        headers, rows = _drive_table(items, translator)
        return [
            f"<h2>{e(t('gui.section.drive_health', 'Drive health'))}</h2>",
            _html_table(headers, rows, numeric=(4, 5, 6, 7)),
        ]

    def folders() -> list[str]:
        items = list(getattr(data, "folder_usage", ()) or ())
        if not items:
            return []
        headers, rows = _folder_table(items, translator, redact)
        return [
            f"<h2>{e(t('gui.section.folders', 'Biggest folders'))}</h2>",
            _html_table(headers, rows, numeric=(1, 2)),
        ]

    def processes() -> list[str]:
        if not data.top_processes:
            return []
        rows = [
            [
                item.pid,
                item.name,
                format_bytes(item.memory_bytes),
                format_percent(item.memory_percent),
                format_percent(item.cpu_percent),
            ]
            for item in data.top_processes
        ]
        headers = [
            t("field.pid", "PID"),
            t("field.name", "Name"),
            t("field.memory", "Memory"),
            t("field.memory_percent", "Memory %"),
            t("field.cpu_percent", "CPU %"),
        ]
        return [
            f"<h2>{e(t('gui.section.processes', 'Top processes'))}</h2>",
            _html_table(headers, rows, numeric=(0, 2, 3, 4)),
        ]

    def temp() -> list[str]:
        if not data.temp_locations:
            return []
        partial = t("report.partial_scan", "partial scan")
        rows = [
            [
                item.label,
                format_bytes(item.size_bytes) + (f" ({partial})" if item.truncated else ""),
                format_count(item.file_count),
                _hide(item.path, redact),
            ]
            for item in data.temp_locations
        ]
        headers = [
            t("field.label", "Location"),
            t("field.folder_size", "Folder Size"),
            t("field.files", "Files"),
            t("field.path", "Path"),
        ]
        return [
            f"<h2>{e(t('gui.card.temp', 'Temporary Files'))}</h2>",
            _html_table(headers, rows, numeric=(1, 2)),
        ]

    def startup() -> list[str]:
        if not data.startup_items:
            return []
        rows = [[item.name, item.source] for item in data.startup_items]
        headers = [t("field.name", "Name"), t("field.source", "Source")]
        return [
            f"<h2>{e(t('field.startup_items', 'Startup Items'))}</h2>",
            _html_table(headers, rows, numeric=()),
        ]

    def warnings() -> list[str]:
        if not data.warnings:
            return []
        items = "".join(
            f'<li style="border-left-color:#ffb454">{e(_hide(str(item), redact))}</li>'
            for item in data.warnings
        )
        return [
            f"<h2>{e(t('gui.section.warnings', 'Analysis warnings'))}</h2>",
            '<ul class="items">' + items + "</ul>",
        ]

    def document_close() -> list[str]:
        note = t(
            "report.footer",
            "This report is informational. Apoliak Vitals did not modify your PC.",
        )
        generated = t(
            "report.generated_by",
            "Generated by {name} {version}",
            name=APP_NAME,
            version=APP_VERSION,
        )
        return [
            f"<footer>{e(note)}<br>{e(generated)}</footer>",
            "</main></body>",
            "</html>",
        ]

    def failed(error: BaseException) -> str:
        text = t(
            "report.section_failed",
            "This section could not be rendered ({error}).",
            error=error,
        )
        return f'<p class="meta">{e(text)}</p>'

    parts = _sections(
        (
            document_open,
            intro,
            score,
            categories,
            deductions,
            advice,
            overview,
            security,
            partitions,
            drive_health,
            processes,
            temp,
            folders,
            startup,
            warnings,
            document_close,
        ),
        failed,
    )
    return "\n".join(parts) + "\n"


# ----------------------------------------------------------------------------------------
# public rendering API
# ----------------------------------------------------------------------------------------


def render(
    fmt: str,
    data: AnalysisData,
    recommendations: Sequence[Recommendation | str],
    assessment: HealthAssessment,
    *,
    translator: object | None = None,
    redact: bool = False,
) -> str:
    """
    Render one analysis in the requested format. Unknown formats raise ValueError.

    ``translator=None`` means English from the i18n catalogue, not each producer's own
    sentence, so two formats of one run always word the same finding the same way.
    """
    name = _normalize_format(fmt)
    words = translator if translator is not None else _english()
    if name == "text":
        return build_report(
            data, recommendations, assessment, translator=words, redact=redact, colors=None
        )
    if name == "json":
        payload = snapshot_to_dict(
            data, recommendations, assessment, redact=redact, translator=words
        )
        return json.dumps(payload, indent=2, ensure_ascii=False)
    if name == "markdown":
        return _render_markdown(data, recommendations, assessment, words, redact)
    return _render_html(data, recommendations, assessment, words, redact)


def export(
    fmt: str,
    data: AnalysisData,
    recommendations: Sequence[Recommendation | str],
    assessment: HealthAssessment,
    output_path: str | Path,
    *,
    translator: object | None = None,
    redact: bool = False,
) -> Path:
    """
    Write one rendered report as UTF-8 and return the resolved destination.

    A file name the caller supplied is written as given - overwriting is what a chosen path
    means. A name generated here for a folder target is resolved to a free one instead, so
    two exports in the same second cannot silently replace each other.
    """
    name = _normalize_format(fmt)
    destination = Path(output_path).expanduser()
    if destination.exists() and destination.is_dir():
        destination = unique_path(destination / default_filename(name))
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = render(
        name, data, recommendations, assessment, translator=translator, redact=redact
    )
    destination.write_text(content, encoding="utf-8")
    return destination.resolve()
