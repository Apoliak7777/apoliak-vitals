"""Rule-based, non-destructive recommendations for analyzed PCs.

Advice never acts. Every sentence points at a tool Windows already ships (Task Manager,
Settings > System > Storage, Settings > Apps > Startup) and describes what the user would
see there. Nothing here tells anyone to delete system files, disable protection, or expect
a specific number of frames or percent.

The thresholds are read out of :data:`src.health_score.SCORE_RULES`, so the report can
never deduct points for something it then fails to mention - or advise on something the
score considered fine. The same reasoning applies to the drive: advice reads ``data.disk``,
the drive the snapshot is about, exactly as the score does.

v2.1 advice may also carry ``action_uri``, the Windows settings page the sentence is about.
It is a pointer, never an action: nothing here opens it, and the interface only does so when
the user clicks. Opening a settings page shows a switch; it never flips one. Two pieces of
advice deliberately have no page at all - Secure Boot lives in the firmware, and no settings
page can undo a drive's wear.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from string import Formatter

from .health_score import (
    LOWER_BOUND_PARAM,
    MIN_MEANINGFUL_SWAP_BYTES,
    SCORE_RULES,
    STATE_LEVELS,
    english_lower_bound,
    failing_drive,
    most_worn_drive,
    required_values_present,
    state_level,
)
from .models import (
    CATEGORY_CPU,
    CATEGORY_GENERAL,
    CATEGORY_MAINTENANCE,
    CATEGORY_MEMORY,
    CATEGORY_POWER,
    CATEGORY_SECURITY,
    CATEGORY_STORAGE,
    STATE_GOOD,
    AnalysisData,
    DiskInfo,
    FolderUsage,
    ProcessInfo,
    Recommendation,
    severity_rank,
)
from .utils import GIB, format_bytes, format_count, format_percent, format_uptime

_TIER_THRESHOLDS: dict[tuple[str, str], float] = {
    (rule.key, rule.tier): float(rule.threshold) for rule in SCORE_RULES
}


def _tier(key: str, tier: str, fallback: float) -> float:
    """Read a score threshold, falling back to the documented literal if a row is missing."""
    return _TIER_THRESHOLDS.get((key, tier), fallback)


# Thresholds mirrored from the score table; the literal is the value expected today.
# Every "MEDIUM_" row is the mild tier of a rule that already deducts points there, so the
# report cannot charge for a measurement it then declines to explain.
CPU_HIGH_PERCENT = _tier("high_cpu", "standard", 70.0)
CPU_CRITICAL_PERCENT = _tier("high_cpu", "high", 85.0)
MEDIUM_CPU_PERCENT = _tier("high_cpu", "mild", 55.0)
RAM_HIGH_PERCENT = _tier("high_ram", "standard", 80.0)
RAM_CRITICAL_PERCENT = _tier("high_ram", "high", 90.0)
MEDIUM_RAM_PERCENT = _tier("high_ram", "mild", 70.0)
SWAP_HIGH_PERCENT = _tier("high_swap", "standard", 75.0)
SWAP_CRITICAL_PERCENT = _tier("high_swap", "severe", 90.0)
MEDIUM_SWAP_PERCENT = _tier("high_swap", "mild", 50.0)
DISK_LOW_BYTES = _tier("low_disk", "standard", 20 * GIB)
DISK_CRITICAL_BYTES = _tier("low_disk", "high", 10 * GIB)
MEDIUM_DISK_BYTES = _tier("low_disk", "mild", 50 * GIB)
DISK_FULL_PERCENT = _tier("disk_nearly_full", "standard", 92.0)
DISK_FULL_CRITICAL_PERCENT = _tier("disk_nearly_full", "severe", 97.0)
MEDIUM_DISK_FULL_PERCENT = _tier("disk_nearly_full", "mild", 85.0)
MANY_PROCESSES_COUNT = _tier("many_processes", "standard", 180)
SOME_PROCESSES_COUNT = _tier("many_processes", "mild", 150)
LARGE_TEMP_BYTES = _tier("large_temp", "standard", 3 * GIB)
MEDIUM_TEMP_BYTES = _tier("large_temp", "mild", GIB)
LONG_UPTIME_SECONDS = _tier("long_uptime", "standard", 48 * 3600)
MEDIUM_UPTIME_SECONDS = _tier("long_uptime", "mild", 24 * 3600)
MANY_STARTUP_COUNT = _tier("many_startup_items", "mild", 12)
HEAVY_STARTUP_COUNT = _tier("many_startup_items", "standard", 20)
BATTERY_LOW_PERCENT = _tier("low_battery", "mild", 25.0)
BATTERY_CRITICAL_PERCENT = _tier("low_battery", "standard", 15.0)

# v2.1 state rules. The protection thresholds are read from the same ladder the score uses,
# so "the rule fired" and "the advice fired" cannot drift apart into a report that deducts
# 30 points for an unguarded PC and then declines to mention it.
ANTIVIRUS_LEVEL = _tier("antivirus_off", "standard", 0.5)
FIREWALL_LEVEL = _tier("firewall_off", "standard", 0.5)
#: Secure Boot has no rule of its own (it is advice only), so its bar is the ladder's own
#: "anything worse than good" rung rather than a threshold borrowed from a deduction.
SECURE_BOOT_LEVEL = STATE_LEVELS[STATE_GOOD]
STALE_SIGNATURE_DAYS = _tier("stale_signatures", "standard", 7.0)
DRIVE_WORN_PERCENT = _tier("drive_worn", "mild", 30.0)
DRIVE_WORN_WARNING_PERCENT = _tier("drive_worn", "standard", 20.0)
DRIVE_WORN_CRITICAL_PERCENT = _tier("drive_worn", "severe", 10.0)
BATTERY_WORN_PERCENT = _tier("battery_worn", "mild", 70.0)
BATTERY_WORN_WARNING_PERCENT = _tier("battery_worn", "standard", 60.0)

#: A single process is only worth naming once it owns a visible share of the machine.
TOP_MEMORY_PERCENT = 15.0
TOP_CPU_PERCENT = 25.0

#: A user folder is worth naming when it is large in absolute terms, or when it owns a
#: visible share of the drive it sits on. Both are needed: 20 GB is a lot on a 256 GB laptop
#: and unremarkable on a 4 TB desktop, and the reverse holds for the percentage.
LARGE_FOLDER_BYTES = 20 * GIB
LARGE_FOLDER_DRIVE_PERCENT = 10.0

#: The Windows settings page each piece of advice is about. Opening one shows the user the
#: switch this application deliberately never touches; it changes nothing by itself, and it
#: is only ever launched by a deliberate click in the interface, never during an analysis.
#: A key missing from this table simply has no page - a wrong page is worse than none.
RECOMMENDATION_ACTIONS: dict[str, str] = {
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
    # Deliberately absent: secure_boot_off (the switch lives in the firmware, not in
    # Windows), drive_worn and drive_failing (no settings page changes a drive's wear).
}

#: English text for every recommendation key. Translations reuse the same placeholders
#: under "recommendation.<key>", which is why the wording is kept in one place.
RECOMMENDATION_TEMPLATES: dict[str, str] = {
    "high_cpu": (
        "CPU usage is high at {value}. That is normal during updates, virus scans or "
        "rendering; if it stays high, review the busiest apps in Task Manager."
    ),
    "medium_cpu": (
        "CPU usage is moderate at {value}. Something is working in the background, which is "
        "usually fine; Task Manager names it if the PC keeps feeling busy."
    ),
    "high_ram": (
        "RAM usage is high at {value}. Closing apps you are not using is the quickest "
        "relief, and Task Manager shows which ones hold the most memory."
    ),
    "medium_ram": (
        "RAM usage is moderate at {value}. There is still headroom; closing apps and browser "
        "tabs you have finished with keeps it that way."
    ),
    "high_swap": (
        "The Windows page file is {value} used, which usually means physical RAM is "
        "running short. Closing a few heavy apps takes the pressure off."
    ),
    "medium_swap": (
        "The Windows page file is {value} used. That is ordinary on a busy PC; if it keeps "
        "climbing, closing a heavy app gives physical RAM room to work."
    ),
    "low_disk": (
        "Low free disk space: {drive} has only {value} left. Windows Storage settings "
        "(Settings > System > Storage) shows what is taking the room."
    ),
    "medium_disk": (
        "{drive} is down to {value} free. There is still room to work with; Windows Storage "
        "settings (Settings > System > Storage) shows what is using it."
    ),
    "disk_nearly_full": (
        "{drive} is {value} full. Reviewing large files and unused apps in Windows Storage "
        "settings keeps space free for Windows updates."
    ),
    "medium_disk_full": (
        "{drive} is {value} full. That still leaves room for Windows updates; Windows "
        "Storage settings shows what is taking the most space."
    ),
    "many_processes": (
        "{value} processes are running. Reviewing the startup apps in Settings > Apps > "
        "Startup is the safest way to bring that number down."
    ),
    "some_processes": (
        "{value} processes are running. If the PC feels slow, check the startup apps in "
        "Settings > Apps > Startup for entries you do not need."
    ),
    "large_temp": (
        "Temporary files are taking {value}. Windows Storage settings can review and clean "
        "them safely."
    ),
    "medium_temp": (
        "Temporary files are taking {value}. Windows Storage settings can reclaim that "
        "space whenever you need it."
    ),
    "long_uptime": (
        "The PC has been running for {value}. A restart lets Windows finish pending "
        "updates and returns memory that apps never released."
    ),
    "medium_uptime": (
        "The PC has been running for {value}. A restart before a demanding work or gaming "
        "session is a cheap way to start clean."
    ),
    "many_startup_items": (
        "{value} startup entries were found. Settings > Apps > Startup shows what launches "
        "with Windows so you can switch off what you do not need."
    ),
    "low_battery": (
        "The battery is at {value} and the PC is not plugged in. Measurements taken on "
        "battery can also look worse, because Windows limits performance to save power."
    ),
    "top_memory_process": (
        "{name} is the largest memory consumer at {value}. Closing it frees the most "
        "memory if you are not using it right now."
    ),
    "top_cpu_process": (
        "{name} is the busiest process at {value} CPU. That is expected while it updates, "
        "scans or renders something."
    ),
    "hdd_system_drive": (
        "Drive {drive} reports a rotating hard disk ({value}). On a PC like this an SSD "
        "upgrade is usually the single biggest real-world improvement; no software setting "
        "can replace it."
    ),
    # Advice about durable state. It stays calm on purpose: "this PC is not properly
    # protected" is a fact the reader can act on, "your PC is in danger" is a scare that
    # helps nobody. The wording matches the shipped English catalogue, so the fallback a
    # consumer without a translator prints and the sentence a translated report prints stay
    # the same sentence.
    #
    # Both sentences have to hold for either rung of their rule, since one template covers
    # the weak and the bad tier alike. A flat "protection is not active" would overstate the
    # common case: the collector reports antivirus as weak for protection that is present but
    # paused or degraded, and reports the firewall as weak when even one network profile is
    # switched off while the others still guard the PC. Naming the profiles is left to the
    # security section, which already lists exactly which ones are off.
    "antivirus_off": (
        "Windows Security reports that this PC is not properly protected. It shows what is "
        "guarding the PC and can switch protection back on."
    ),
    "firewall_off": (
        "The Windows firewall is not active on every network profile. Windows Security shows "
        "which profiles are switched off and can switch them back on."
    ),
    "stale_signatures": (
        "Antivirus definitions are not up to date. Windows Security refreshes them by itself "
        "once the PC is online, and you can start the update there too."
    ),
    # Advice only - there is deliberately no deduction for this. Secure Boot is off for many
    # legitimate reasons, and taking points away for a dual-boot machine would be dishonest.
    "secure_boot_off": (
        "Secure Boot is off. A dual-boot setup or older firmware is a normal reason for that, "
        "so this is context rather than a fault, and no points are deducted for it."
    ),
    "reboot_pending": (
        "Windows is waiting for a restart to finish an update. Restarting at a time that "
        "suits you completes it."
    ),
    # Neither drive sentence predicts anything. The first repeats the drive's own warning,
    # the second repeats the drive's own wear figure; a date, or "this disk will die", would
    # be an invention this application has no way to make.
    "drive_failing": (
        "The drive ({drive}) reports a critical health warning. Back up what matters to you "
        "now and have the drive checked."
    ),
    "drive_worn": (
        "The drive ({drive}) is wearing out ({value} of its rated life left). It still works, "
        "so plan the replacement calmly instead of waiting for a failure."
    ),
    "battery_worn": (
        "The battery is worn ({value} of its original capacity). Expect shorter runtime away "
        "from the charger; wear like this is normal ageing, not a fault."
    ),
    "large_folder": (
        "{name} takes up the most space of the folders measured ({value}). Windows Storage "
        "settings show what is inside before you clear anything out."
    ),
    "incomplete_data": (
        "Some measurements were unavailable on this system. Review the analysis warnings "
        "before relying on the score."
    ),
    "all_good": (
        "No urgent issues were detected. Keeping Windows and your apps up to date is the "
        "best next step."
    ),
}


def generate_recommendations(data: AnalysisData) -> list[Recommendation]:
    """Return safe, deterministic advice for one snapshot. Unknown values produce nothing."""
    found: list[Recommendation] = []
    _advise_cpu(data, found)
    _advise_memory(data, found)
    _advise_storage(data, found)
    _advise_maintenance(data, found)
    _advise_power(data, found)
    _advise_processes(data, found)
    _advise_security(data, found)

    # A collector that failed loudly (a warning) and one that returned nothing at all are the
    # same thing to a reader, so both disclose. required_values_present() is the score's own
    # definition, which keeps the disclosure and the assessment's data_complete flag in step.
    if data.warnings or not required_values_present(data):
        found.append(_make("incomplete_data", "warning", CATEGORY_GENERAL))
    if not found:
        found.append(_make("all_good", "info", CATEGORY_GENERAL))

    found.sort(key=lambda item: (-severity_rank(item.severity), item.category, item.key))
    return found


def _advise_cpu(data: AnalysisData, found: list[Recommendation]) -> None:
    usage = _as_float(data.cpu.usage_percent)
    if usage is None:
        return
    if usage > CPU_HIGH_PERCENT:
        severity = "critical" if usage > CPU_CRITICAL_PERCENT else "warning"
        found.append(_make("high_cpu", severity, CATEGORY_CPU, value=format_percent(usage)))
    elif usage > MEDIUM_CPU_PERCENT:
        # The score's mild tier already charges points here, so staying silent would print a
        # deduction next to "no urgent issues were detected".
        found.append(_make("medium_cpu", "info", CATEGORY_CPU, value=format_percent(usage)))


def _advise_memory(data: AnalysisData, found: list[Recommendation]) -> None:
    usage = _as_float(data.ram.usage_percent)
    if usage is not None:
        if usage > RAM_HIGH_PERCENT:
            severity = "critical" if usage > RAM_CRITICAL_PERCENT else "warning"
            found.append(_make("high_ram", severity, CATEGORY_MEMORY, value=format_percent(usage)))
        elif usage > MEDIUM_RAM_PERCENT:
            # Same reasoning as the CPU mild tier: the score deducts here, so advice follows.
            found.append(_make("medium_ram", "info", CATEGORY_MEMORY, value=format_percent(usage)))

    swap_total = _as_float(data.ram.swap_total_bytes)
    swap_usage = _as_float(data.ram.swap_percent)
    # A tiny or disabled page file reports extreme percentages that say nothing about
    # memory pressure, so it is left out entirely - the same guard the score uses.
    if swap_total is None or swap_total < MIN_MEANINGFUL_SWAP_BYTES:
        swap_usage = None
    if swap_usage is not None:
        value = format_percent(swap_usage)
        if swap_usage > SWAP_HIGH_PERCENT:
            severity = "critical" if swap_usage > SWAP_CRITICAL_PERCENT else "warning"
            found.append(_make("high_swap", severity, CATEGORY_MEMORY, value=value))
        elif swap_usage > MEDIUM_SWAP_PERCENT:
            found.append(_make("medium_swap", "info", CATEGORY_MEMORY, value=value))


def _advise_storage(data: AnalysisData, found: list[Recommendation]) -> None:
    # data.disk is the drive the snapshot is *about*: analyze_pc(drive=...) can point it at
    # something other than C:, and the score reads that same record. Picking a different
    # drive here once produced a report that deducted 32 points for a full disk and then
    # said nothing was wrong, so this must stay the one authoritative source.
    disk = data.disk
    drive = _drive_label(disk.drive)
    free = _as_float(disk.free_bytes)
    usage = _disk_usage_percent(disk)

    # The order below mirrors the score's own suppression rule exactly: the free-bytes rule
    # wins whenever it fires at any tier, and only then does the percentage rule get a turn.
    # Each branch quotes the same number its deduction quotes, because advice that answers a
    # "49.0 GB free" deduction with "90% full" explains a different measurement.
    if free is not None and free < DISK_LOW_BYTES:
        severity = "critical" if free < DISK_CRITICAL_BYTES else "warning"
        value = format_bytes(free)
        found.append(_make("low_disk", severity, CATEGORY_STORAGE, drive=drive, value=value))
    elif free is not None and free < MEDIUM_DISK_BYTES:
        # The mild tier of low_disk. It deducts points, so it has to say something: an
        # ordinary 512 GB laptop with 60 GB left used to lose 8 points in silence.
        value = format_bytes(free)
        found.append(_make("medium_disk", "info", CATEGORY_STORAGE, drive=drive, value=value))
    elif usage is not None and usage > DISK_FULL_PERCENT:
        # Only the case the free-bytes rule misses: a big drive that is nearly full but
        # still has room to spare. Saying both would be the same advice twice.
        severity = "critical" if usage > DISK_FULL_CRITICAL_PERCENT else "warning"
        full = format_percent(usage)
        found.append(_make("disk_nearly_full", severity, CATEGORY_STORAGE, drive=drive, value=full))
    elif usage is not None and usage > MEDIUM_DISK_FULL_PERCENT:
        # The mild tier of disk_nearly_full, reached only on a drive roomy enough that the
        # free-bytes rule stayed quiet - a 1 TB disk at 90% still has 100 GB left.
        full = format_percent(usage)
        found.append(
            _make("medium_disk_full", "info", CATEGORY_STORAGE, drive=drive, value=full)
        )

    media = _rotating_media(disk)
    if media is not None:
        found.append(_make("hdd_system_drive", "info", CATEGORY_STORAGE, drive=drive, value=media))

    _advise_drive_health(data, found)
    _advise_folders(data, found)


def _advise_drive_health(data: AnalysisData, found: list[Recommendation]) -> None:
    """Report what the drives say about themselves. Never predicts, never sets a date."""
    # The same selectors the score uses, so the deduction and the advice name one drive.
    failing = failing_drive(data.drive_health)
    if failing is not None:
        found.append(
            _make("drive_failing", "critical", CATEGORY_STORAGE, drive=_drive_label(failing.drive))
        )

    worn = most_worn_drive(data.drive_health)
    life_left = None if worn is None else _as_float(worn.life_left_percent)
    if worn is None or life_left is None or life_left >= DRIVE_WORN_PERCENT:
        return
    if life_left < DRIVE_WORN_CRITICAL_PERCENT:
        severity = "critical"
    elif life_left < DRIVE_WORN_WARNING_PERCENT:
        severity = "warning"
    else:
        severity = "info"
    found.append(
        _make(
            "drive_worn",
            severity,
            CATEGORY_STORAGE,
            drive=_drive_label(worn.drive),
            value=format_percent(life_left),
        )
    )


def _advise_folders(data: AnalysisData, found: list[Recommendation]) -> None:
    """Name the one user folder worth looking at, if any folder was actually measured."""
    folder = _largest_folder(data)
    if folder is None:
        return
    size = _as_float(folder.size_bytes)
    if size is None:
        return
    share = _drive_share_percent(size, data.disk)
    if size < LARGE_FOLDER_BYTES and (share is None or share < LARGE_FOLDER_DRIVE_PERCENT):
        return
    found.append(
        _make(
            "large_folder",
            "info",
            CATEGORY_STORAGE,
            # A scan cut short reports a floor, exactly as a truncated TEMP scan does.
            lower_bound=bool(folder.truncated),
            name=str(folder.label or folder.key),
            value=format_bytes(size),
        )
    )


def _largest_folder(data: AnalysisData) -> FolderUsage | None:
    """The biggest measured folder, ties broken by label and key so the pick is stable."""
    temp_path = str(data.temp_path or "").strip().casefold()
    measured = [
        folder
        for folder in data.folder_usage
        # TEMP has its own finding with its own advice; saying it twice under two names
        # would report one measurement as two problems.
        if _as_float(folder.size_bytes) is not None
        and str(folder.path or "").strip().casefold() != temp_path
    ]
    if not measured:
        return None
    measured.sort(
        key=lambda folder: (
            -(_as_float(folder.size_bytes) or 0.0),
            str(folder.label or "").casefold(),
            str(folder.key or ""),
        )
    )
    return measured[0]


def _drive_share_percent(size: float, disk: DiskInfo) -> float | None:
    """What share of the analysed drive a folder occupies, or None when the total is unknown."""
    total = _as_float(disk.total_bytes)
    if total is None or total <= 0:
        return None
    return size / total * 100.0


def _advise_security(data: AnalysisData, found: list[Recommendation]) -> None:
    """Report the protection settings. An unreadable verdict says nothing at all."""
    security = data.security
    if security is None:
        return

    # None of these quote a number: the finding is that a setting is off, and the severity -
    # not the wording - carries how far off it is. The measured verdicts and the signature
    # age are reported in full in the security section of the report.
    antivirus = state_level(security.antivirus)
    if antivirus is not None and antivirus > ANTIVIRUS_LEVEL:
        found.append(_make("antivirus_off", "critical", CATEGORY_SECURITY))

    firewall = state_level(security.firewall)
    if firewall is not None and firewall > FIREWALL_LEVEL:
        found.append(_make("firewall_off", "warning", CATEGORY_SECURITY))

    age = _as_float(security.signature_age_days)
    if age is not None and age > STALE_SIGNATURE_DAYS:
        found.append(_make("stale_signatures", "warning", CATEGORY_SECURITY))

    # Advice only, and deliberately so: Secure Boot is off for legitimate reasons on plenty
    # of machines, and deducting points for a dual-boot setup would be dishonest.
    secure_boot = state_level(security.secure_boot)
    if secure_boot is not None and secure_boot > SECURE_BOOT_LEVEL:
        found.append(_make("secure_boot_off", "info", CATEGORY_SECURITY))


def _advise_maintenance(data: AnalysisData, found: list[Recommendation]) -> None:
    processes = _as_float(data.process_count)
    if processes is not None:
        count = format_count(int(processes))
        if processes > MANY_PROCESSES_COUNT:
            found.append(_make("many_processes", "warning", CATEGORY_MAINTENANCE, value=count))
        elif processes > SOME_PROCESSES_COUNT:
            found.append(_make("some_processes", "info", CATEGORY_MAINTENANCE, value=count))

    temp_size = _as_float(data.temp_size_bytes)
    if temp_size is not None:
        size = format_bytes(temp_size)
        # A scan cut short by its time budget produced a floor, and the deduction for the
        # same folder already says so. Quoting it here as an exact total would state one
        # measurement two ways inside a single report.
        floor = bool(data.temp_truncated)
        if temp_size > LARGE_TEMP_BYTES:
            found.append(
                _make("large_temp", "warning", CATEGORY_MAINTENANCE, lower_bound=floor, value=size)
            )
        elif temp_size > MEDIUM_TEMP_BYTES:
            found.append(
                _make("medium_temp", "info", CATEGORY_MAINTENANCE, lower_bound=floor, value=size)
            )

    uptime = _as_float(data.uptime_seconds)
    if uptime is not None:
        running = format_uptime(uptime)
        if uptime > LONG_UPTIME_SECONDS:
            found.append(_make("long_uptime", "warning", CATEGORY_MAINTENANCE, value=running))
        elif uptime > MEDIUM_UPTIME_SECONDS:
            found.append(_make("medium_uptime", "info", CATEGORY_MAINTENANCE, value=running))

    # Advice starts one entry earlier than the penalty: reviewing the list is free.
    startup_count = len(data.startup_items)
    if startup_count >= MANY_STARTUP_COUNT:
        severity = "warning" if startup_count > HEAVY_STARTUP_COUNT else "info"
        entries = format_count(startup_count)
        found.append(_make("many_startup_items", severity, CATEGORY_MAINTENANCE, value=entries))

    # Housekeeping rather than protection, which is why it sits here and not with the
    # security advice: the restart is one the user was going to do anyway.
    security = data.security
    if security is not None and security.reboot_pending is True:
        found.append(_make("reboot_pending", "info", CATEGORY_MAINTENANCE))


def _advise_power(data: AnalysisData, found: list[Recommendation]) -> None:
    battery = data.battery
    if battery is None:
        return

    # Wear is a property of the pack itself, so it is worth saying whether the PC is plugged
    # in or not - unlike the charge level below, which only matters while discharging.
    health = _as_float(battery.health_percent)
    if health is not None and health < BATTERY_WORN_PERCENT:
        severity = "warning" if health < BATTERY_WORN_WARNING_PERCENT else "info"
        found.append(
            _make("battery_worn", severity, CATEGORY_POWER, value=format_percent(health))
        )

    if battery.plugged_in is not False:
        return  # Charging or unknown power state is not a finding.
    percent = _as_float(battery.percent)
    if percent is None or percent >= BATTERY_LOW_PERCENT:
        return
    severity = "warning" if percent < BATTERY_CRITICAL_PERCENT else "info"
    found.append(_make("low_battery", severity, CATEGORY_POWER, value=format_percent(percent)))


def _advise_processes(data: AnalysisData, found: list[Recommendation]) -> None:
    ram_total = _as_float(data.ram.total_bytes)

    memory_leader = _leader(data.top_processes, lambda item: _memory_share(item, ram_total))
    if memory_leader is not None and memory_leader[1] > TOP_MEMORY_PERCENT:
        process = memory_leader[0]
        size = _as_float(process.memory_bytes)
        value = format_bytes(size) if size is not None else format_percent(memory_leader[1])
        found.append(
            _make("top_memory_process", "info", CATEGORY_MEMORY, name=process.name, value=value)
        )

    cpu_leader = _leader(data.top_processes, lambda item: _as_float(item.cpu_percent))
    if cpu_leader is not None and cpu_leader[1] > TOP_CPU_PERCENT:
        process = cpu_leader[0]
        # format_percent clamps at 100%, which is what a per-core reading above 100 should
        # read as here: "this process is busy", not an invented share of the whole CPU.
        value = format_percent(cpu_leader[1])
        found.append(_make("top_cpu_process", "info", CATEGORY_CPU, name=process.name, value=value))


def _leader(
    processes: tuple[ProcessInfo, ...], measure: Callable[[ProcessInfo], float | None]
) -> tuple[ProcessInfo, float] | None:
    """Return the highest-scoring process, breaking ties by name and pid for determinism."""
    ranked: list[tuple[ProcessInfo, float]] = []
    for process in processes:
        value = measure(process)
        if value is not None:
            ranked.append((process, value))
    if not ranked:
        return None
    # str() guards the tie-break against a collector that handed over a nameless process.
    ranked.sort(key=lambda pair: (-pair[1], str(pair[0].name or "").lower(), pair[0].pid))
    return ranked[0]


def _memory_share(process: ProcessInfo, ram_total: float | None) -> float | None:
    """Percentage of installed RAM held by a process, derived only from measured numbers."""
    share = _as_float(process.memory_percent)
    if share is not None:
        return share
    used = _as_float(process.memory_bytes)
    if used is not None and ram_total:
        return used / ram_total * 100.0
    return None


def _disk_usage_percent(disk: DiskInfo) -> float | None:
    usage = _as_float(disk.usage_percent)
    if usage is not None:
        return usage
    total = _as_float(disk.total_bytes)
    used = _as_float(disk.used_bytes)
    if total is not None and used is not None and total > 0:
        return used / total * 100.0
    return None


def _rotating_media(disk: DiskInfo) -> str | None:
    """Return the reported media type when it names a rotating disk, otherwise None."""
    media = str(disk.media_type or "").strip().upper()
    return media if media == "HDD" else None


def _drive_label(drive: str | None) -> str:
    if not drive:
        return "the system drive"
    label = str(drive).strip().rstrip("\\/")
    return label or "the system drive"


def _make(
    key: str, severity: str, category: str, *, lower_bound: bool = False, **values: str
) -> Recommendation:
    """Build one recommendation.

    ``lower_bound`` marks the quoted measurement as a floor. It is a qualifier, not a
    substitution, so it travels in the params under :data:`LOWER_BOUND_PARAM` rather than
    inside ``value``: the renderer words it in the reader's language. Only ``text`` - the
    fallback a consumer without a translator prints - spells it out in English.

    The settings page, if this advice has one, comes from :data:`RECOMMENDATION_ACTIONS`, so
    every producer attaches the same page to the same key and none can invent its own.
    """
    template = RECOMMENDATION_TEMPLATES.get(key, key)
    text_values = dict(values)
    if lower_bound and "value" in text_values:
        text_values["value"] = english_lower_bound(text_values["value"])
    params = _params_for(template, values)
    if lower_bound:
        params = (*params, LOWER_BOUND_PARAM)
    return Recommendation(
        key=key,
        text=_safe_format(template, text_values),
        severity=severity,
        category=category,
        params=params,
        action_uri=RECOMMENDATION_ACTIONS.get(key),
    )


def _params_for(template: str, values: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Carry exactly the placeholders the sentence uses, so text and params cannot drift."""
    names: list[str] = []
    try:
        for _, field, _, _ in Formatter().parse(template):
            if field and field in values and field not in names:
                names.append(field)
    except (ValueError, AttributeError):
        return ()
    return tuple((name, values[name]) for name in names)


def _safe_format(template: str, values: dict[str, str]) -> str:
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError):
        return template


def _as_float(value: object) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    # NaN and infinity are not measurements; advising on them would mean inventing one.
    return number if math.isfinite(number) else None
