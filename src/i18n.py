"""Bilingual user-facing strings for the report, the exporters, the CLI, and the GUI.

Rendering modules never hardcode a finished sentence. They ask for a key and pass an English
default, so a missing translation degrades to English instead of breaking a report.

Placeholders use ``str.format`` syntax. A value that was not supplied never raises: an optional
``(...)`` segment wrapped around it is dropped, and any placeholder left over becomes "N/A".
Deduction and recommendation texts depend on that, because a collector cannot always measure
the number the sentence would like to quote.

A phrase that quotes a count is stored once per grammatical number - ``<key>.one``,
``<key>.few`` and ``<key>.many`` - and asked for through :meth:`Translator.t_plural`, because
Slovak declines 1, 2-4 and 5+ differently and "3 bodov" is simply wrong.

The file is UTF-8; the Slovak table uses full diacritics.
"""

from __future__ import annotations

import locale
import os
import re
import warnings
from typing import Mapping

#: Language codes this build ships. The first entry is the fallback.
LANGUAGES: tuple[str, ...] = ("en", "sk")

DEFAULT_LANGUAGE = "en"

#: Environment override checked before the operating-system locale.
LANGUAGE_ENV = "APOLIAK_LANG"

#: Rendered in place of a placeholder no caller supplied a value for.
UNKNOWN_VALUE = "N/A"

#: Grammatical numbers a count-dependent phrase can ask for. A catalogue stores them as
#: ``<base key>.one``, ``<base key>.few`` and ``<base key>.many``. English only distinguishes
#: one from the rest and repeats its plural in "few"; Slovak needs all three.
PLURAL_FORMS: tuple[str, ...] = ("one", "few", "many")

# A control character can never appear in a translation, which makes it a safe marker for
# "this placeholder had no value" that survives str.format.
_MISSING = "\x00"
_OPTIONAL_SEGMENT = re.compile(r"\s*[(\[][^()\[\]]*\x00[^()\[\]]*[)\]]")
_REPEATED_SPACES = re.compile(r"[ \t]{2,}")


_EN: dict[str, str] = {
    # -- health status ------------------------------------------------------------------
    "status.excellent": "Excellent",
    "status.good": "Good",
    "status.needs_optimization": "Needs Optimization",
    "status.poor": "Poor",
    # -- severity -----------------------------------------------------------------------
    "severity.info": "Info",
    "severity.warning": "Warning",
    "severity.critical": "Critical",
    # -- categories ---------------------------------------------------------------------
    "category.cpu": "CPU",
    "category.memory": "Memory",
    "category.storage": "Storage",
    "category.maintenance": "Maintenance",
    "category.power": "Power",
    "category.security": "Security",
    "category.general": "General",
    # -- score deductions ---------------------------------------------------------------
    "deduction.high_cpu": "CPU usage is high ({value}).",
    "deduction.high_ram": "RAM usage is high ({value}).",
    "deduction.high_swap": "The Windows page file is heavily used ({value}).",
    # The drive is quoted in its own optional parenthesis: the producer always names the
    # analysed drive, but a snapshot that does not still has to read as a sentence.
    "deduction.low_disk": "Free space on the drive ({drive}) is low ({value}).",
    "deduction.disk_nearly_full": "The drive ({drive}) is nearly full ({value}).",
    "deduction.many_processes": "A large number of processes is running ({value}).",
    "deduction.large_temp": "The TEMP folder holds a lot of data ({value}).",
    "deduction.long_uptime": "The PC has been running without a restart for a long time ({value}).",
    "deduction.many_startup_items": "Many apps start together with Windows ({value}).",
    "deduction.low_battery": "The battery charge is low ({value}).",
    # State rather than load: what is durably wrong with this PC, not how busy it is.
    # Every one of these is worded as a fact. An unreadable setting is "unknown" and never
    # reaches a deduction at all, so a sentence here always describes something measured.
    "deduction.antivirus_off": "Antivirus protection is not active.",
    "deduction.firewall_off": "The Windows firewall is not active.",
    # No number: the age is quoted in the SECURITY section, where the renderer can decline
    # the noun ("1 day", "3 dni", "12 dní"). A deduction is rendered through plain t().
    "deduction.stale_signatures": "Antivirus definitions are not up to date.",
    "deduction.reboot_pending": "Windows is waiting for a restart to finish an update.",
    "deduction.drive_failing": "The drive ({drive}) reports a critical health warning.",
    "deduction.drive_worn": "The drive ({drive}) is wearing out ({value} of its rated life left).",
    "deduction.battery_worn": "The battery is worn ({value} of its original capacity).",
    # -- recommendations ----------------------------------------------------------------
    "recommendation.high_cpu": (
        "CPU usage is high ({value}). Let running tasks finish, or review CPU-heavy apps "
        "in Task Manager."
    ),
    # The mild tier of every rule that deducts points needs advice of its own: a report that
    # takes points away and then says nothing leaves the reader with no move to make.
    "recommendation.medium_cpu": (
        "CPU usage is elevated ({value}). Let running tasks finish, and check Task Manager "
        "if the PC feels slow."
    ),
    "recommendation.high_ram": (
        "RAM usage is high ({value}). Close background apps and browser tabs you do not need."
    ),
    "recommendation.medium_ram": (
        "RAM usage is elevated ({value}). Closing a few background apps or browser tabs "
        "frees memory."
    ),
    "recommendation.high_swap": (
        "Windows is leaning on the page file ({value}). Closing memory-heavy apps helps more "
        "than any setting."
    ),
    "recommendation.medium_swap": (
        "Windows is using the page file ({value}). Closing memory-heavy apps keeps more work "
        "in RAM, which is faster than the drive."
    ),
    "recommendation.low_disk": (
        "Free space on the drive ({drive}) is low ({value}). Move large files to another "
        "drive or review Windows Storage settings."
    ),
    "recommendation.medium_disk": (
        "Free space on the drive ({drive}) is getting smaller ({value}). Windows Storage "
        "settings shows what is using it."
    ),
    "recommendation.disk_nearly_full": (
        "The drive ({drive}) is nearly full ({value}). Windows needs free space for updates "
        "and for the page file."
    ),
    "recommendation.medium_disk_full": (
        "The drive ({drive}) is filling up ({value}). There is still room, and Windows "
        "Storage settings shows what is taking the most of it."
    ),
    "recommendation.many_processes": (
        "{value} processes are running. Review which apps start automatically."
    ),
    "recommendation.some_processes": (
        "{value} processes are running. Check your startup apps if the PC feels slow."
    ),
    "recommendation.large_temp": (
        "Temporary files take up {value}. Windows Storage settings can review and remove them "
        "safely."
    ),
    "recommendation.medium_temp": (
        "Temporary files take up {value}. Clearing them in Windows Storage settings reclaims "
        "some space."
    ),
    "recommendation.long_uptime": (
        "The PC has been running for {value}. A restart often restores both stability and speed."
    ),
    "recommendation.medium_uptime": (
        "The PC has been running for {value}. Consider restarting before demanding work."
    ),
    "recommendation.many_startup_items": (
        "{value} apps start together with Windows. Disable the ones you do not need in "
        "Task Manager, on the Startup tab."
    ),
    "recommendation.low_battery": (
        "The battery is at {value}. Connect the charger before longer work."
    ),
    "recommendation.top_memory_process": (
        "{name} uses the most memory right now ({value}). Close it if you are not using it."
    ),
    "recommendation.top_cpu_process": (
        "{name} uses the most CPU right now ({value}). Check whether that load is expected."
    ),
    "recommendation.hdd_system_drive": (
        "The analysed drive ({drive}) is a rotating hard disk (HDD). Replacing it with an SSD "
        "is usually the single biggest real-world speed upgrade for a PC like this."
    ),
    # Advice about durable state. It stays calm on purpose: "real-time protection is off" is
    # a fact the reader can act on, "your PC is in danger" is a scare that helps nobody.
    "recommendation.antivirus_off": (
        "Antivirus protection is not active. Windows Security shows what is guarding this PC "
        "and can switch the protection back on."
    ),
    "recommendation.firewall_off": (
        "The Windows firewall is not active. Windows Security can switch it back on for the "
        "network profile you are using."
    ),
    "recommendation.stale_signatures": (
        "Antivirus definitions are not up to date. Windows Security refreshes them by itself "
        "once the PC is online, and you can start the update there too."
    ),
    "recommendation.reboot_pending": (
        "Windows is waiting for a restart to finish an update. Restarting at a time that "
        "suits you completes it."
    ),
    # Advice only - there is deliberately no deduction for this. Secure Boot is off for many
    # legitimate reasons, and taking points away for a dual-boot machine would be dishonest.
    "recommendation.secure_boot_off": (
        "Secure Boot is off. A dual-boot setup or older firmware is a normal reason for that, "
        "so this is information rather than a fault, and no points are deducted for it."
    ),
    "recommendation.drive_failing": (
        "The drive ({drive}) reports a critical health warning. Back up what matters to you "
        "now and have the drive checked."
    ),
    "recommendation.drive_worn": (
        "The drive ({drive}) is wearing out ({value} of its rated life left). It still works, "
        "so plan the replacement calmly instead of waiting for a failure."
    ),
    "recommendation.battery_worn": (
        "The battery is worn ({value} of its original capacity). Expect shorter runtime away "
        "from the charger; wear like this is normal ageing, not a fault."
    ),
    "recommendation.large_folder": (
        "{name} takes up the most space of the folders measured ({value}). Windows Storage "
        "settings show what is inside before you remove anything."
    ),
    "recommendation.incomplete_data": (
        "Some metrics could not be read. Review the analysis warnings before trusting the score."
    ),
    "recommendation.all_good": (
        "No urgent issues were detected. Keep Windows and your apps up to date."
    ),
    # -- report frame -------------------------------------------------------------------
    "report.title": "Apoliak Vitals",
    "report.subtitle": "PC health report",
    "report.analysis_date": "Analysis Date",
    "report.mode": "Mode",
    "report.mode_readonly": "Read-only analysis (no settings or files changed)",
    "report.duration": "Analysis Duration",
    "report.score": "Score",
    "report.status": "Status",
    "report.score_value": "{score}/100",
    # Kept for callers that predate the plural forms below; new code uses t_plural().
    "report.points": "points",
    "report.points.one": "point",
    "report.points.few": "points",
    "report.points.many": "points",
    "report.deductions": "Score deductions:",
    "report.no_deductions": "No deductions were applied.",
    "report.categories": "Category scores:",
    "report.unavailable": "not measured",
    "report.partial_scan": "partial scan",
    "report.system_drive": "system",
    "report.none_detected": "None detected.",
    # A measurement a rule could only bound from below. The qualifier is worded here rather
    # than baked into the number by its producer, so a Slovak report does not read
    # "aspoň" in English.
    "report.at_least": "at least {value}",
    "report.temp_truncated": (
        "The TEMP scan ran out of time, so this size is a lower bound, not a measurement."
    ),
    "report.and_more": "... and {count} more",
    "report.and_more.one": "... and {count} more item",
    "report.and_more.few": "... and {count} more items",
    "report.and_more.many": "... and {count} more items",
    # Two counted nouns the state sections quote: the age of the antivirus definitions and
    # the hours a drive has been powered on. Both decline in Slovak, so both are asked for
    # through t_plural() instead of being pasted next to a bare number.
    "report.days.one": "{count} day",
    "report.days.few": "{count} days",
    "report.days.many": "{count} days",
    "report.hours.one": "{count} hour",
    "report.hours.few": "{count} hours",
    "report.hours.many": "{count} hours",
    # Says why a protection verdict is N/A. Without it a reader cannot tell "nobody asked"
    # from "the answer was no", and this analyser never lets an unknown look like a fault.
    "report.security_center_down": (
        "The Windows Security Center did not answer, so the antivirus and firewall states are "
        "unknown rather than off."
    ),
    # Each count carries its own noun form, because Slovak declines 1, 2-4 and 5+ differently
    # and the two numbers can land in different groups ("2 fyzické / 8 logických").
    "report.cores_value": "{physical} / {logical}",
    "report.cores_physical.one": "{count} physical",
    "report.cores_physical.few": "{count} physical",
    "report.cores_physical.many": "{count} physical",
    "report.cores_logical.one": "{count} logical",
    "report.cores_logical.few": "{count} logical",
    "report.cores_logical.many": "{count} logical",
    "report.frequency_value": "{current} (max. {maximum})",
    "report.per_core_value": "min {min} / avg {avg} / max {max}",
    "report.swap_value": "{used} of {total} ({percent})",
    "report.interface_value": "{name}: {state}",
    "report.driver_value": "{version} ({date})",
    "report.footer": (
        "This report is informational. Apoliak Vitals did not modify your PC."
    ),
    "report.generated_by": "Generated by {name} {version}",
    "report.section_failed": "This section could not be rendered ({error}).",
    # -- section headings ---------------------------------------------------------------
    "section.system": "SYSTEM",
    "section.cpu": "CPU",
    "section.ram": "RAM",
    "section.disk": "DISK",
    "section.partitions": "PARTITIONS",
    "section.processes": "PROCESSES",
    "section.top_processes": "TOP PROCESSES",
    "section.temp": "TEMP FILES",
    "section.folders": "BIGGEST FOLDERS",
    "section.drive_health": "DRIVE HEALTH",
    "section.security": "SECURITY",
    "section.uptime": "UPTIME",
    "section.battery": "BATTERY",
    "section.network": "NETWORK",
    "section.gpu": "GRAPHICS",
    "section.startup": "STARTUP ITEMS",
    "section.score": "PC HEALTH SCORE",
    "section.recommendations": "RECOMMENDATIONS",
    "section.warnings": "ANALYSIS WARNINGS",
    # -- field labels -------------------------------------------------------------------
    "field.os": "System",
    "field.release": "Release",
    "field.version": "Version",
    "field.display_version": "Windows Version",
    "field.build": "Build",
    "field.edition": "Edition",
    "field.architecture": "Architecture",
    "field.processor": "Processor",
    "field.manufacturer": "Manufacturer",
    "field.model": "Model",
    "field.bios": "BIOS Version",
    "field.install_date": "Windows Installed",
    "field.boot_time": "Last Boot",
    "field.cores": "CPU Cores",
    "field.physical_cores": "Physical Cores",
    "field.logical_cores": "Logical Cores",
    "field.usage": "Usage",
    "field.cpu_usage": "CPU Usage",
    "field.ram_usage": "RAM Usage",
    "field.disk_usage": "Disk Usage",
    "field.frequency": "CPU Frequency",
    "field.max_frequency": "Max Frequency",
    "field.per_core": "Per-core Usage",
    "field.installed": "Installed RAM",
    "field.ram_total": "Total RAM",
    "field.ram_available": "Available RAM",
    "field.ram_used": "Used RAM",
    "field.disk_total": "Total Disk",
    "field.disk_used": "Used Disk",
    "field.disk_free": "Free Disk",
    "field.total": "Total",
    "field.used": "Used",
    "field.available": "Available",
    "field.free": "Free",
    "field.swap": "Page File",
    "field.drive": "Drive",
    "field.filesystem": "File System",
    "field.media_type": "Media Type",
    "field.processes": "Running Processes",
    "field.uptime": "System Uptime",
    "field.data_complete": "Data Complete",
    "field.folder_size": "Folder Size",
    "field.path": "Path",
    "field.files": "Files",
    "field.folder": "Folder",
    "field.battery": "Battery",
    "field.plugged_in": "Plugged In",
    "field.time_left": "Time Left",
    # -- battery wear ---------------------------------------------------------------------
    "field.battery_health": "Battery Health",
    "field.design_capacity": "Design Capacity",
    "field.full_charge_capacity": "Full Charge Capacity",
    "field.cycle_count": "Charge Cycles",
    "field.chemistry": "Cell Chemistry",
    # -- drive wear -----------------------------------------------------------------------
    "field.bus_type": "Bus",
    "field.life_left": "Life Left",
    "field.temperature": "Temperature",
    "field.power_on_hours": "Power-on Hours",
    "field.data_written": "Data Written",
    "field.critical_warning": "Critical Warning",
    # -- protection state -----------------------------------------------------------------
    "field.antivirus": "Antivirus",
    "field.firewall": "Firewall",
    "field.secure_boot": "Secure Boot",
    "field.reboot_pending": "Restart Pending",
    "field.signature_age": "Definitions Age",
    "field.last_scan": "Last Scan",
    # One label per STATE_* verdict. "Unknown" is its own word on purpose: a setting nobody
    # could read must never be shown as "Off", which would be an invented measurement.
    "field.state_good": "On",
    "field.state_weak": "Needs attention",
    "field.state_bad": "Off",
    "field.state_unknown": "Unknown",
    "field.sent": "Sent",
    "field.received": "Received",
    "field.interfaces": "Interfaces",
    "field.startup_items": "Startup Items",
    "field.driver": "Driver",
    "field.gpu_memory": "Graphics Memory",
    "field.yes": "Yes",
    "field.no": "No",
    "field.name": "Name",
    "field.value": "Value",
    "field.pid": "PID",
    "field.memory": "Memory",
    "field.memory_percent": "Memory %",
    "field.cpu_percent": "CPU %",
    "field.source": "Source",
    "field.label": "Location",
    "field.up": "up",
    "field.down": "down",
    "field.score": "Score",
    "field.status": "Status",
    "field.severity": "Severity",
    "field.category": "Category",
    "field.reason": "Reason",
    "field.points": "Points",
    "field.temp_path": "TEMP Folder",
    "field.temp_size": "TEMP Folder Size",
    "field.duration": "Duration",
    # -- console interface --------------------------------------------------------------
    "cli.description": (
        "Safely analyze Windows PC health without changing any system setting."
    ),
    "cli.epilog": (
        "Exit codes: 0 success, 1 runtime failure, 2 invalid arguments, 3 score below "
        "--fail-under. The analyzer only reads. It never deletes, repairs, or reconfigures."
    ),
    "cli.group.analysis": "analysis",
    "cli.group.output": "output",
    "cli.group.history": "history (opt-in, stored locally)",
    "cli.help.export": (
        "export the result; without a path an auto-named file lands in this folder"
    ),
    "cli.help.format": (
        "export format: text, json, html or markdown (default: text, or taken from the "
        "export file extension)"
    ),
    "cli.help.output": "explicit export destination; implies --export and wins over it",
    "cli.help.no_prompt": "never ask anything interactively",
    "cli.help.cpu_seconds": "CPU measurement interval from 0 to 5 seconds (default: 1)",
    "cli.help.language": (
        "report language: en or sk (default: from APOLIAK_LANG or the system locale)"
    ),
    "cli.help.redact": "mask the Windows account name everywhere in the output",
    "cli.help.color": (
        "terminal colour: auto, always or never; it never reaches an exported file "
        "(default: auto)"
    ),
    "cli.help.quiet": "print only the score line",
    "cli.help.no_temp_scan": "skip the TEMP folder measurement entirely",
    # The default is passed in, so the number cannot drift away from DEFAULT_SCAN_SECONDS.
    # It is not called {default}: that name is already the second argument of Translator.t().
    "cli.help.temp_seconds": "time budget for the TEMP folder scan in seconds (default: {seconds})",
    "cli.help.top": "how many top processes to collect, 0 disables the list (default: 5)",
    "cli.help.history": "append this run to the local history file",
    "cli.help.history_path": "custom history file (default: the local application-data folder)",
    "cli.help.show_history": "print the last N stored runs and exit (default: 10, 0 shows all)",
    "cli.help.compare": "show the change against the previous stored run",
    "cli.help.fail_under": "exit with code 3 when the health score is below N (0-100)",
    "cli.help.no_startup": "skip reading the startup-item list",
    "cli.help.no_gpu": "skip reading graphics-adapter information",
    "cli.help.version": "show the program version and exit",
    # argparse writes this line itself in English; the parser replaces -h so that --help
    # describes itself in the chosen language like every other option does.
    "cli.help.help": "show this help message and exit",
    "cli.prompt.export": "Export this report? [y/N]: ",
    "cli.msg.progress": "{message}",
    "cli.msg.score_line": "Score: {score}/100 ({status})",
    "cli.msg.saved": "Report saved to: {path}",
    "cli.msg.export_failed": "Could not export the report: {error}",
    "cli.msg.analysis_failed": "Analysis failed safely: {error}",
    "cli.msg.missing_dependency": "Error: {error}",
    "cli.msg.invalid_interval": "Error: --cpu-sample-seconds must be between 0 and 5.",
    "cli.msg.invalid_top": "Error: --top must be 0 or a whole number.",
    "cli.msg.invalid_temp_seconds": "Error: --temp-scan-seconds must be 0 or greater.",
    "cli.msg.invalid_threshold": "Error: --fail-under must be between 0 and 100.",
    "cli.msg.invalid_color": "Error: --color must be one of: {values}.",
    "cli.msg.invalid_format": "Error: unknown export format '{value}'.",
    "cli.msg.cancelled": "Cancelled.",
    "cli.msg.below_threshold": "Score {score} is below the required minimum {threshold}.",
    "cli.msg.history_saved": "History updated: {path}",
    "cli.msg.history_failed": "Could not update the history file: {error}",
    "cli.msg.history_file": "History file: {path}",
    "cli.msg.no_history": "No previous analysis is stored yet.",
    "cli.msg.compare_header": "Compared with the previous analysis ({when}):",
    "cli.msg.compare_score": "Score: {value}",
    "cli.msg.compare_cpu": "CPU usage: {value}",
    "cli.msg.compare_ram": "RAM usage: {value}",
    "cli.msg.compare_disk": "Free disk space: {value}",
    # Column headings of the --show-history table. One key per column, because the table is
    # laid out by padding each cell to the width of its own heading.
    "cli.history.column.date": "Analysis Date",
    "cli.history.column.score": "Score",
    "cli.history.column.status": "Status",
    "cli.history.column.cpu": "CPU",
    "cli.history.column.ram": "RAM",
    "cli.history.column.free_disk": "Free disk",
    # -- analysis progress steps ----------------------------------------------------------
    # One key per step the analyzer announces. The analyzer itself hands its callers a step
    # key plus an English label, so the console and the window can both say the step in the
    # chosen language instead of forwarding the literal the collector happened to carry.
    "progress.system": "Reading system information",
    "progress.cpu": "Measuring CPU usage",
    "progress.ram": "Reading memory usage",
    "progress.disk": "Reading drives",
    "progress.partitions": "Reading partitions",
    "progress.processes": "Counting processes",
    "progress.top_processes": "Ranking processes",
    "progress.temp": "Measuring temporary files",
    "progress.folders": "Measuring the biggest folders",
    "progress.drive_health": "Reading drive health",
    "progress.security": "Reading protection settings",
    "progress.extras": "Reading hardware details",
    "progress.done": "Analysis complete",
    # -- graphical interface ------------------------------------------------------------
    "gui.title": "Apoliak Vitals",
    "gui.window_title": "Apoliak Vitals",
    "gui.subtitle": "Read-only Windows health check",
    "gui.version": "Version {version}",
    # The sidebar wordmark is a brand asset, so it reads identically in every language.
    "gui.brand.name": "APOLIAK",
    "gui.brand.tagline": "VITALS",
    "gui.sidebar.analysis": "ANALYSIS",
    "gui.sidebar.export": "EXPORT",
    "gui.nav.overview": "Overview",
    "gui.nav.processes": "Processes",
    "gui.nav.storage": "Storage",
    "gui.nav.security": "Security",
    "gui.nav.system": "System",
    "gui.nav.history": "History",
    "gui.nav.settings": "Settings",
    "gui.button.analyze": "Analyze my PC",
    "gui.button.analyzing": "Analyzing...",
    "gui.button.again": "Analyze again",
    "gui.button.export": "Export report",
    "gui.button.copy": "Copy to clipboard",
    "gui.button.copied": "Copied",
    # Opens a Windows settings page on a deliberate click. Read-only stays read-only: showing
    # a settings page changes nothing, and nothing here is ever launched by the analysis.
    "gui.button.open_setting": "Open setting",
    "gui.state.ready": "Ready",
    "gui.state.running": "Analysis in progress...",
    "gui.state.complete": "Analysis complete",
    "gui.state.failed": "Analysis failed",
    "gui.progress.starting": "Starting analysis...",
    "gui.status.duration": "took {duration}",
    # Kept for callers that predate the plural forms below; new code uses t_plural().
    "gui.status.warnings": "{count} warning(s)",
    "gui.status.warnings.one": "{count} warning",
    "gui.status.warnings.few": "{count} warnings",
    "gui.status.warnings.many": "{count} warnings",
    # -- export formats -----------------------------------------------------------------
    "gui.format.text": "Text (.txt)",
    "gui.format.json": "JSON (.json)",
    "gui.format.html": "HTML (.html)",
    "gui.format.markdown": "Markdown (.md)",
    "gui.filetype.text": "Text report",
    "gui.filetype.json": "JSON data",
    "gui.filetype.html": "HTML report",
    "gui.filetype.markdown": "Markdown report",
    "gui.filetype.all": "All files",
    "gui.card.system": "System",
    "gui.card.cpu": "Processor",
    "gui.card.ram": "Memory",
    "gui.card.disk": "System Drive",
    "gui.card.activity": "Activity",
    "gui.card.temp": "Temporary Files",
    # No "gui.card.folders" / "gui.card.drive_health": neither is a metric card. Both live in
    # the Storage view and in the exports as sections, under "gui.section.*" below.
    "gui.card.security": "Security",
    "gui.card.battery": "Battery",
    "gui.card.network": "Network",
    "gui.card.gpu": "Graphics",
    "gui.section.folders": "Biggest folders",
    "gui.section.drive_health": "Drive health",
    "gui.section.history_chart": "Score over time",
    "gui.section.recommendations": "Recommendations",
    "gui.section.deductions": "Score deductions",
    "gui.section.processes": "Top processes",
    "gui.section.categories": "Category scores",
    "gui.section.warnings": "Analysis warnings",
    "gui.section.partitions": "Partitions",
    "gui.section.overview": "Overview",
    "gui.deductions.points": "-{points} pts",
    "gui.processes.subtitle": (
        "Sorted by memory use. This list is read-only - nothing is ever terminated."
    ),
    "gui.storage.title": "Drives and partitions",
    "gui.storage.usage": "{used} of {total} used, {free} free",
    "gui.system.title": "Operating system",
    "gui.system.firmware": "Firmware",
    "gui.system.gpus": "Graphics adapters",
    "gui.system.no_gpus": "No graphics adapters were reported.",
    "gui.system.no_startup": "No startup items were found.",
    "gui.system.no_warnings": "No warnings. Every metric was collected.",
    "gui.field.charge": "Charge",
    "gui.field.locations": "Locations",
    "gui.field.files_changed": "Files changed",
    "gui.field.adapters": "Adapters",
    "gui.value.plugged": "Plugged in",
    "gui.value.on_battery": "On battery",
    "gui.value.system_drive": "System drive",
    "gui.label.not_analyzed": "Not analyzed yet",
    "gui.label.last_analyzed": "Last analysis: {value}",
    "gui.label.readonly_title": "Read-only mode",
    "gui.label.readonly_body": (
        "This app only reads system information. It never deletes files, edits the registry, "
        "stops services, or changes Windows settings."
    ),
    "gui.label.language": "Language",
    "gui.label.redact": "Redact personal data",
    "gui.label.redact_hint": (
        "Replaces your Windows account name with <user> in exported and copied reports, so "
        "they are safe to share."
    ),
    "gui.label.theme": "Theme",
    "gui.label.placeholder": "--",
    "gui.label.score_hint": "100 points minus every issue listed below.",
    "gui.label.score": "Health score",
    "gui.label.no_data": "No data yet",
    "gui.label.history_empty": "Save a few analyses and the trend shows up here.",
    # Sits next to the button above, so a reader knows what the click does before making it.
    "gui.label.action_hint": (
        "Opens the matching Windows settings page. Nothing is changed for you."
    ),
    "gui.label.history_hint": "History is optional and stored only on this PC.",
    "gui.health.of100": "/ 100",
    "gui.theme.dark": "Dark",
    "gui.theme.light": "Light",
    # -- opt-in local history -----------------------------------------------------------
    "gui.history.title": "Local history",
    "gui.history.optin": "Save this analysis locally",
    "gui.history.explain": "While the box above is unchecked, nothing is written to disk.",
    "gui.history.location": "Storage location",
    "gui.history.refresh": "Refresh list",
    "gui.history.score": "Score {score}",
    "gui.history.first": "First saved run",
    "gui.history.delta": "{delta} vs previous",
    "gui.history.saved": "Saved to {path}",
    "gui.history.failed": "This run could not be saved: {error}",
    "gui.history.unavailable": "The history module is not available in this installation.",
    "gui.dialog.export_title": "Save the report",
    "gui.dialog.exported": "Report exported",
    "gui.dialog.export_failed": "Export failed",
    "gui.dialog.format_unavailable": (
        "This export format is not available in this installation."
    ),
    "gui.dialog.copy_failed": "Copy failed",
    "gui.msg.export_ok": "Report saved to {path}",
    "gui.msg.export_failed": "The report could not be saved: {error}",
    "gui.msg.copied": "The report was copied to the clipboard.",
    "gui.msg.setting_opened": "Windows opened the settings page. Nothing was changed.",
    "gui.msg.setting_failed": "The settings page could not be opened: {error}",
    "gui.msg.redact_unavailable": (
        "This installation cannot mask personal data. Untick '{label}' to continue."
    ),
    "gui.msg.analysis_failed": "The analysis could not finish: {error}",
    "gui.msg.no_recommendations": "No recommendations for this snapshot.",
    "gui.msg.no_deductions": "No points were deducted.",
    "gui.msg.no_processes": "No process information is available.",
    "gui.msg.no_history": "No previous analysis is stored yet.",
}


_SK: dict[str, str] = {
    # -- health status ------------------------------------------------------------------
    "status.excellent": "Výborný",
    "status.good": "Dobrý",
    "status.needs_optimization": "Potrebuje optimalizáciu",
    "status.poor": "Slabý",
    # -- severity -----------------------------------------------------------------------
    "severity.info": "Informácia",
    "severity.warning": "Upozornenie",
    "severity.critical": "Kritické",
    # -- categories ---------------------------------------------------------------------
    "category.cpu": "Procesor",
    "category.memory": "Pamäť",
    "category.storage": "Úložisko",
    "category.maintenance": "Údržba",
    "category.power": "Napájanie",
    "category.security": "Zabezpečenie",
    "category.general": "Všeobecné",
    # -- score deductions ---------------------------------------------------------------
    "deduction.high_cpu": "Vyťaženie procesora je vysoké ({value}).",
    "deduction.high_ram": "Vyťaženie pamäte RAM je vysoké ({value}).",
    "deduction.high_swap": "Stránkovací súbor Windowsu je výrazne využívaný ({value}).",
    # "Na disku" stays in the locative whether or not the parenthesis with the drive letter
    # survives, so an unnamed drive still leaves a grammatical Slovak sentence behind.
    "deduction.low_disk": "Na disku ({drive}) je málo voľného miesta ({value}).",
    "deduction.disk_nearly_full": "Disk ({drive}) je takmer plný ({value}).",
    "deduction.many_processes": "Beží veľké množstvo procesov ({value}).",
    "deduction.large_temp": "Priečinok TEMP obsahuje veľa údajov ({value}).",
    "deduction.long_uptime": "Počítač beží veľmi dlho bez reštartu ({value}).",
    "deduction.many_startup_items": "Spolu s Windowsom sa spúšťa veľa aplikácií ({value}).",
    "deduction.low_battery": "Batéria je málo nabitá ({value}).",
    # Stav namiesto zaťaženia. Vecné konštatovanie: nečitateľné nastavenie je "neznáme"
    # a k zrážke sa nikdy nedostane, takže každá veta tu popisuje niečo naozaj namerané.
    "deduction.antivirus_off": "Antivírusová ochrana nie je aktívna.",
    "deduction.firewall_off": "Brána firewall Windowsu nie je aktívna.",
    # Bez čísla: vek definícií uvádza časť ZABEZPEČENIE, kde ho vie renderer správne
    # vyskloňovať ("1 deň", "3 dni", "12 dní"). Zrážka sa vykresľuje cez obyčajné t().
    "deduction.stale_signatures": "Definície antivírusu nie sú aktuálne.",
    "deduction.reboot_pending": "Windows čaká na reštart, aby dokončil aktualizáciu.",
    "deduction.drive_failing": "Disk ({drive}) hlási kritické varovanie o svojom stave.",
    "deduction.drive_worn": "Disk ({drive}) sa opotrebúva (zostáva {value} jeho životnosti).",
    "deduction.battery_worn": "Batéria je opotrebovaná ({value} pôvodnej kapacity).",
    # -- recommendations ----------------------------------------------------------------
    "recommendation.high_cpu": (
        "Vyťaženie procesora je vysoké ({value}). Nechajte bežiace úlohy dokončiť alebo si "
        "v Správcovi úloh pozrite najnáročnejšie aplikácie."
    ),
    "recommendation.medium_cpu": (
        "Vyťaženie procesora je zvýšené ({value}). Nechajte bežiace úlohy dokončiť a ak je "
        "počítač pomalý, pozrite si Správcu úloh."
    ),
    "recommendation.high_ram": (
        "Vyťaženie pamäte RAM je vysoké ({value}). Zatvorte aplikácie a karty prehliadača, "
        "ktoré práve nepotrebujete."
    ),
    "recommendation.medium_ram": (
        "Vyťaženie pamäte RAM je zvýšené ({value}). Zatvorením niekoľkých aplikácií "
        "v pozadí alebo kariet prehliadača uvoľníte pamäť."
    ),
    "recommendation.high_swap": (
        "Windows sa výrazne opiera o stránkovací súbor ({value}). Viac než akékoľvek "
        "nastavenie pomôže zatvorenie pamäťovo náročných aplikácií."
    ),
    "recommendation.medium_swap": (
        "Windows využíva stránkovací súbor ({value}). Zatvorením pamäťovo náročných "
        "aplikácií udržíte viac práce v pamäti RAM, ktorá je rýchlejšia než disk."
    ),
    "recommendation.low_disk": (
        "Na disku ({drive}) je málo voľného miesta ({value}). Presuňte veľké súbory na iný "
        "disk alebo si prezrite nastavenia Úložiska vo Windowse."
    ),
    "recommendation.medium_disk": (
        "Voľného miesta na disku ({drive}) ubúda ({value}). V nastaveniach Úložiska vo "
        "Windowse uvidíte, čo ho zaberá."
    ),
    "recommendation.disk_nearly_full": (
        "Disk ({drive}) je takmer plný ({value}). Windows potrebuje voľné miesto na "
        "aktualizácie aj na stránkovací súbor."
    ),
    "recommendation.medium_disk_full": (
        "Disk ({drive}) sa zapĺňa ({value}). Miesto ešte je a v nastaveniach Úložiska vo "
        "Windowse uvidíte, čo ho zaberá najviac."
    ),
    "recommendation.many_processes": (
        "Beží {value} procesov. Skontrolujte, ktoré aplikácie sa spúšťajú automaticky."
    ),
    "recommendation.some_processes": (
        "Beží {value} procesov. Ak je počítač pomalý, prezrite si aplikácie po štarte."
    ),
    "recommendation.large_temp": (
        "Dočasné súbory zaberajú {value}. Bezpečne ich skontrolujete a odstránite "
        "v nastaveniach Úložiska vo Windowse."
    ),
    "recommendation.medium_temp": (
        "Dočasné súbory zaberajú {value}. Ich vyčistením v nastaveniach Úložiska získate "
        "späť časť miesta."
    ),
    "recommendation.long_uptime": (
        "Počítač beží už {value}. Reštart často vráti stabilitu aj rýchlosť."
    ),
    "recommendation.medium_uptime": (
        "Počítač beží už {value}. Pred náročnou prácou zvážte reštart."
    ),
    "recommendation.many_startup_items": (
        "Spolu s Windowsom sa spúšťa {value} aplikácií. Nepotrebné vypnite v Správcovi úloh "
        "na karte Po spustení."
    ),
    "recommendation.low_battery": (
        "Batéria je na {value}. Pred dlhšou prácou pripojte nabíjačku."
    ),
    "recommendation.top_memory_process": (
        "Najviac pamäte práve využíva {name} ({value}). Ak ho nepoužívate, zatvorte ho."
    ),
    "recommendation.top_cpu_process": (
        "Najviac procesora práve využíva {name} ({value}). Overte, či je také zaťaženie "
        "očakávané."
    ),
    "recommendation.hdd_system_drive": (
        "Analyzovaný disk ({drive}) je klasický rotačný pevný disk (HDD). Jeho výmena za SSD "
        "býva pre takýto počítač najväčšie reálne zrýchlenie."
    ),
    # Rady k trvalému stavu. Zámerne pokojné: "ochrana v reálnom čase je vypnutá" je fakt,
    # s ktorým sa dá niečo urobiť; "váš počítač je v nebezpečenstve" je strašenie bez úžitku.
    "recommendation.antivirus_off": (
        "Antivírusová ochrana nie je aktívna. V Zabezpečení Windows vidíte, čo tento počítač "
        "chráni, a ochranu tam môžete znova zapnúť."
    ),
    "recommendation.firewall_off": (
        "Brána firewall Windowsu nie je aktívna. V Zabezpečení Windows ju môžete znova zapnúť "
        "pre sieťový profil, ktorý používate."
    ),
    "recommendation.stale_signatures": (
        "Definície antivírusu nie sú aktuálne. Zabezpečenie Windows ich obnoví samo, hneď ako "
        "je počítač online, a aktualizáciu tam môžete spustiť aj sami."
    ),
    "recommendation.reboot_pending": (
        "Windows čaká na reštart, aby dokončil aktualizáciu. Dokončí ju hneď, ako počítač "
        "reštartujete v čase, ktorý vám vyhovuje."
    ),
    # Len rada - zrážka za toto zámerne neexistuje. Secure Boot býva vypnutý z množstva
    # legitímnych dôvodov a strhávať body počítaču s dvoma systémami by bolo nečestné.
    "recommendation.secure_boot_off": (
        "Secure Boot je vypnutý. Bežným dôvodom býva dvojitý štart systémov alebo starší "
        "firmvér, takže ide o informáciu, nie o chybu, a body sa za to nestrhávajú."
    ),
    "recommendation.drive_failing": (
        "Disk ({drive}) hlási kritické varovanie o svojom stave. Zálohujte si teraz to, na čom "
        "vám záleží, a disk dajte skontrolovať."
    ),
    "recommendation.drive_worn": (
        "Disk ({drive}) sa opotrebúva (zostáva {value} jeho životnosti). Stále funguje, takže "
        "výmenu si naplánujte v pokoji a nečakajte na poruchu."
    ),
    "recommendation.battery_worn": (
        "Batéria je opotrebovaná ({value} pôvodnej kapacity). Počítajte s kratšou výdržou bez "
        "nabíjačky; takéto opotrebenie je bežné starnutie, nie porucha."
    ),
    "recommendation.large_folder": (
        "Z meraných priečinkov zaberá najviac miesta {name} ({value}). Skôr než čokoľvek "
        "odstránite, jeho obsah si pozrite v nastaveniach Úložiska vo Windowse."
    ),
    "recommendation.incomplete_data": (
        "Niektoré údaje sa nepodarilo načítať. Skôr než sa spoľahnete na skóre, prečítajte si "
        "upozornenia analýzy."
    ),
    "recommendation.all_good": (
        "Nezistili sa žiadne naliehavé problémy. Udržiavajte Windows aj aplikácie aktuálne."
    ),
    # -- report frame -------------------------------------------------------------------
    "report.title": "Apoliak Vitals",
    "report.subtitle": "Správa o stave počítača",
    "report.analysis_date": "Dátum analýzy",
    "report.mode": "Režim",
    "report.mode_readonly": "Analýza len na čítanie (nezmenili sa žiadne nastavenia ani súbory)",
    "report.duration": "Trvanie analýzy",
    "report.score": "Skóre",
    "report.status": "Stav",
    "report.score_value": "{score}/100",
    # 1 bod, 2-4 body, 0 a 5+ bodov. The bare key keeps the genitive plural for old callers.
    "report.points": "bodov",
    "report.points.one": "bod",
    "report.points.few": "body",
    "report.points.many": "bodov",
    "report.deductions": "Zrážky zo skóre:",
    "report.no_deductions": "Neuplatnila sa žiadna zrážka.",
    "report.categories": "Skóre podľa oblastí:",
    "report.unavailable": "nemerané",
    "report.partial_scan": "čiastočný sken",
    "report.system_drive": "systémový",
    "report.none_detected": "Nič sa nenašlo.",
    # "aspoň" precedes the number exactly as "at least" does, so the qualifier drops into the
    # parenthesis of the surrounding sentence without changing its grammar.
    "report.at_least": "aspoň {value}",
    "report.temp_truncated": (
        "Sken priečinka TEMP vyčerpal časový limit, veľkosť je preto len dolná hranica, "
        "nie nameraná hodnota."
    ),
    # Slovak numerals decline with the count, so the number stays outside the noun phrase.
    "report.and_more": "... a ďalšie ({count})",
    "report.and_more.one": "... a ďalšia {count} položka",
    "report.and_more.few": "... a ďalšie {count} položky",
    "report.and_more.many": "... a ďalších {count} položiek",
    # 1 deň, 2-4 dni, 0 a 5+ dní; 1 hodina, 2-4 hodiny, 0 a 5+ hodín.
    "report.days.one": "{count} deň",
    "report.days.few": "{count} dni",
    "report.days.many": "{count} dní",
    "report.hours.one": "{count} hodina",
    "report.hours.few": "{count} hodiny",
    "report.hours.many": "{count} hodín",
    "report.security_center_down": (
        "Centrum zabezpečenia Windows neodpovedalo, preto je stav antivírusu a brány firewall "
        "neznámy, nie vypnutý."
    ),
    "report.cores_value": "{physical} / {logical}",
    "report.cores_physical.one": "{count} fyzické",
    "report.cores_physical.few": "{count} fyzické",
    "report.cores_physical.many": "{count} fyzických",
    "report.cores_logical.one": "{count} logické",
    "report.cores_logical.few": "{count} logické",
    "report.cores_logical.many": "{count} logických",
    "report.frequency_value": "{current} (max. {maximum})",
    "report.per_core_value": "min {min} / priem. {avg} / max {max}",
    "report.swap_value": "{used} z {total} ({percent})",
    "report.interface_value": "{name}: {state}",
    "report.driver_value": "{version} ({date})",
    "report.footer": (
        "Táto správa je informatívna. Apoliak Vitals vo vašom počítači nič nezmenil."
    ),
    "report.generated_by": "Vytvoril {name} {version}",
    "report.section_failed": "Túto časť sa nepodarilo vykresliť ({error}).",
    # -- section headings ---------------------------------------------------------------
    "section.system": "SYSTÉM",
    "section.cpu": "PROCESOR",
    "section.ram": "PAMÄŤ RAM",
    "section.disk": "DISK",
    "section.partitions": "ODDIELY",
    "section.processes": "PROCESY",
    "section.top_processes": "NAJNÁROČNEJŠIE PROCESY",
    "section.temp": "DOČASNÉ SÚBORY",
    "section.folders": "NAJVÄČŠIE PRIEČINKY",
    "section.drive_health": "STAV DISKOV",
    "section.security": "ZABEZPEČENIE",
    "section.uptime": "DOBA BEHU",
    "section.battery": "BATÉRIA",
    "section.network": "SIEŤ",
    "section.gpu": "GRAFIKA",
    "section.startup": "POLOŽKY PO ŠTARTE",
    "section.score": "SKÓRE ZDRAVIA PC",
    "section.recommendations": "ODPORÚČANIA",
    "section.warnings": "UPOZORNENIA ANALÝZY",
    # -- field labels -------------------------------------------------------------------
    "field.os": "Systém",
    "field.release": "Vydanie",
    "field.version": "Verzia",
    "field.display_version": "Verzia Windowsu",
    "field.build": "Zostava",
    "field.edition": "Edícia",
    "field.architecture": "Architektúra",
    "field.processor": "Procesor",
    "field.manufacturer": "Výrobca",
    "field.model": "Model",
    "field.bios": "Verzia BIOS",
    "field.install_date": "Inštalácia Windowsu",
    "field.boot_time": "Posledný štart",
    "field.cores": "Jadrá procesora",
    "field.physical_cores": "Fyzické jadrá",
    "field.logical_cores": "Logické jadrá",
    "field.usage": "Vyťaženie",
    "field.cpu_usage": "Vyťaženie procesora",
    "field.ram_usage": "Vyťaženie pamäte RAM",
    "field.disk_usage": "Zaplnenie disku",
    "field.frequency": "Frekvencia procesora",
    "field.max_frequency": "Maximálna frekvencia",
    "field.per_core": "Vyťaženie jadier",
    "field.installed": "Nainštalovaná RAM",
    "field.ram_total": "Celková RAM",
    "field.ram_available": "Dostupná RAM",
    "field.ram_used": "Použitá RAM",
    "field.disk_total": "Kapacita disku",
    "field.disk_used": "Obsadené miesto",
    "field.disk_free": "Voľné miesto",
    "field.total": "Celkom",
    "field.used": "Použité",
    "field.available": "Dostupné",
    "field.free": "Voľné",
    "field.swap": "Stránkovací súbor",
    "field.drive": "Disk",
    "field.filesystem": "Súborový systém",
    "field.media_type": "Typ média",
    "field.processes": "Bežiace procesy",
    "field.uptime": "Doba behu systému",
    "field.data_complete": "Úplné údaje",
    "field.folder_size": "Veľkosť priečinka",
    "field.path": "Cesta",
    "field.files": "Súbory",
    "field.folder": "Priečinok",
    "field.battery": "Batéria",
    "field.plugged_in": "Napájanie zo siete",
    "field.time_left": "Zostávajúci čas",
    # -- opotrebenie batérie ---------------------------------------------------------------
    "field.battery_health": "Kondícia batérie",
    "field.design_capacity": "Pôvodná kapacita",
    "field.full_charge_capacity": "Kapacita pri plnom nabití",
    "field.cycle_count": "Nabíjacie cykly",
    "field.chemistry": "Chémia článkov",
    # -- opotrebenie diskov ----------------------------------------------------------------
    "field.bus_type": "Zbernica",
    "field.life_left": "Zostávajúca životnosť",
    "field.temperature": "Teplota",
    "field.power_on_hours": "Hodiny v prevádzke",
    "field.data_written": "Zapísané údaje",
    "field.critical_warning": "Kritické varovanie",
    # -- stav ochrany ----------------------------------------------------------------------
    "field.antivirus": "Antivírus",
    "field.firewall": "Brána firewall",
    "field.secure_boot": "Secure Boot",
    "field.reboot_pending": "Čaká sa na reštart",
    "field.signature_age": "Vek definícií",
    "field.last_scan": "Posledná kontrola",
    # Po jednom označení pre každý verdikt STATE_*. "Neznáme" je zámerne vlastné slovo:
    # nastavenie, ktoré sa nepodarilo prečítať, sa nikdy nesmie tváriť ako "Vypnuté".
    "field.state_good": "Zapnuté",
    "field.state_weak": "Vyžaduje pozornosť",
    "field.state_bad": "Vypnuté",
    "field.state_unknown": "Neznáme",
    "field.sent": "Odoslané",
    "field.received": "Prijaté",
    "field.interfaces": "Rozhrania",
    "field.startup_items": "Položky po štarte",
    "field.driver": "Ovládač",
    "field.gpu_memory": "Pamäť grafiky",
    "field.yes": "Áno",
    "field.no": "Nie",
    "field.name": "Názov",
    "field.value": "Hodnota",
    "field.pid": "PID",
    "field.memory": "Pamäť",
    "field.memory_percent": "Pamäť %",
    "field.cpu_percent": "Procesor %",
    "field.source": "Zdroj",
    "field.label": "Umiestnenie",
    "field.up": "aktívne",
    "field.down": "neaktívne",
    "field.score": "Skóre",
    "field.status": "Stav",
    "field.severity": "Závažnosť",
    "field.category": "Oblasť",
    "field.reason": "Dôvod",
    "field.points": "Body",
    "field.temp_path": "Priečinok TEMP",
    "field.temp_size": "Veľkosť priečinka TEMP",
    "field.duration": "Trvanie",
    # -- console interface --------------------------------------------------------------
    "cli.description": (
        "Bezpečne zanalyzuje stav počítača s Windowsom bez zmeny akéhokoľvek nastavenia."
    ),
    "cli.epilog": (
        "Návratové kódy: 0 úspech, 1 chyba pri behu, 2 neplatné argumenty, 3 skóre pod "
        "--fail-under. Analyzátor iba číta. Nikdy nič nemaže, neopravuje ani nenastavuje."
    ),
    "cli.group.analysis": "analýza",
    "cli.group.output": "výstup",
    "cli.group.history": "história (voliteľná, uložená lokálne)",
    "cli.help.export": (
        "exportovať výsledok; bez cesty sa v tomto priečinku vytvorí automaticky "
        "pomenovaný súbor"
    ),
    "cli.help.format": (
        "formát exportu: text, json, html alebo markdown (predvolene: text alebo podľa "
        "prípony exportovaného súboru)"
    ),
    "cli.help.output": "výslovné umiestnenie exportu; zapína --export a má pred ním prednosť",
    "cli.help.no_prompt": "nepýtať sa na nič interaktívne",
    "cli.help.cpu_seconds": "dĺžka merania procesora od 0 do 5 sekúnd (predvolene: 1)",
    "cli.help.language": (
        "jazyk správy: en alebo sk (predvolene: podľa APOLIAK_LANG alebo miestnych nastavení)"
    ),
    "cli.help.redact": "skryť meno používateľa Windowsu všade vo výstupe",
    "cli.help.color": (
        "farby v konzole: auto, always alebo never; do exportovaného súboru sa nikdy "
        "nedostanú (predvolene: auto)"
    ),
    "cli.help.quiet": "vypísať iba riadok so skóre",
    "cli.help.no_temp_scan": "úplne preskočiť meranie priečinka TEMP",
    "cli.help.temp_seconds": (
        "časový limit skenu priečinka TEMP v sekundách (predvolene: {seconds})"
    ),
    "cli.help.top": (
        "koľko najnáročnejších procesov načítať, 0 zoznam vypne (predvolene: 5)"
    ),
    "cli.help.history": "pridať toto meranie do lokálneho súboru histórie",
    "cli.help.history_path": (
        "vlastný súbor histórie (predvolene: lokálny priečinok údajov aplikácií)"
    ),
    "cli.help.show_history": (
        "vypísať posledných N uložených meraní a skončiť (predvolene: 10, 0 vypíše všetky)"
    ),
    "cli.help.compare": "zobraziť zmenu oproti predchádzajúcemu uloženému meraniu",
    "cli.help.fail_under": "skončiť s kódom 3, ak je skóre zdravia nižšie ako N (0 - 100)",
    "cli.help.no_startup": "preskočiť načítanie položiek po štarte",
    "cli.help.no_gpu": "preskočiť načítanie údajov o grafickej karte",
    "cli.help.version": "vypísať verziu programu a skončiť",
    "cli.help.help": "vypísať túto nápovedu a skončiť",
    "cli.prompt.export": "Exportovať túto správu? [a/N]: ",
    "cli.msg.progress": "{message}",
    "cli.msg.score_line": "Skóre: {score}/100 ({status})",
    "cli.msg.saved": "Správa uložená do: {path}",
    "cli.msg.export_failed": "Správu sa nepodarilo exportovať: {error}",
    "cli.msg.analysis_failed": "Analýza sa bezpečne ukončila s chybou: {error}",
    "cli.msg.missing_dependency": "Chyba: {error}",
    "cli.msg.invalid_interval": "Chyba: --cpu-sample-seconds musí byť od 0 do 5.",
    "cli.msg.invalid_top": "Chyba: --top musí byť 0 alebo celé číslo.",
    "cli.msg.invalid_temp_seconds": "Chyba: --temp-scan-seconds musí byť 0 alebo viac.",
    "cli.msg.invalid_threshold": "Chyba: --fail-under musí byť od 0 do 100.",
    "cli.msg.invalid_color": "Chyba: --color musí byť jedna z hodnôt: {values}.",
    "cli.msg.invalid_format": "Chyba: neznámy formát exportu „{value}“.",
    "cli.msg.cancelled": "Zrušené.",
    "cli.msg.below_threshold": "Skóre {score} je pod požadovaným minimom {threshold}.",
    "cli.msg.history_saved": "História aktualizovaná: {path}",
    "cli.msg.history_failed": "Súbor histórie sa nepodarilo aktualizovať: {error}",
    "cli.msg.history_file": "Súbor histórie: {path}",
    "cli.msg.no_history": "Zatiaľ nie je uložená žiadna predchádzajúca analýza.",
    "cli.msg.compare_header": "Porovnanie s predchádzajúcou analýzou ({when}):",
    "cli.msg.compare_score": "Skóre: {value}",
    "cli.msg.compare_cpu": "Vyťaženie procesora: {value}",
    "cli.msg.compare_ram": "Vyťaženie pamäte RAM: {value}",
    "cli.msg.compare_disk": "Voľné miesto na disku: {value}",
    # Columns of the --show-history table. Slovak names the two hardware columns rather than
    # keeping the English abbreviations, exactly as the field labels of the report do.
    "cli.history.column.date": "Dátum analýzy",
    "cli.history.column.score": "Skóre",
    "cli.history.column.status": "Stav",
    "cli.history.column.cpu": "Procesor",
    "cli.history.column.ram": "Pamäť",
    "cli.history.column.free_disk": "Voľné miesto",
    # -- analysis progress steps ----------------------------------------------------------
    # First person singular, like the other running-state strings ("Spúšťam analýzu...").
    "progress.system": "Načítavam údaje o systéme",
    "progress.cpu": "Meriam vyťaženie procesora",
    "progress.ram": "Načítavam využitie pamäte",
    "progress.disk": "Načítavam disky",
    "progress.partitions": "Načítavam oddiely",
    "progress.processes": "Počítam procesy",
    "progress.top_processes": "Zoraďujem procesy",
    "progress.temp": "Meriam dočasné súbory",
    "progress.folders": "Meriam najväčšie priečinky",
    "progress.drive_health": "Načítavam stav diskov",
    "progress.security": "Načítavam nastavenia ochrany",
    "progress.extras": "Načítavam údaje o hardvéri",
    "progress.done": "Analýza dokončená",
    # -- graphical interface ------------------------------------------------------------
    "gui.title": "Apoliak Vitals",
    "gui.window_title": "Apoliak Vitals",
    "gui.subtitle": "Kontrola stavu Windowsu len na čítanie",
    "gui.version": "Verzia {version}",
    "gui.brand.name": "APOLIAK",
    "gui.brand.tagline": "VITALS",
    "gui.sidebar.analysis": "ANALÝZA",
    "gui.sidebar.export": "EXPORT",
    "gui.nav.overview": "Prehľad",
    "gui.nav.processes": "Procesy",
    "gui.nav.storage": "Úložisko",
    "gui.nav.security": "Zabezpečenie",
    "gui.nav.system": "Systém",
    "gui.nav.history": "História",
    "gui.nav.settings": "Nastavenia",
    "gui.button.analyze": "Analyzovať počítač",
    "gui.button.analyzing": "Analyzujem...",
    "gui.button.again": "Analyzovať znova",
    "gui.button.export": "Exportovať správu",
    "gui.button.copy": "Kopírovať do schránky",
    "gui.button.copied": "Skopírované",
    # Otvorí stránku nastavení Windowsu na vedomé kliknutie. Režim len na čítanie ostáva
    # nedotknutý: zobrazenie stránky nič nemení a analýza sama nikdy nič neotvára.
    "gui.button.open_setting": "Otvoriť nastavenie",
    "gui.state.ready": "Pripravené",
    "gui.state.running": "Prebieha analýza...",
    "gui.state.complete": "Analýza dokončená",
    "gui.state.failed": "Analýza zlyhala",
    "gui.progress.starting": "Spúšťam analýzu...",
    "gui.status.duration": "trvalo {duration}",
    # Slovak numerals decline with the count, so the bare key keeps the noun in the genitive
    # plural and puts the number last; the plural forms below decline it properly.
    "gui.status.warnings": "upozornení: {count}",
    "gui.status.warnings.one": "{count} upozornenie",
    "gui.status.warnings.few": "{count} upozornenia",
    "gui.status.warnings.many": "{count} upozornení",
    # -- export formats -----------------------------------------------------------------
    "gui.format.text": "Text (.txt)",
    "gui.format.json": "JSON (.json)",
    "gui.format.html": "HTML (.html)",
    "gui.format.markdown": "Markdown (.md)",
    "gui.filetype.text": "Textová správa",
    "gui.filetype.json": "Údaje JSON",
    "gui.filetype.html": "Správa HTML",
    "gui.filetype.markdown": "Správa Markdown",
    "gui.filetype.all": "Všetky súbory",
    "gui.card.system": "Systém",
    "gui.card.cpu": "Procesor",
    "gui.card.ram": "Pamäť",
    "gui.card.disk": "Systémový disk",
    "gui.card.activity": "Aktivita",
    "gui.card.temp": "Dočasné súbory",
    # Zámerne bez "gui.card.folders" / "gui.card.drive_health" - pozri anglickú tabuľku.
    "gui.card.security": "Zabezpečenie",
    "gui.card.battery": "Batéria",
    "gui.card.network": "Sieť",
    "gui.card.gpu": "Grafika",
    "gui.section.folders": "Najväčšie priečinky",
    "gui.section.drive_health": "Stav diskov",
    "gui.section.history_chart": "Skóre v čase",
    "gui.section.recommendations": "Odporúčania",
    "gui.section.deductions": "Zrážky zo skóre",
    "gui.section.processes": "Najnáročnejšie procesy",
    "gui.section.categories": "Skóre oblastí",
    "gui.section.warnings": "Upozornenia analýzy",
    "gui.section.partitions": "Oddiely",
    "gui.section.overview": "Prehľad",
    "gui.deductions.points": "-{points} b.",
    "gui.processes.subtitle": (
        "Zoradené podľa využitia pamäte. Zoznam je len na čítanie - nič sa neukončuje."
    ),
    "gui.storage.title": "Disky a oddiely",
    "gui.storage.usage": "{used} z {total} obsadených, {free} voľných",
    "gui.system.title": "Operačný systém",
    "gui.system.firmware": "Firmvér",
    "gui.system.gpus": "Grafické adaptéry",
    "gui.system.no_gpus": "Nenašli sa žiadne grafické adaptéry.",
    "gui.system.no_startup": "Nenašli sa žiadne položky po štarte.",
    "gui.system.no_warnings": "Žiadne upozornenia. Všetky údaje sa podarilo načítať.",
    "gui.field.charge": "Nabitie",
    "gui.field.locations": "Umiestnenia",
    "gui.field.files_changed": "Zmenené súbory",
    "gui.field.adapters": "Adaptéry",
    "gui.value.plugged": "Pripojené k sieti",
    "gui.value.on_battery": "Na batérii",
    "gui.value.system_drive": "Systémový disk",
    "gui.label.not_analyzed": "Zatiaľ nezanalyzované",
    "gui.label.last_analyzed": "Posledná analýza: {value}",
    "gui.label.readonly_title": "Režim len na čítanie",
    "gui.label.readonly_body": (
        "Aplikácia iba číta údaje o systéme. Nikdy nemaže súbory, needituje register, "
        "nezastavuje služby ani nemení nastavenia Windowsu."
    ),
    "gui.label.language": "Jazyk",
    "gui.label.redact": "Skryť osobné údaje",
    "gui.label.redact_hint": (
        "V exportovaných a skopírovaných správach nahradí meno vášho účtu vo Windowse "
        "textom <user>, takže sa dajú bezpečne zdieľať."
    ),
    "gui.label.theme": "Vzhľad",
    "gui.label.placeholder": "--",
    "gui.label.score_hint": "100 bodov mínus každý nižšie uvedený nález.",
    "gui.label.score": "Skóre zdravia",
    "gui.label.no_data": "Zatiaľ bez údajov",
    "gui.label.history_empty": "Uložte niekoľko analýz a vývoj sa zobrazí tu.",
    # Stojí vedľa tlačidla vyššie, aby čitateľ vedel, čo kliknutie spraví, ešte pred ním.
    "gui.label.action_hint": (
        "Otvorí príslušnú stránku nastavení Windowsu. Nič sa za vás nezmení."
    ),
    "gui.label.history_hint": "História je voliteľná a ukladá sa len v tomto počítači.",
    "gui.health.of100": "/ 100",
    "gui.theme.dark": "Tmavý",
    "gui.theme.light": "Svetlý",
    # -- opt-in local history -----------------------------------------------------------
    "gui.history.title": "Lokálna história",
    "gui.history.optin": "Uložiť túto analýzu lokálne",
    "gui.history.explain": "Kým je políčko vyššie nezaškrtnuté, na disk sa nič nezapisuje.",
    "gui.history.location": "Miesto uloženia",
    "gui.history.refresh": "Obnoviť zoznam",
    "gui.history.score": "Skóre {score}",
    "gui.history.first": "Prvé uložené meranie",
    "gui.history.delta": "{delta} oproti minulému",
    "gui.history.saved": "Uložené do {path}",
    "gui.history.failed": "Toto meranie sa nepodarilo uložiť: {error}",
    "gui.history.unavailable": "Modul histórie nie je v tejto inštalácii dostupný.",
    "gui.dialog.export_title": "Uložiť správu",
    "gui.dialog.exported": "Správa exportovaná",
    "gui.dialog.export_failed": "Export zlyhal",
    "gui.dialog.format_unavailable": (
        "Tento formát exportu nie je v tejto inštalácii dostupný."
    ),
    "gui.dialog.copy_failed": "Kopírovanie zlyhalo",
    "gui.msg.export_ok": "Správa uložená do {path}",
    "gui.msg.export_failed": "Správu sa nepodarilo uložiť: {error}",
    "gui.msg.copied": "Správa bola skopírovaná do schránky.",
    "gui.msg.setting_opened": "Windows otvoril stránku nastavení. Nič sa nezmenilo.",
    "gui.msg.setting_failed": "Stránku nastavení sa nepodarilo otvoriť: {error}",
    "gui.msg.redact_unavailable": (
        "Táto inštalácia nedokáže skryť osobné údaje. Pokračujte odškrtnutím políčka "
        "„{label}“."
    ),
    "gui.msg.analysis_failed": "Analýzu sa nepodarilo dokončiť: {error}",
    "gui.msg.no_recommendations": "Pre túto snímku nie sú žiadne odporúčania.",
    "gui.msg.no_deductions": "Neodpočítal sa žiadny bod.",
    "gui.msg.no_processes": "Údaje o procesoch nie sú k dispozícii.",
    "gui.msg.no_history": "Zatiaľ nie je uložená žiadna predchádzajúca analýza.",
}

# A gap in a translation must degrade to English, never to a raw key on screen.
for _key, _value in _EN.items():
    _SK.setdefault(_key, _value)

_TRANSLATIONS: dict[str, dict[str, str]] = {"en": _EN, "sk": _SK}

_LANGUAGE_LABELS: dict[str, str] = {"en": "English", "sk": "Slovenčina"}

# Windows reports locales such as "Slovak_Slovakia", POSIX reports "sk_SK".
_LOCALE_PREFIXES: tuple[tuple[str, str], ...] = (
    ("sk", "sk"),
    ("slovak", "sk"),
    ("slovensk", "sk"),
    ("en", "en"),
    ("english", "en"),
)


class _Defaults(dict):
    """Mapping that returns a marker instead of raising for an unsupplied placeholder."""

    def __missing__(self, key: str) -> str:
        return _MISSING


def _format(template: str, params: Mapping[str, object]) -> str:
    """Substitute ``params`` into ``template`` without ever raising."""
    if "{" not in template:
        return template
    try:
        text = template.format_map(_Defaults(params))
    except Exception:
        # A malformed template must not take down a report; show it unformatted.
        return template
    if _MISSING not in text:
        return text
    # An unmeasured value should disappear with its parenthetical instead of reading "(N/A)".
    text = _OPTIONAL_SEGMENT.sub("", text)
    text = text.replace(_MISSING, UNKNOWN_VALUE)
    return _REPEATED_SPACES.sub(" ", text).strip()


def _language_from_locale(value: object) -> str | None:
    """Map a locale-ish string onto a shipped language code, or None."""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().lower().replace("-", "_")
    for prefix, code in _LOCALE_PREFIXES:
        if text.startswith(prefix):
            return code
    return None


def normalize_language(value: object) -> str:
    """Return a supported language code, falling back to the default one."""
    return _language_from_locale(value) or DEFAULT_LANGUAGE


def plural_form(count: object, language: object = None) -> str:
    """
    Return the grammatical number ``language`` uses for ``count``: one, few, or many.

    Slovak counts in three groups - 1 "bod", 2 to 4 "body", 0 and 5 upwards "bodov" - which is
    why the choice cannot live in a renderer that only knows English. A value that is not a
    whole number is never singular ("1.5 point" is wrong in both languages), and an
    unreadable count degrades to the generic plural instead of raising.
    """
    try:
        number = float(count)  # type: ignore[arg-type]
        if not number.is_integer():  # Also excludes NaN and infinity.
            return "many"
        whole = abs(int(number))
    except (TypeError, ValueError, OverflowError):
        return "many"
    if whole == 1:
        return "one"
    if 2 <= whole <= 4 and normalize_language(language) == "sk":
        return "few"
    return "many"


class Translator:
    """Key-to-text lookup for one language. Every method is failure-tolerant."""

    __slots__ = ("_language", "_table", "_missing")

    def __init__(self, language: str = DEFAULT_LANGUAGE) -> None:
        self._language = normalize_language(language)
        self._table = _TRANSLATIONS.get(self._language, _EN)
        # dict keeps request order, which makes a coverage report readable.
        self._missing: dict[str, None] = {}

    @property
    def language(self) -> str:
        return self._language

    @language.setter
    def language(self, value: str) -> None:
        self._language = normalize_language(value)
        self._table = _TRANSLATIONS.get(self._language, _EN)

    def has(self, key: str) -> bool:
        """True when the key resolves in this language or in the English fallback."""
        return key in self._table or key in _EN

    def t(self, key: str, default: str | None = None, **params: object) -> str:
        """
        Translate ``key``.

        Unknown keys fall back to ``default`` and are recorded for ``missing_keys()``; with no
        default the key itself is returned so a gap is visible instead of silent.
        """
        try:
            template = self._table.get(key)
            if template is None:
                template = _EN.get(key)
            if template is None:
                self._missing[key] = None
                template = default if default is not None else key
            return _format(str(template), params)
        except Exception:
            return default if default is not None else key

    __call__ = t

    def t_plural(
        self, base_key: str, count: object, default: str | None = None, /, **params: object
    ) -> str:
        """
        Translate a phrase whose wording depends on ``count``.

        Resolves ``<base_key>.one``, ``.few`` or ``.many`` - see :func:`plural_form` - so a
        caller writes one line and Slovak still says "1 bod", "3 body" and "5 bodov" instead
        of the wrong "3 bodov". ``count`` is passed on as the ``{count}`` placeholder unless
        the caller supplied that name itself, which is how a formatted "N/A" can stand in for
        a number that was never measured. The first three parameters are positional-only
        precisely so that ``count=`` reaches the template instead of colliding with them.

        A catalogue that only knows the plain ``base_key`` still answers on it, so adding
        plural forms to one language never breaks another.
        """
        try:
            params.setdefault("count", count)
            key = f"{base_key}.{plural_form(count, self._language)}"
            if not self.has(key) and self.has(base_key):
                key = base_key
            return self.t(key, default, **params)
        except Exception:
            return default if default is not None else base_key

    def missing_keys(self) -> tuple[str, ...]:
        """Keys that were requested but are not part of any shipped table."""
        return tuple(self._missing)


def available_languages() -> tuple[str, ...]:
    return LANGUAGES


def language_label(code: str) -> str:
    """Human-readable, self-referencing name of a language."""
    return _LANGUAGE_LABELS.get(normalize_language(code), str(code))


def translation_keys(language: str | None = None) -> tuple[str, ...]:
    """Sorted keys of one table. Used by the tests to assert coverage across languages."""
    table = _TRANSLATIONS.get(normalize_language(language) if language else DEFAULT_LANGUAGE, _EN)
    return tuple(sorted(table))


def _system_locales() -> tuple[str, ...]:
    """Best-effort locale probe. Every source here is optional and must never raise."""
    found: list[str] = []
    with warnings.catch_warnings():
        # getdefaultlocale() is deprecated but still the only answer on some Windows setups.
        warnings.simplefilter("ignore")
        for name in ("getlocale", "getdefaultlocale"):
            getter = getattr(locale, name, None)
            if getter is None:
                continue
            try:
                value = getter()
            except Exception:
                continue
            if isinstance(value, tuple) and value:
                found.append(value[0] if isinstance(value[0], str) else "")
    for variable in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        found.append(os.environ.get(variable, ""))
    return tuple(item for item in found if item)


def detect_language() -> str:
    """Pick a language from the environment override, then the OS locale, then English."""
    try:
        override = _language_from_locale(os.environ.get(LANGUAGE_ENV))
        if override:
            return override
        for candidate in _system_locales():
            code = _language_from_locale(candidate)
            if code:
                return code
    except Exception:
        pass
    return DEFAULT_LANGUAGE


def get_translator(language: str | None = None) -> Translator:
    """Build a translator. ``None`` detects the language from the environment."""
    return Translator(language if language else detect_language())
