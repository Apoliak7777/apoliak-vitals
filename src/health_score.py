"""Transparent, deterministic PC Health Score with graded tiers and per-area sub-scores.

The score is a table, not a black box: every row of :data:`SCORE_RULES` is a public,
documentable statement of "this measurement, past this threshold, costs this many points".
The six v1.0 thresholds survive as the ``standard`` tier of their rule, so the published
score table stays literally true; the surrounding tiers only make the reaction proportional
instead of binary.

v2.1 adds rows for durable state - protection, drive wear, battery wear - rather than a
second engine beside the table. A verdict such as "the antivirus is at risk" is placed on a
small numeric ladder (:data:`STATE_LEVELS`), which lets one threshold machinery, one
unknown-is-never-penalised rule and one tier selector serve every finding the app can make.

Three principles are load-bearing and must not be optimised away:

* An unknown measurement never costs points. Its rule stays unevaluated and its category is
  reported as unavailable, so presenters can show "N/A" instead of an unearned 100.
* Only one tier of a rule can fire. Tiers are alternatives, never cumulative.
* Every deduction states the number it was based on, so a user can check the verdict.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from string import Formatter

from .models import (
    CATEGORY_CPU,
    CATEGORY_MAINTENANCE,
    CATEGORY_MEMORY,
    CATEGORY_POWER,
    CATEGORY_SECURITY,
    CATEGORY_STORAGE,
    STATE_BAD,
    STATE_GOOD,
    STATE_WEAK,
    AnalysisData,
    CategoryScore,
    DriveHealth,
    HealthAssessment,
    ScoreDeduction,
    severity_rank,
)
from .utils import GIB, format_bytes, format_count, format_percent, format_uptime

HOUR = 3600.0

#: A page file smaller than this makes its usage percentage meaningless (a 256 MB page file
#: sits at 95% on a perfectly healthy PC), so swap is not scored below this size.
MIN_MEANINGFUL_SWAP_BYTES = GIB

#: Where each protection verdict sits on the "how bad is this" ladder the rule table compares
#: against. Turning a verdict into a number is what lets a state be scored by the very same
#: threshold machinery as a percentage, so a protection finding is a row of the table rather
#: than a branch beside it. STATE_UNKNOWN is deliberately absent: an unreadable verdict maps
#: to None, and None never matches a rule - an antivirus nobody could ask about is not a fault.
STATE_LEVELS: dict[str, float] = {STATE_GOOD: 0.0, STATE_WEAK: 1.0, STATE_BAD: 2.0}

#: The word each rung is described by. These name the rungs of the ladder for the published
#: rule table ("Antivirus protection is at risk or worse"); the deduction sentences quote no
#: state word at all, because "off" is a word and a word belongs to the reader's language.
STATE_WORDS: dict[str, str] = {STATE_GOOD: "on", STATE_WEAK: "at risk", STATE_BAD: "off"}

#: The two binary readings, described the same way: a restart is owed or it is not, and a
#: drive either raised its critical warning or it did not.
RESTART_PENDING_WORD = "pending"
DRIVE_FAILING_WORD = "failing"

#: Rung -> word, worst rung first. A metric that carries one of these reports a state instead
#: of a quantity, and the word is what the deduction quotes.
_PROTECTION_SCALE: tuple[tuple[float, str], ...] = tuple(
    (STATE_LEVELS[state], STATE_WORDS[state]) for state in (STATE_BAD, STATE_WEAK, STATE_GOOD)
)
_RESTART_SCALE: tuple[tuple[float, str], ...] = ((1.0, RESTART_PENDING_WORD), (0.0, "none"))
_DRIVE_HEALTH_SCALE: tuple[tuple[float, str], ...] = ((1.0, DRIVE_FAILING_WORD), (0.0, "healthy"))

#: Threshold that catches every rung above "good" - i.e. weak or bad, never unknown.
_WORSE_THAN_GOOD = (STATE_LEVELS[STATE_GOOD] + STATE_LEVELS[STATE_WEAK]) / 2
#: Threshold that catches only the worst rung.
_WORSE_THAN_WEAK = (STATE_LEVELS[STATE_WEAK] + STATE_LEVELS[STATE_BAD]) / 2
#: Threshold that catches a raised flag. Halfway between "no" (0) and "yes" (1).
_FLAG_RAISED = 0.5

#: Score bands, highest first. Published in the README and unchanged since v1.0.
STATUS_BANDS: tuple[tuple[int, str], ...] = (
    (90, "Excellent"),
    (75, "Good"),
    (50, "Needs Optimization"),
    (0, "Poor"),
)

#: English reason templates, one per deduction key. One template per key, not per tier,
#: because translations are keyed by "deduction.<key>"; the tier is carried by the points
#: and the severity rather than by different wording.
DEDUCTION_TEMPLATES: dict[str, str] = {
    "high_cpu": "CPU usage is {value}.",
    "high_ram": "RAM usage is {value}.",
    "high_swap": "Page file usage is {value}.",
    "low_disk": "Free space on {drive} is {value}.",
    "disk_nearly_full": "Drive {drive} is {value} full.",
    "many_processes": "{value} processes are running.",
    "large_temp": "The temporary files folder holds {value}.",
    "long_uptime": "The system has been running for {value}.",
    "many_startup_items": "{value} startup entries are registered.",
    "low_battery": "The battery is at {value} and the PC is running on battery power.",
    # State rather than load. Four of these quote no number because there is none to quote:
    # the finding is that a setting is off, and the tier - not the wording - carries how far
    # off it is. The signature age is deliberately left out of the sentence too, so the
    # section that quotes it can decline the noun in languages that need three plural forms
    # where English needs two; a deduction is rendered through plain lookup, which cannot.
    # These sentences are kept identical to the shipped English catalogue, so the fallback a
    # translator-less consumer prints and the text a translated report prints never diverge.
    #
    # The two protection sentences must be true of BOTH rungs they cover, because one
    # template serves both tiers. "Antivirus protection is not active" would be a claim this
    # application cannot support: the Security Center's "poor"/"snoozed" verdict - the worst
    # one the collector can actually reach on a real machine - means protection that is
    # present but degraded or paused, and reading the firewall as weak can mean a single
    # network profile is switched off while the other two guard the PC normally. Stating
    # something stronger than what was measured would be inventing a measurement.
    "antivirus_off": "Windows Security reports that this PC is not properly protected.",
    "firewall_off": "The Windows firewall is not active on every network profile.",
    "stale_signatures": "Antivirus definitions are not up to date.",
    "reboot_pending": "Windows is waiting for a restart to finish an update.",
    "drive_failing": "The drive ({drive}) reports a critical health warning.",
    "drive_worn": "The drive ({drive}) is wearing out ({value} of its rated life left).",
    "battery_worn": "The battery is worn ({value} of its original capacity).",
}

#: Parameter that marks a quoted measurement as a floor rather than a reading, because the
#: collector had to cut its scan short. Producers attach it instead of baking "at least ..."
#: into the number: the qualifier is a sentence, and a sentence belongs to the reader's
#: language. The renderer resolves it through the translator ("report.at_least"), so a
#: Slovak report reads "aspoň 12,0 GB" where an English one reads "at least 12.0 GB".
LOWER_BOUND_PARAM: tuple[str, str] = ("bound", "lower")


def english_lower_bound(measurement: str) -> str:
    """Qualify a measurement as a floor for a producer's own fallback sentence.

    Only the ``reason``/``text`` strings the producers carry use this. They are the
    last-resort rendering for a consumer that has no translator at all, so they stay plain
    readable English; every translated format goes through :data:`LOWER_BOUND_PARAM`.
    """
    return f"at least {measurement}"


@dataclass(frozen=True, slots=True)
class Metric:
    """One measurement the score can read, and how it behaves."""

    key: str
    label: str
    #: percent | bytes | count | duration | state - decides how the value is rendered.
    unit: str
    category: str
    #: ``above`` means high values are bad, ``below`` means low values are bad.
    direction: str = "above"
    #: Rung -> word, worst rung first, for a metric that reports a state instead of a
    #: quantity. Present exactly when ``unit`` is ``state``; the scale, not the unit
    #: formatter, then decides what the reading is quoted as.
    scale: tuple[tuple[float, str], ...] = ()

    def render(self, value: float | None) -> str:
        """Quote one reading of this metric: a word for a state, a number for a quantity."""
        if self.scale:
            return _scale_word(self.scale, value)
        return _format_measurement(self.unit, value)

    def caught(self, threshold: float) -> str:
        """The mildest rung a rule at ``threshold`` still catches, for documentation."""
        for level, word in reversed(self.scale):  # Best rung first.
            if level > threshold:
                return word
        return self.scale[0][1] if self.scale else "N/A"


#: Every input the rule table may reference. Category and direction live here so a rule row
#: cannot file itself under the wrong area or compare in the wrong direction.
METRICS: dict[str, Metric] = {
    metric.key: metric
    for metric in (
        Metric("cpu_percent", "CPU usage", "percent", CATEGORY_CPU),
        Metric("ram_percent", "RAM usage", "percent", CATEGORY_MEMORY),
        Metric("swap_percent", "Page file usage", "percent", CATEGORY_MEMORY),
        Metric("disk_free_bytes", "Free system-drive space", "bytes", CATEGORY_STORAGE, "below"),
        Metric("disk_usage_percent", "System-drive usage", "percent", CATEGORY_STORAGE),
        Metric("process_count", "Running processes", "count", CATEGORY_MAINTENANCE),
        Metric("temp_bytes", "TEMP folder size", "bytes", CATEGORY_MAINTENANCE),
        Metric("uptime_seconds", "System uptime", "duration", CATEGORY_MAINTENANCE),
        Metric("startup_count", "Startup entries", "count", CATEGORY_MAINTENANCE),
        Metric("battery_percent", "Battery charge", "percent", CATEGORY_POWER),
        Metric("battery_low", "Battery charge on battery", "percent", CATEGORY_POWER, "below"),
        # --- v2.1: durable state, as opposed to the load the rows above measure ---
        Metric(
            "antivirus_state", "Antivirus protection", "state", CATEGORY_SECURITY,
            scale=_PROTECTION_SCALE,
        ),
        Metric(
            "firewall_state", "Firewall protection", "state", CATEGORY_SECURITY,
            scale=_PROTECTION_SCALE,
        ),
        # Measured, reported, and deliberately never scored: Secure Boot is off for entirely
        # legitimate reasons (dual boot, older firmware), so no rule row references this
        # metric. It is listed because it still decides whether the Security sub-score was
        # measurable at all - a machine that answered only this question is not "unknown".
        Metric(
            "secure_boot_state", "Secure Boot", "state", CATEGORY_SECURITY,
            scale=_PROTECTION_SCALE,
        ),
        Metric(
            "signature_age_days", "Antivirus signature age (days)", "count", CATEGORY_SECURITY
        ),
        Metric(
            "restart_pending", "Pending Windows restart", "state", CATEGORY_MAINTENANCE,
            scale=_RESTART_SCALE,
        ),
        Metric(
            "drive_self_assessment", "Drive self-assessment", "state", CATEGORY_STORAGE,
            scale=_DRIVE_HEALTH_SCALE,
        ),
        Metric("drive_life_left", "Drive life remaining", "percent", CATEGORY_STORAGE, "below"),
        Metric(
            "battery_health", "Battery capacity remaining", "percent", CATEGORY_POWER, "below"
        ),
    )
}

#: Display order and English labels of the sub-scores.
CATEGORY_LABELS: tuple[tuple[str, str], ...] = (
    (CATEGORY_CPU, "CPU"),
    (CATEGORY_MEMORY, "Memory"),
    (CATEGORY_STORAGE, "Storage"),
    (CATEGORY_MAINTENANCE, "Maintenance"),
    (CATEGORY_POWER, "Power"),
    (CATEGORY_SECURITY, "Security"),
)

_UNIT_FORMATTERS = {
    "percent": format_percent,
    "bytes": format_bytes,
    "count": format_count,
    "duration": format_uptime,
}


@dataclass(frozen=True, slots=True)
class ScoreRule:
    """One row of the published score table."""

    key: str
    #: mild | standard | high | severe. ``standard`` is the threshold published in v1.0.
    tier: str
    points: int
    metric: str
    threshold: float
    severity: str

    @property
    def category(self) -> str:
        return METRICS[self.metric].category

    @property
    def direction(self) -> str:
        return METRICS[self.metric].direction

    @property
    def unit(self) -> str:
        return METRICS[self.metric].unit

    @property
    def metric_label(self) -> str:
        return METRICS[self.metric].label

    @property
    def reason_template(self) -> str:
        return DEDUCTION_TEMPLATES.get(self.key, "{value}")

    @property
    def condition(self) -> str:
        """One-line description of the row, for the README and in-app documentation."""
        metric = METRICS[self.metric]
        if metric.scale:
            # "Antivirus protection is at risk or worse" says what a threshold of 0.5 on a
            # ladder means; "above 0.5" would be a number nobody can check a PC against.
            caught = metric.caught(self.threshold)
            suffix = "" if caught == metric.scale[0][1] else " or worse"
            return f"{metric.label} is {caught}{suffix}"
        return f"{self.metric_label} {self.direction} {self.format_value(self.threshold)}"

    def format_value(self, value: float | None) -> str:
        return METRICS[self.metric].render(value)

    def matches(self, value: float | None) -> bool:
        if value is None:  # Unknown is never penalised.
            return False
        if self.direction == "below":
            return value < self.threshold
        return value > self.threshold


#: The complete score table, grouped by key and ordered mild -> severe. The ``standard``
#: tier of the first six keys is exactly the penalty published for v1.0.
SCORE_RULES: tuple[ScoreRule, ...] = (
    ScoreRule("high_cpu", "mild", 6, "cpu_percent", 55.0, "info"),
    ScoreRule("high_cpu", "standard", 15, "cpu_percent", 70.0, "warning"),
    ScoreRule("high_cpu", "high", 22, "cpu_percent", 85.0, "warning"),
    ScoreRule("high_cpu", "severe", 28, "cpu_percent", 95.0, "critical"),
    ScoreRule("high_ram", "mild", 8, "ram_percent", 70.0, "info"),
    ScoreRule("high_ram", "standard", 20, "ram_percent", 80.0, "warning"),
    ScoreRule("high_ram", "high", 28, "ram_percent", 90.0, "critical"),
    ScoreRule("high_ram", "severe", 34, "ram_percent", 95.0, "critical"),
    ScoreRule("high_swap", "mild", 4, "swap_percent", 50.0, "info"),
    ScoreRule("high_swap", "standard", 10, "swap_percent", 75.0, "warning"),
    ScoreRule("high_swap", "severe", 16, "swap_percent", 90.0, "critical"),
    ScoreRule("low_disk", "mild", 8, "disk_free_bytes", 50 * GIB, "info"),
    ScoreRule("low_disk", "standard", 20, "disk_free_bytes", 20 * GIB, "warning"),
    ScoreRule("low_disk", "high", 26, "disk_free_bytes", 10 * GIB, "critical"),
    ScoreRule("low_disk", "severe", 32, "disk_free_bytes", 5 * GIB, "critical"),
    ScoreRule("disk_nearly_full", "mild", 5, "disk_usage_percent", 85.0, "info"),
    ScoreRule("disk_nearly_full", "standard", 12, "disk_usage_percent", 92.0, "warning"),
    ScoreRule("disk_nearly_full", "severe", 18, "disk_usage_percent", 97.0, "critical"),
    ScoreRule("many_processes", "mild", 4, "process_count", 150, "info"),
    ScoreRule("many_processes", "standard", 10, "process_count", 180, "warning"),
    ScoreRule("many_processes", "high", 14, "process_count", 250, "warning"),
    ScoreRule("many_processes", "severe", 18, "process_count", 350, "warning"),
    ScoreRule("large_temp", "mild", 4, "temp_bytes", GIB, "info"),
    ScoreRule("large_temp", "standard", 10, "temp_bytes", 3 * GIB, "warning"),
    ScoreRule("large_temp", "high", 14, "temp_bytes", 10 * GIB, "warning"),
    ScoreRule("large_temp", "severe", 18, "temp_bytes", 25 * GIB, "warning"),
    ScoreRule("long_uptime", "mild", 2, "uptime_seconds", 24 * HOUR, "info"),
    ScoreRule("long_uptime", "standard", 5, "uptime_seconds", 48 * HOUR, "warning"),
    ScoreRule("long_uptime", "high", 8, "uptime_seconds", 168 * HOUR, "warning"),
    ScoreRule("long_uptime", "severe", 10, "uptime_seconds", 336 * HOUR, "warning"),
    ScoreRule("many_startup_items", "mild", 3, "startup_count", 12, "info"),
    ScoreRule("many_startup_items", "standard", 6, "startup_count", 20, "warning"),
    ScoreRule("many_startup_items", "severe", 10, "startup_count", 30, "warning"),
    ScoreRule("low_battery", "mild", 2, "battery_low", 25.0, "info"),
    ScoreRule("low_battery", "standard", 4, "battery_low", 15.0, "warning"),
    ScoreRule("low_battery", "severe", 6, "battery_low", 7.0, "critical"),
    # --- v2.1 ---
    # An unguarded PC is the worst thing this application can find, so antivirus_off carries
    # the heaviest penalty in the table: a machine with nothing watching it must not be able
    # to read "Excellent" no matter how idle it is. "at risk" is the Security Center's own
    # verdict for protection that is paused or out of date, which is bad but not absent.
    ScoreRule("antivirus_off", "standard", 30, "antivirus_state", _WORSE_THAN_GOOD, "critical"),
    ScoreRule("antivirus_off", "severe", 40, "antivirus_state", _WORSE_THAN_WEAK, "critical"),
    ScoreRule("firewall_off", "standard", 12, "firewall_state", _WORSE_THAN_GOOD, "warning"),
    ScoreRule("firewall_off", "severe", 18, "firewall_state", _WORSE_THAN_WEAK, "warning"),
    # A scanner only recognises what its definitions describe. A week is the point at which
    # the gap stops being ordinary; a month is a scanner that has effectively stopped working.
    ScoreRule("stale_signatures", "standard", 8, "signature_age_days", 7, "warning"),
    ScoreRule("stale_signatures", "severe", 14, "signature_age_days", 30, "warning"),
    # Housekeeping, not danger: the fix is a restart the user was going to do anyway.
    ScoreRule("reboot_pending", "standard", 3, "restart_pending", _FLAG_RAISED, "info"),
    # The drive's own controller raised its critical warning. That is the drive stating its
    # condition, not this application predicting anything, which is why it is charged in full.
    ScoreRule("drive_failing", "standard", 25, "drive_self_assessment", _FLAG_RAISED, "critical"),
    # Wear is gradual and normal, so the reaction is too. The figure is the drive's estimate
    # of the write endurance it was designed for - a worn drive still works.
    ScoreRule("drive_worn", "mild", 4, "drive_life_left", 30.0, "info"),
    ScoreRule("drive_worn", "standard", 10, "drive_life_left", 20.0, "warning"),
    ScoreRule("drive_worn", "severe", 18, "drive_life_left", 10.0, "critical"),
    # Battery wear is ageing rather than a fault, so it costs little: it explains a short
    # runtime honestly without pretending the PC is unhealthy.
    ScoreRule("battery_worn", "mild", 3, "battery_health", 70.0, "info"),
    ScoreRule("battery_worn", "standard", 6, "battery_health", 60.0, "warning"),
    ScoreRule("battery_worn", "severe", 10, "battery_health", 50.0, "warning"),
)

#: Evaluation order of the deduction keys, derived from the table so the two cannot drift.
_KEY_ORDER: tuple[str, ...] = tuple(dict.fromkeys(rule.key for rule in SCORE_RULES))


def score_rules() -> tuple[ScoreRule, ...]:
    """Return the rule rows for documentation, grouped by key and ordered mild -> severe."""
    return tuple(sorted(SCORE_RULES, key=lambda rule: (_KEY_ORDER.index(rule.key), rule.points)))


def most_worn_drive(drives: Sequence[DriveHealth]) -> DriveHealth | None:
    """
    The drive with the least life left, or None when no drive reported a wear figure.

    One deduction per snapshot, not one per disk: a PC with two worn drives has one problem
    to act on, and charging twice for it would make the score depend on how many disks are
    fitted. Advice imports this same selector, so both name the same drive.
    """
    ranked = [drive for drive in drives if drive.life_left_percent is not None]
    if not ranked:
        return None
    # The drive letter breaks ties, so two equally worn disks always report in the same order.
    ranked.sort(key=lambda drive: (int(drive.life_left_percent or 0), str(drive.drive or "")))
    return ranked[0]


def failing_drive(drives: Sequence[DriveHealth]) -> DriveHealth | None:
    """The first drive that raised its own critical warning, in a deterministic order."""
    flagged = sorted(
        (drive for drive in drives if drive.critical_warning is True),
        key=lambda drive: str(drive.drive or ""),
    )
    return flagged[0] if flagged else None


def state_level(state: object) -> float | None:
    """Place a protection verdict on the ladder. Unknown and unrecognised both read None."""
    if not isinstance(state, str):
        return None
    return STATE_LEVELS.get(state)


def get_score_status(score: int) -> str:
    score = max(0, min(100, int(score)))
    for minimum, status in STATUS_BANDS:
        if score >= minimum:
            return status
    return STATUS_BANDS[-1][1]


def required_values_present(data: AnalysisData) -> bool:
    """The one definition of "this snapshot was measured completely".

    The score, the ``data_complete`` flag and the ``incomplete_data`` advice all read this
    single predicate, so no report can call a snapshot complete in one place and incomplete
    in another. A truncated TEMP scan counts as absent: it produced a lower bound, and a
    lower bound is not the measurement the rule table asks for.
    """
    required = (
        data.cpu.usage_percent,
        data.ram.usage_percent,
        data.disk.free_bytes,
        data.process_count,
        data.temp_size_bytes,
        data.uptime_seconds,
    )
    return all(value is not None for value in required) and not data.temp_truncated


def calculate_health_details(data: AnalysisData) -> HealthAssessment:
    """Score one snapshot. Missing values reduce coverage, never the score."""
    values, context, details = _read_metrics(data)
    # A partial TEMP size can only under-report, so the rule may still fire - firing on a
    # floor is always at least as accurate as staying silent. Only the wording changes.
    lower_bounds = frozenset({"temp_bytes"}) if data.temp_truncated else frozenset()

    deductions = [
        _to_deduction(
            rule,
            values.get(rule.metric),
            # A metric may name the thing it measured - which disk is worn, for instance -
            # and that name overrides the snapshot-wide default for its own rule only.
            {**context, **details.get(rule.metric, {})},
            lower_bounds,
        )
        for rule in _fire_rules(values)
    ]
    # Stable order: worst severity first, then the heavier penalty, then the key.
    deductions.sort(key=lambda item: (-severity_rank(item.severity), -item.points, item.key))

    score = max(0, 100 - sum(item.points for item in deductions))
    return HealthAssessment(
        score=score,
        status=get_score_status(score),
        deductions=tuple(deductions),
        data_complete=required_values_present(data),
        categories=_build_categories(deductions, values),
    )


def calculate_health_score(data: AnalysisData) -> tuple[int, str]:
    """Compatibility API described in the project plan."""
    result = calculate_health_details(data)
    return result.score, result.status


def _fire_rules(values: dict[str, float | None]) -> list[ScoreRule]:
    """Pick at most one tier per key: the worst tier whose threshold is crossed."""
    fired: list[ScoreRule] = []
    for key in _KEY_ORDER:
        worst: ScoreRule | None = None
        for rule in SCORE_RULES:
            if rule.key != key or not rule.matches(values.get(rule.metric)):
                continue
            if worst is None or rule.points > worst.points:
                worst = rule
        if worst is not None:
            fired.append(worst)

    # low_disk (absolute free bytes) and disk_nearly_full (percentage) describe the same
    # drive from two angles, so charging for both would punish one problem twice. The
    # percentage rule therefore only covers what the byte rule misses: a large drive that
    # is almost full yet still has more than 20 GB free.
    if any(rule.key == "low_disk" for rule in fired):
        fired = [rule for rule in fired if rule.key != "disk_nearly_full"]
    return fired


def _to_deduction(
    rule: ScoreRule,
    value: float | None,
    context: dict[str, str],
    lower_bounds: frozenset[str] = frozenset(),
) -> ScoreDeduction:
    measurement = rule.format_value(value)
    bounded = rule.metric in lower_bounds
    substitutions = {"value": measurement, **context}
    template = rule.reason_template

    # The params carry the plain measurement plus a language-neutral marker, so the
    # qualifier is worded once by the renderer in the reader's language. Only the fallback
    # sentence spells it out here, because that path has no translator to ask.
    reason_values = dict(substitutions)
    if bounded:
        reason_values["value"] = english_lower_bound(measurement)
    params = _params_for(template, substitutions)
    if bounded:
        params = (*params, LOWER_BOUND_PARAM)

    return ScoreDeduction(
        key=rule.key,
        points=rule.points,
        reason=_safe_format(template, reason_values),
        category=rule.category,
        severity=rule.severity,
        params=params,
    )


def _build_categories(
    deductions: list[ScoreDeduction], values: dict[str, float | None]
) -> tuple[CategoryScore, ...]:
    categories: list[CategoryScore] = []
    for key, label in CATEGORY_LABELS:
        inputs = [name for name, metric in METRICS.items() if metric.category == key]
        owned = tuple(item for item in deductions if item.category == key)
        lost = sum(item.points for item in owned)
        categories.append(
            CategoryScore(
                key=key,
                label=label,
                score=max(0, min(100, 100 - lost)),
                deductions=owned,
                # A category nobody could measure keeps a nominal 100 but is flagged
                # unavailable, so no interface reports a clean bill of health it never got.
                available=any(values.get(name) is not None for name in inputs),
            )
        )
    return tuple(categories)


def _read_metrics(
    data: AnalysisData,
) -> tuple[dict[str, float | None], dict[str, str], dict[str, dict[str, str]]]:
    """Flatten the snapshot into exactly the numbers the rule table asks for.

    Returns the readings, the substitutions every reason may use, and the substitutions that
    belong to one metric alone (the drive a wear figure came from, for instance).
    """
    disk = data.disk
    disk_usage = _as_float(disk.usage_percent)
    if disk_usage is None:
        # usage_percent is optional in older snapshots; deriving it from two measured
        # numbers is arithmetic, not invention.
        total = _as_float(disk.total_bytes)
        used = _as_float(disk.used_bytes)
        if total is not None and used is not None and total > 0:
            disk_usage = used / total * 100.0

    swap_total = _as_float(data.ram.swap_total_bytes)
    swap_percent = _as_float(data.ram.swap_percent)
    if swap_total is None or swap_total < MIN_MEANINGFUL_SWAP_BYTES:
        swap_percent = None

    battery = data.battery
    battery_percent = _as_float(battery.percent) if battery is not None else None
    # Battery level is only a finding while the PC is actually discharging: a plugged-in
    # laptop at 20% is charging, not in trouble.
    on_battery = battery is not None and battery.plugged_in is False

    security = data.security
    worn = most_worn_drive(data.drive_health)
    failing = failing_drive(data.drive_health)

    values: dict[str, float | None] = {
        "cpu_percent": _as_float(data.cpu.usage_percent),
        "ram_percent": _as_float(data.ram.usage_percent),
        "swap_percent": swap_percent,
        "disk_free_bytes": _as_float(disk.free_bytes),
        "disk_usage_percent": disk_usage,
        "process_count": _as_float(data.process_count),
        "temp_bytes": _as_float(data.temp_size_bytes),
        "uptime_seconds": _as_float(data.uptime_seconds),
        "startup_count": float(len(data.startup_items)) if data.startup_items else None,
        "battery_percent": battery_percent,
        "battery_low": battery_percent if on_battery else None,
        "antivirus_state": state_level(security.antivirus) if security is not None else None,
        "firewall_state": state_level(security.firewall) if security is not None else None,
        "secure_boot_state": state_level(security.secure_boot) if security is not None else None,
        "signature_age_days": (
            _as_float(security.signature_age_days) if security is not None else None
        ),
        "restart_pending": _flag_level(security.reboot_pending) if security is not None else None,
        "drive_self_assessment": _drive_warning_level(data.drive_health),
        "drive_life_left": float(worn.life_left_percent or 0) if worn is not None else None,
        "battery_health": _as_float(battery.health_percent) if battery is not None else None,
    }

    details: dict[str, dict[str, str]] = {}
    if worn is not None:
        details["drive_life_left"] = {"drive": _drive_label(worn.drive)}
    if failing is not None:
        details["drive_self_assessment"] = {"drive": _drive_label(failing.drive)}
    return values, {"drive": _drive_label(disk.drive)}, details


def _flag_level(flag: object) -> float | None:
    """Place a yes/no reading on the flag ladder. Anything that is not a bool is unknown."""
    if not isinstance(flag, bool):
        return None
    return 1.0 if flag else 0.0


def _drive_warning_level(drives: Sequence[DriveHealth]) -> float | None:
    """
    Whether any drive raised its critical warning.

    Stays None until at least one drive actually answered the question, because "no drive
    told us" and "every drive said it is fine" are different facts: only the second one may
    report the Storage area as measured.
    """
    answers = [
        drive.critical_warning
        for drive in drives
        if isinstance(drive.critical_warning, bool)
    ]
    if not answers:
        return None
    return 1.0 if any(answers) else 0.0


def _drive_label(drive: str | None) -> str:
    if not drive:
        return "the system drive"
    label = str(drive).strip().rstrip("\\/")
    return label or "the system drive"


def _format_measurement(unit: str, value: float | None) -> str:
    formatter = _UNIT_FORMATTERS.get(unit, format_count)
    try:
        return formatter(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        # OverflowError: int() rejects a non-finite float, and a renderer must never raise.
        return "N/A"


def _scale_word(scale: tuple[tuple[float, str], ...], value: float | None) -> str:
    """Quote a reading that is a state: the worst rung the value has reached."""
    if value is None or not scale:
        return "N/A"
    for level, word in scale:  # Worst rung first.
        if value >= level:
            return word
    return scale[-1][1]


def _params_for(template: str, substitutions: dict[str, str]) -> tuple[tuple[str, str], ...]:
    """Carry exactly the placeholders the sentence uses, so text and params cannot drift."""
    names: list[str] = []
    try:
        for _, field, _, _ in Formatter().parse(template):
            if field and field in substitutions and field not in names:
                names.append(field)
    except (ValueError, AttributeError):
        return ()
    return tuple((name, substitutions[name]) for name in names)


def _safe_format(template: str, substitutions: dict[str, str]) -> str:
    try:
        return template.format(**substitutions)
    except (KeyError, IndexError, ValueError):
        return template


def _as_float(value: object) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    # NaN and infinity are not measurements: a NaN silently loses every comparison and an
    # infinity breaks the integer formatters, so both are treated as "unknown" instead.
    return number if math.isfinite(number) else None
