"""Opt-in local history of past analysis runs.

The store is a JSON Lines file: one small object per run, newest last. Only the numeric
summary and the score label are kept - never paths, process names, host names, or serial
numbers - so the file stays safe to keep, easy to read, and trivial to delete.

Nothing in this module runs unless the caller explicitly asks for it. This is the only
file the application ever writes without an export request, and it is created only after
an explicit opt-in (``--save-history`` on the console).
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .models import AnalysisData, HealthAssessment

#: How many runs the store keeps by default. Roughly a year of daily checks.
DEFAULT_MAX_ENTRIES = 200


@dataclass(frozen=True, slots=True)
class HistoryEntry:
    """One stored run. Deliberately numbers only, so the file carries no private data."""

    analyzed_at: datetime
    score: int
    status: str
    cpu_percent: float | None = None
    ram_percent: float | None = None
    disk_free_bytes: int | None = None
    temp_size_bytes: int | None = None
    process_count: int | None = None
    uptime_seconds: float | None = None


@dataclass(frozen=True, slots=True)
class HistoryDelta:
    """Difference between the current run and the newest stored run before it."""

    previous: HistoryEntry
    score_delta: int
    cpu_delta: float | None = None
    ram_delta: float | None = None
    disk_free_delta: int | None = None


def default_history_path() -> Path:
    """Return the standard store location. Never raises, never creates anything."""
    base = os.environ.get("LOCALAPPDATA", "").strip()
    if base:
        root = Path(base)
    else:
        # Non-Windows systems (and stripped-down Windows sessions) keep it under $HOME.
        try:
            root = Path.home()
        except (OSError, RuntimeError):
            root = Path(".")
    return root / "Apoliak" / "Vitals" / "history.jsonl"


def append_snapshot(
    data: AnalysisData,
    assessment: HealthAssessment,
    *,
    path: str | os.PathLike[str] | None = None,
    max_entries: int = DEFAULT_MAX_ENTRIES,
) -> Path:
    """
    Append one run summary and keep only the newest ``max_entries`` records.

    The file is rewritten from the records that still parse, so a truncated or hand-edited
    line is dropped instead of breaking the store. The rewrite goes through a sibling
    temporary file and an atomic replace, so an interrupted run cannot destroy the history.

    A genuinely unwritable target (missing permission, read-only folder, a directory in the
    way) raises ``OSError`` on purpose: history is opt-in, and a caller that asked for it
    deserves to hear that it did not happen. Corrupt *content* never raises.
    """
    target = _resolve(path)
    keep = max(1, int(max_entries))
    kept = load_history(path=target)[-(keep - 1) :] if keep > 1 else []
    records = (*kept, _entry_from_snapshot(data, assessment))
    payload = "".join(f"{_to_json(entry)}\n" for entry in records)

    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f"{target.name}.tmp")
    try:
        temporary.write_text(payload, encoding="utf-8")
        os.replace(temporary, target)
    except OSError:
        try:  # Do not leave a stray temporary file behind on a failed write.
            temporary.unlink()
        except OSError:
            pass
        raise
    return _resolved_or_original(target)


def load_history(
    *,
    path: str | os.PathLike[str] | None = None,
    limit: int | None = None,
) -> list[HistoryEntry]:
    """
    Read stored runs, oldest first.

    A missing file, an unreadable file, and unparsable lines all mean "no data" - reading
    history must never interrupt or fail an analysis. ``limit`` keeps the newest N records
    while preserving the oldest-first order.
    """
    try:
        raw = _resolve(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return []

    entries: list[HistoryEntry] = []
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except (TypeError, ValueError):
            continue
        entry = _entry_from_payload(payload)
        if entry is not None:
            entries.append(entry)

    if limit is not None:
        try:
            count = int(limit)
        except (TypeError, ValueError):
            count = 0
        if count > 0:
            entries = entries[-count:]
    return entries


def compare_to_previous(
    data: AnalysisData,
    assessment: HealthAssessment,
    *,
    path: str | os.PathLike[str] | None = None,
    history: Iterable[HistoryEntry] | None = None,
) -> HistoryDelta | None:
    """
    Compare this run against the newest stored run that is not this run itself.

    Returns ``None`` when nothing usable is stored yet, so a first run simply says nothing
    instead of inventing a trend. ``history`` lets callers (and tests) supply the records
    directly instead of reading the file twice.
    """
    entries = list(history) if history is not None else load_history(path=path)
    current = _entry_from_snapshot(data, assessment)

    previous: HistoryEntry | None = None
    for entry in reversed(entries):
        # The current run may already be stored; identical timestamps mean the same run.
        if entry.analyzed_at == current.analyzed_at:
            continue
        previous = entry
        break

    if previous is None:
        return None
    return HistoryDelta(
        previous=previous,
        score_delta=current.score - previous.score,
        cpu_delta=_difference(current.cpu_percent, previous.cpu_percent),
        ram_delta=_difference(current.ram_percent, previous.ram_percent),
        disk_free_delta=_integer_difference(current.disk_free_bytes, previous.disk_free_bytes),
    )


def _resolve(path: str | os.PathLike[str] | None) -> Path:
    if path is None:
        return default_history_path()
    return Path(os.fspath(path)).expanduser()


def _resolved_or_original(target: Path) -> Path:
    try:
        return target.resolve()
    except OSError:
        return target


def _entry_from_snapshot(data: AnalysisData, assessment: HealthAssessment) -> HistoryEntry:
    return HistoryEntry(
        analyzed_at=data.analyzed_at,
        score=int(assessment.score),
        status=str(assessment.status),
        cpu_percent=_as_float(data.cpu.usage_percent),
        ram_percent=_as_float(data.ram.usage_percent),
        disk_free_bytes=_as_int(data.disk.free_bytes),
        temp_size_bytes=_as_int(data.temp_size_bytes),
        process_count=_as_int(data.process_count),
        uptime_seconds=_as_float(data.uptime_seconds),
    )


def _entry_from_payload(payload: Any) -> HistoryEntry | None:
    """Build an entry from one decoded line, or ``None`` when the line is not usable."""
    if not isinstance(payload, dict):
        return None
    moment = _parse_datetime(payload.get("analyzed_at"))
    score = _as_int(payload.get("score"))
    if moment is None or score is None:
        return None
    return HistoryEntry(
        analyzed_at=moment,
        score=score,
        status=str(payload.get("status") or "Unknown"),
        cpu_percent=_as_float(payload.get("cpu_percent")),
        ram_percent=_as_float(payload.get("ram_percent")),
        disk_free_bytes=_as_int(payload.get("disk_free_bytes")),
        temp_size_bytes=_as_int(payload.get("temp_size_bytes")),
        process_count=_as_int(payload.get("process_count")),
        uptime_seconds=_as_float(payload.get("uptime_seconds")),
    )


def _to_json(entry: HistoryEntry) -> str:
    record = {
        "analyzed_at": _isoformat(entry.analyzed_at),
        "score": int(entry.score),
        "status": str(entry.status),
        "cpu_percent": entry.cpu_percent,
        "ram_percent": entry.ram_percent,
        "disk_free_bytes": entry.disk_free_bytes,
        "temp_size_bytes": entry.temp_size_bytes,
        "process_count": entry.process_count,
        "uptime_seconds": entry.uptime_seconds,
    }
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False)


def _isoformat(moment: Any) -> str:
    try:
        return moment.isoformat()
    except Exception:
        return str(moment)


def _parse_datetime(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):  # Python 3.10 cannot parse the military zone suffix.
        text = f"{text[:-1]}+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _as_float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    # NaN and infinity cannot survive a JSON round trip, so they are treated as unknown.
    return number if math.isfinite(number) else None


def _as_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return int(number) if math.isfinite(number) else None


def _difference(current: float | None, previous: float | None) -> float | None:
    if current is None or previous is None:
        return None
    return float(current) - float(previous)


def _integer_difference(current: int | None, previous: int | None) -> int | None:
    if current is None or previous is None:
        return None
    return int(current) - int(previous)
