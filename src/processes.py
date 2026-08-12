"""Read-only ranking of the running processes.

The list is informational only: nothing here suspends, terminates, or changes a process.
Any process that disappears or refuses access while the list is being built is skipped,
because a partial ranking is far more useful than an exception.
"""

from __future__ import annotations

import time
from typing import Any

from .models import ProcessInfo

try:
    import psutil as _psutil
except ImportError:  # The caller decides how to report a missing dependency.
    _psutil = None  # type: ignore[assignment]

#: Gap between the two CPU samples. psutil reports 0.0 on the first call per process, so a
#: second reading is required; anything longer than this would noticeably slow the analysis.
CPU_SAMPLE_SECONDS = 0.15

_SORT_KEYS = ("memory", "cpu")
_PROCESS_ATTRS = ["pid", "name", "memory_info", "memory_percent"]


def top_processes(
    psutil_module: Any | None = None,
    *,
    limit: int = 5,
    sort_by: str = "memory",
    sample_cpu: bool = False,
) -> list[ProcessInfo]:
    """
    Return the heaviest processes, ordered by RSS memory or by CPU share.

    ``sample_cpu`` fills in the CPU column without changing the ranking, which is what a
    memory-sorted report needs: the two readings cost one shared ``CPU_SAMPLE_SECONDS``
    pause for the whole list, not one per process. A CPU ranking always samples, so the
    flag can only ever turn sampling on.

    CPU percentages are divided by the logical core count so they match what Task Manager
    shows. Never raises: an unusable psutil module yields an empty list.
    """
    if limit <= 0:
        return []

    module = psutil_module if psutil_module is not None else _psutil
    if module is None:
        return []

    mode = sort_by.lower() if isinstance(sort_by, str) else "memory"
    if mode not in _SORT_KEYS:
        mode = "memory"
    measure_cpu = bool(sample_cpu) or mode == "cpu"

    process_iter = getattr(module, "process_iter", None)
    if not callable(process_iter):
        return []

    try:
        handles, entries = _collect(process_iter, keep_handles=measure_cpu)
    except Exception:
        return []

    # Negating the metric instead of reverse=True keeps the name tie-break alphabetical.
    if mode == "cpu":
        # The ranking itself needs a number for every process, so all of them are sampled.
        entries = _sample_cpu(module, handles, entries)
        entries.sort(key=lambda item: (-(item.cpu_percent or 0.0), item.name.lower(), item.pid))
        return entries[:limit]

    entries.sort(key=lambda item: (-(item.memory_bytes or 0), item.name.lower(), item.pid))
    ranked = entries[:limit]
    # Sampling after the ranking is what keeps this affordable: only the handful of
    # processes actually shown are queried, instead of every process on the machine.
    return _sample_cpu(module, handles, ranked) if measure_cpu else ranked


def _collect(process_iter: Any, *, keep_handles: bool) -> tuple[list[Any], list[ProcessInfo]]:
    """Walk the process table once, keeping the live handles when the CPU will be sampled."""
    handles: list[Any] = []
    entries: list[ProcessInfo] = []

    try:
        iterator = iter(process_iter(attrs=_PROCESS_ATTRS, ad_value=None))
    except Exception:
        return handles, entries

    while True:
        # A failing iterator ends the walk but keeps everything collected so far.
        try:
            process = next(iterator)
        except StopIteration:
            break
        except Exception:
            break
        # Per-item guard: processes routinely die mid-iteration, and a fake psutil used by
        # the tests may not expose NoSuchProcess/AccessDenied at all.
        try:
            info = getattr(process, "info", None) or {}
            pid = int(info.get("pid"))
            if pid <= 0:  # PID 0 is the synthetic idle process, not a real program.
                continue
            memory_info = info.get("memory_info")
            memory_bytes = int(getattr(memory_info, "rss", 0)) if memory_info else None
            memory_percent = info.get("memory_percent")
            entries.append(
                ProcessInfo(
                    pid=pid,
                    name=str(info.get("name") or f"PID {pid}"),
                    cpu_percent=None,
                    memory_bytes=memory_bytes,
                    memory_percent=float(memory_percent) if memory_percent is not None else None,
                )
            )
            if keep_handles:
                handles.append(process)
        except Exception:
            continue
    return handles, entries


def _sample_cpu(module: Any, handles: list[Any], entries: list[ProcessInfo]) -> list[ProcessInfo]:
    """
    Measure the CPU share of the processes in ``entries`` and fold it into them.

    psutil returns 0.0 the first time it is asked about a process, so a counter has to be
    primed and read again a moment later. Priming every wanted process before the single
    shared pause gives them all the same measurement window and costs one wait for the
    whole list.
    """
    if not handles or not entries:
        return entries

    wanted = {entry.pid for entry in entries}
    primed: list[Any] = []
    for process in handles:
        try:
            if int(process.pid) not in wanted:  # Nobody will see this one; do not pay for it.
                continue
            process.cpu_percent()  # First call only primes the counter and returns 0.0.
        except Exception:
            continue
        primed.append(process)
    if not primed:
        return entries

    try:
        time.sleep(CPU_SAMPLE_SECONDS)
    except Exception:
        pass

    cores = _logical_cores(module)
    measured: dict[int, float] = {}
    for process in primed:
        try:
            pid = int(process.pid)
            value = float(process.cpu_percent())
        except Exception:
            continue
        measured[pid] = max(0.0, min(100.0, value / cores))

    return [
        ProcessInfo(
            pid=entry.pid,
            name=entry.name,
            cpu_percent=measured.get(entry.pid),
            memory_bytes=entry.memory_bytes,
            memory_percent=entry.memory_percent,
        )
        for entry in entries
    ]


def _logical_cores(module: Any) -> int:
    """Logical core count used to scale CPU percentages; falls back to 1 when unknown."""
    try:
        cores = module.cpu_count(logical=True)
    except Exception:
        return 1
    try:
        return max(1, int(cores))
    except (TypeError, ValueError):
        return 1
