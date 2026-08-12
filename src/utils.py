"""Small, dependency-free helpers used throughout the application."""

from __future__ import annotations

import os
import re
import stat
import sys
import time
from pathlib import Path

KIB = 1024
MIB = KIB**2
GIB = KIB**3
TIB = KIB**4

#: Default wall-clock budget for one folder scan. TEMP can hold millions of entries.
DEFAULT_SCAN_SECONDS = 12.0


def bytes_to_gb(value: int | float | None) -> float | None:
    """Convert bytes to gibibytes (the value Windows commonly labels as GB)."""
    if value is None:
        return None
    return float(value) / GIB


def format_bytes(value: int | float | None) -> str:
    """Return a compact human-readable binary size or N/A."""
    if value is None:
        return "N/A"

    size = max(0.0, float(value))
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if size < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} {unit}"
            return f"{size:.1f} {unit}"
        size /= 1024
    return "N/A"


def format_percent(value: int | float | None) -> str:
    if value is None:
        return "N/A"
    value = max(0.0, min(100.0, float(value)))
    return f"{value:.0f}%"


def format_uptime(seconds: int | float | None) -> str:
    """Format uptime as days, hours, and minutes."""
    if seconds is None:
        return "N/A"

    total_minutes = max(0, int(seconds)) // 60
    days, remainder = divmod(total_minutes, 24 * 60)
    hours, minutes = divmod(remainder, 60)

    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def format_frequency(megahertz: int | float | None) -> str:
    """Format a CPU frequency, switching to GHz once the number gets long."""
    if megahertz is None or float(megahertz) <= 0:
        return "N/A"
    value = float(megahertz)
    if value >= 1000:
        return f"{value / 1000:.2f} GHz"
    return f"{value:.0f} MHz"


def format_count(value: int | None) -> str:
    """Format a whole number with thin thousands separators, or N/A."""
    if value is None:
        return "N/A"
    return f"{int(value):,}".replace(",", " ")


def format_duration(seconds: int | float | None) -> str:
    """Format a short duration such as an analysis run or a battery estimate."""
    if seconds is None:
        return "N/A"
    total = max(0, int(seconds))
    if total < 60:
        return f"{max(0.0, float(seconds)):.1f} s"
    hours, remainder = divmod(total, 3600)
    minutes = remainder // 60
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


# Unanchored on purpose: a profile path is just as identifying in the middle of a quoted
# startup command as it is at the start of a bare path.
_USER_PATH_PATTERN = re.compile(r"(?i)([a-z]:[\\/]users[\\/])([^\\/\"'<>|]+)")


def redact_text(value: str | None, username: str | None = None) -> str | None:
    """
    Replace the Windows account name in a string so a report can be shared safely.

    Only the profile-name segment is masked; the rest of the path stays useful.
    """
    if not value:
        return value

    result = _USER_PATH_PATTERN.sub(lambda match: f"{match.group(1)}<user>", value)
    account = username if username is not None else os.environ.get("USERNAME", "")
    if account and len(account) >= 3:
        result = re.sub(re.escape(account), "<user>", result, flags=re.IGNORECASE)
    return result


def _is_reparse_point(entry: os.DirEntry[str]) -> bool:
    """Detect Windows junctions/reparse points so directory walking stays local."""
    try:
        info = entry.stat(follow_symlinks=False)
    except OSError:
        return True
    attributes = getattr(info, "st_file_attributes", 0)
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return bool(flag and attributes & flag)


def scan_folder(
    path: str | os.PathLike[str],
    *,
    max_seconds: float | None = DEFAULT_SCAN_SECONDS,
    monotonic: object = None,
) -> tuple[int, int, bool]:
    """
    Measure a folder without following links.

    Returns ``(total_bytes, file_count, truncated)``. ``truncated`` is true when the time
    budget ran out, so callers can label the number as a partial measurement instead of
    silently reporting a size that is too small.

    Unreadable, disappearing, and protected files are skipped. This matters for TEMP,
    where files often change while the scan is running.
    """
    clock = monotonic if callable(monotonic) else time.monotonic
    deadline = None if max_seconds is None else clock() + max(0.0, float(max_seconds))

    root = Path(path)
    try:
        if root.is_file():
            try:
                return root.stat().st_size, 1, False
            except OSError:
                return 0, 0, False
        if not root.exists():
            return 0, 0, False
    except OSError:
        return 0, 0, False

    total = 0
    files = 0
    checked = 0
    pending = [os.fspath(root)]
    while pending:
        current = pending.pop()
        # Also checked per directory: a folder on a stalled network share can hold fewer
        # entries than the sampling stride and would otherwise never test the deadline.
        if deadline is not None and clock() > deadline:
            return total, files, True
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    checked += 1
                    # Checking the clock every entry would cost more than the scan itself.
                    if deadline is not None and checked % 128 == 0 and clock() > deadline:
                        return total, files, True
                    try:
                        if entry.is_symlink() or _is_reparse_point(entry):
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                            files += 1
                    except (OSError, PermissionError):
                        continue
        except (OSError, PermissionError):
            continue
    return total, files, False


def safe_get_folder_size(
    path: str | os.PathLike[str],
    *,
    max_seconds: float | None = DEFAULT_SCAN_SECONDS,
) -> int:
    """Backwards-compatible wrapper returning only the total size in bytes."""
    total, _, _ = scan_folder(path, max_seconds=max_seconds)
    return total


class Ansi:
    """Minimal ANSI colouring for the console report, disabled when unsupported."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"

    def __init__(self, enabled: bool = True) -> None:
        self.enabled = bool(enabled)

    def paint(self, text: str, *codes: str) -> str:
        if not self.enabled or not codes:
            return text
        return f"{''.join(codes)}{text}{self.RESET}"

    def bold(self, text: str) -> str:
        return self.paint(text, self.BOLD)

    def dim(self, text: str) -> str:
        return self.paint(text, self.DIM)


def supports_color(stream: object | None = None) -> bool:
    """Report whether ANSI colour is safe to emit on the given stream."""
    target = stream if stream is not None else sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        if not target.isatty():  # type: ignore[union-attr]
            return False
    except Exception:
        return False
    if os.name != "nt":
        return True
    # Windows Terminal and modern conhost handle ANSI; legacy consoles do not.
    return bool(os.environ.get("WT_SESSION") or os.environ.get("ANSICON") or _enable_vt_mode())


_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
_STD_OUTPUT_HANDLE = -11
_vt_restore_registered = False


def _set_console_mode(mode: int) -> bool:
    """Write a console mode value. Never raises; returns whether Windows accepted it."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        return bool(kernel32.SetConsoleMode(kernel32.GetStdHandle(_STD_OUTPUT_HANDLE), mode))
    except Exception:
        return False


def _enable_vt_mode() -> bool:
    """
    Ask the Windows console for virtual-terminal processing. Never raises.

    The console screen buffer belongs to the parent shell, so the previous mode is restored
    at exit: this tool does not leave a changed setting behind, not even a harmless one.
    """
    global _vt_restore_registered
    try:
        import atexit
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(_STD_OUTPUT_HANDLE)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        original = int(mode.value)
        if original & _ENABLE_VIRTUAL_TERMINAL_PROCESSING:
            return True
        if not kernel32.SetConsoleMode(handle, original | _ENABLE_VIRTUAL_TERMINAL_PROCESSING):
            return False
        if not _vt_restore_registered:
            _vt_restore_registered = True
            atexit.register(_set_console_mode, original)
        return True
    except Exception:
        return False
