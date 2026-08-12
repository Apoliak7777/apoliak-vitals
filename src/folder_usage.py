"""Read-only sizes of the well-known user folders.

"You have 588 GB free" is a fact the user can do nothing with. "Your Downloads folder holds
40 GB" is the same disk, said in a way that names the next action. This module measures the
handful of folders where a person's own files actually accumulate, using the same defensive
walker the TEMP measurement uses: nothing is opened, nothing is written, links are never
followed, and an unreadable entry is skipped rather than raised.

Paths come from ``SHGetKnownFolderPath`` rather than from ``%USERPROFILE%`` joins, because on
a real machine these folders move: Documents and Desktop are routinely redirected into
OneDrive, and a joined path would then measure an empty leftover directory and report a
reassuring, wrong number. The environment join stays as the fallback for the case where the
shell call fails outright.

**One budget, shared.** Walking a disk is the only part of an analysis whose cost depends on
what is stored on the machine rather than on the machine itself, so the whole set of folders
shares a single wall-clock budget. Each folder may claim what is left of it minus a small
reserve held back for the folders not yet measured - so a 40 GB AppData cannot starve the
five folders behind it, and a folder that finishes early hands its unused time on. A scan
that runs out reports ``truncated``: the size is then a **lower bound**, and every caller in
this project labels it as one.
"""

from __future__ import annotations

import os
import platform
import time
from typing import Any

from .models import FolderUsage
from .utils import DEFAULT_SCAN_SECONDS, scan_folder

#: Stable keys for the folders this module measures, in the order it measures them:
#: Downloads first because it is the one users act on most, the two application-data folders
#: last because they are the slowest to walk and gain the most from inherited time.
KNOWN_FOLDER_KEYS: tuple[str, ...] = (
    "downloads",
    "desktop",
    "documents",
    "pictures",
    "videos",
    "music",
    "local_appdata",
    "packages",
)

#: ``(key, label, KNOWNFOLDERID, path under the user profile to fall back on)``.
#:
#: The labels are plain English on purpose: they travel into the snapshot as data, and the
#: interfaces translate around them rather than re-deriving them from the key.
#:
#: ``packages`` has no KNOWNFOLDERID of its own - it is a fixed subfolder of Local app data,
#: so it is derived from whatever that resolved to. Its bytes are therefore counted twice,
#: once in each row. That is deliberate: "all application data" and "Microsoft Store app
#: data" answer different questions, and both numbers are true.
_KNOWN_FOLDERS: tuple[tuple[str, str, str | None, str], ...] = (
    ("downloads", "Downloads", "374DE290-123F-4565-9164-39C4925E467B", "Downloads"),
    ("desktop", "Desktop", "B4BFCC3A-DB2C-424C-B029-7FE99A87C641", "Desktop"),
    ("documents", "Documents", "FDD39AD0-238F-46AF-ADB4-6C85480369C7", "Documents"),
    ("pictures", "Pictures", "33E28130-4E1E-4676-835A-98395C3BC3BB", "Pictures"),
    ("videos", "Videos", "18989B1D-99B5-455B-841C-AB7C74E4DDFC", "Videos"),
    ("music", "Music", "4BD8D571-6D19-48D3-BE97-422220080E43", "Music"),
    (
        "local_appdata",
        "Local app data",
        "F1B32785-6FBA-4FCF-9D55-7B8E7F157091",
        os.path.join("AppData", "Local"),
    ),
    ("packages", "Store app data", None, os.path.join("AppData", "Local", "Packages")),
)

#: The folder ``packages`` lives in, and the subfolder name inside it.
_PACKAGES_PARENT_KEY = "local_appdata"
_PACKAGES_SUBFOLDER = "Packages"

#: Seconds every folder is guaranteed, however long the ones before it took. A folder that
#: gets less than this reports "0 bytes, partial" - a measurement nobody could act on - so the
#: reserve is what keeps the last row in the table worth printing.
_MIN_FOLDER_SECONDS = 0.5

#: KF_FLAG_DEFAULT. No KF_FLAG_CREATE and no KF_FLAG_INIT: this application does not create
#: folders, not even the ones Windows would happily create for it.
_KF_FLAG_DEFAULT = 0

#: A path this long is not a folder anyone stores files in; it is a malformed answer.
_MAX_PATH_LENGTH = 4096


def read_folder_usage(*, max_seconds: float | None = None, limit: int = 8) -> list[FolderUsage]:
    """
    Measure the well-known user folders and return them biggest first.

    ``max_seconds`` is the budget for *all* of them together, defaulting to
    :data:`utils.DEFAULT_SCAN_SECONDS`; ``limit`` caps how many rows come back.

    A folder that exists but cannot be listed comes back with ``size_bytes=None`` - unknown,
    which is not the same as empty, and is never scored. A folder that is not there at all is
    left out entirely: there is nothing to report about a Music folder the user removed.

    Returns an empty list on a non-Windows platform. It never raises.
    """
    if platform.system() != "Windows":
        return []

    try:
        cap = max(0, int(limit))
        if cap == 0:
            return []
        budget = DEFAULT_SCAN_SECONDS if max_seconds is None else max(0.0, float(max_seconds))

        measured = _measure(_folder_candidates(), budget)
        # An unmeasured folder sorts last, because "unknown" is not "small". Label and key
        # break ties so two folders of the same size always come back in the same order.
        measured.sort(
            key=lambda item: (
                item.size_bytes is None,
                -(item.size_bytes or 0),
                item.label.casefold(),
                item.key,
            )
        )
        return measured[:cap]
    except Exception:
        return []


def _measure(candidates: list[tuple[str, str, str]], budget: float) -> list[FolderUsage]:
    """Walk each candidate within its share of ``budget``, in the order it was given."""
    results: list[FolderUsage] = []
    remaining = max(0.0, budget)

    for index, (key, label, path) in enumerate(candidates):
        left = len(candidates) - index
        if not _is_listable_directory(path):
            # Never measured, so no size: reporting 0 bytes here would turn a folder this
            # account may not open into a spotlessly clean one.
            results.append(FolderUsage(key=key, label=label, path=path))
            continue

        started = time.monotonic()
        try:
            size, files, truncated = scan_folder(path, max_seconds=_share(remaining, left))
        except Exception:
            results.append(FolderUsage(key=key, label=label, path=path))
            continue
        # Whatever this folder did not need stays in the pot for the ones behind it.
        remaining = max(0.0, remaining - (time.monotonic() - started))

        results.append(
            FolderUsage(
                key=key,
                label=label,
                path=path,
                size_bytes=size,
                file_count=files,
                truncated=truncated,
            )
        )
    return results


def _share(remaining: float, left: int) -> float:
    """
    How long the next folder may spend: everything left, minus a reserve for the rest.

    Pure arithmetic, so the sharing rule can be checked without touching a disk. On a budget
    too small to give everyone the reserve, it degrades to an even split rather than handing
    the first folder everything.
    """
    remaining = max(0.0, remaining)
    if left <= 1:
        return remaining
    reserve = min(_MIN_FOLDER_SECONDS, remaining / left)
    return max(reserve, remaining - reserve * (left - 1))


def _folder_candidates() -> list[tuple[str, str, str]]:
    """
    Resolve every known folder to ``(key, label, path)``, in measuring order.

    Folders that resolve to the same place - a machine where Videos was pointed at Documents,
    say - are measured once, under the first key that reached them. Anything that resolves
    nowhere at all is dropped here rather than carried as a row with no path.
    """
    api = _load_shell_api()
    resolved: dict[str, str] = {}
    candidates: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    for key, label, guid_text, fallback in _KNOWN_FOLDERS:
        path = _resolve_folder(api, key, guid_text, fallback, resolved)
        if not path:
            continue
        resolved[key] = path
        marker = _identity(path)
        if marker in seen:
            continue
        seen.add(marker)
        candidates.append((key, label, path))
    return candidates


def _resolve_folder(
    api: Any,
    key: str,
    guid_text: str | None,
    fallback: str,
    resolved: dict[str, str],
) -> str | None:
    """Find one folder: derived, then by KNOWNFOLDERID, then by user-profile join."""
    if key == "packages":
        # Derived from wherever Local app data actually turned out to be, so a redirected
        # AppData does not leave this pointing at an empty default location.
        parent = resolved.get(_PACKAGES_PARENT_KEY)
        if parent:
            return os.path.join(parent, _PACKAGES_SUBFOLDER)

    if guid_text:
        path = _known_folder_path(api, guid_text)
        if path:
            return path

    if key == _PACKAGES_PARENT_KEY:
        # %LOCALAPPDATA% is the one of these Windows genuinely publishes as an environment
        # variable, so it beats a profile join when the shell call did not answer.
        local = (os.environ.get("LOCALAPPDATA") or "").strip()
        if local:
            return local

    profile = (os.environ.get("USERPROFILE") or "").strip()
    if not profile:
        return None
    return os.path.join(profile, fallback)


def _identity(path: str) -> str:
    """A comparable form of a path, so two names for one folder are recognised as one."""
    try:
        return os.path.normcase(os.path.realpath(path))
    except (OSError, ValueError):
        return os.path.normcase(path)


def _is_listable_directory(path: str) -> bool:
    """
    Whether ``path`` is a directory this account is actually allowed to list.

    ``scan_folder`` answers "0 bytes, 0 files" for a folder that is missing or refuses to
    open, and that is indistinguishable from a genuinely empty one. Opening the directory and
    asking for its first entry costs one listing and turns "cannot look" back into "unknown".

    Deliberately a copy of the analyzer's identical helper rather than an import of it:
    ``analyzer`` imports this module, so borrowing it back would be an import cycle.
    """
    try:
        if not os.path.isdir(path):
            return False
        with os.scandir(path) as entries:  # Listing is the permission that matters here.
            next(iter(entries), None)
    except (OSError, ValueError):
        return False
    return True


def _load_shell_api() -> Any | None:
    """
    Load shell32 and ole32 with the prototypes needed to resolve a known folder.

    Returns None off Windows and whenever the libraries cannot be loaded - the caller then
    falls back to the environment. The imports are local because ``ctypes.wintypes`` does not
    exist on other platforms, and this module has to import cleanly there.
    """
    if platform.system() != "Windows":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        from types import SimpleNamespace

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", ctypes.c_uint32),
                ("Data2", ctypes.c_uint16),
                ("Data3", ctypes.c_uint16),
                ("Data4", ctypes.c_ubyte * 8),
            ]

        shell32 = ctypes.WinDLL("shell32", use_last_error=True)
        ole32 = ctypes.WinDLL("ole32", use_last_error=True)

        shell32.SHGetKnownFolderPath.argtypes = [
            ctypes.POINTER(GUID),
            wintypes.DWORD,
            wintypes.HANDLE,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        shell32.SHGetKnownFolderPath.restype = ctypes.c_long  # HRESULT
        ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
        ole32.CoTaskMemFree.restype = None

        return SimpleNamespace(shell32=shell32, ole32=ole32, guid_type=GUID)
    except Exception:
        return None


def _known_folder_path(api: Any, guid_text: str) -> str | None:
    """
    Ask the shell where a known folder currently lives, or None when it will not say.

    The path is returned in memory the shell allocated, so it is freed with ``CoTaskMemFree``
    in a ``finally`` - including on the paths where the string turns out to be unusable.
    """
    if api is None:
        return None
    try:
        import ctypes

        fields = _guid_fields(guid_text)
        if fields is None:
            return None
        data1, data2, data3, data4 = fields
        guid = api.guid_type(data1, data2, data3, (ctypes.c_ubyte * 8)(*data4))

        pointer = ctypes.c_void_p()
        hresult = api.shell32.SHGetKnownFolderPath(
            ctypes.byref(guid), _KF_FLAG_DEFAULT, None, ctypes.byref(pointer)
        )
        if hresult != 0 or not pointer.value:
            # A non-zero HRESULT here usually means the folder does not exist on this
            # machine, which the caller handles by falling back to the profile join.
            return None
        try:
            path = ctypes.wstring_at(pointer.value)
        finally:
            api.ole32.CoTaskMemFree(pointer)
        path = path.strip()
        return path if path and len(path) <= _MAX_PATH_LENGTH else None
    except Exception:
        return None


def _guid_fields(text: str) -> tuple[int, int, int, bytes] | None:
    """
    Split a ``8-4-4-4-12`` GUID string into the four members of a Win32 GUID.

    Pure, so the identifiers in this module can be checked without loading a single DLL.
    """
    try:
        parts = str(text).strip().strip("{}").split("-")
        if len(parts) != 5:
            return None
        data4 = bytes.fromhex(parts[3] + parts[4])
        if len(data4) != 8:
            return None
        return int(parts[0], 16), int(parts[1], 16), int(parts[2], 16), data4
    except (AttributeError, ValueError):
        return None
