"""Read-only wear and lifetime figures for the physical drives behind Windows volumes.

Everything here is a query. Volumes and physical devices are opened with
``dwDesiredAccess = 0``, which grants metadata IOCTLs only: no read, no write, and - just as
important - no administrator rights. A drive that refuses to answer produces None, never an
exception and never an estimate.

Three IOCTLs are used, all of them pure queries:

* ``IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS`` maps a drive letter to its physical disk number.
* ``IOCTL_STORAGE_QUERY_PROPERTY`` with ``StorageDeviceProperty`` returns the model and the
  bus type. The descriptor also carries a serial number; this module deliberately never
  reads it, because a serial is a hardware identifier and this application collects none.
* ``IOCTL_STORAGE_QUERY_PROPERTY`` with ``StorageDeviceProtocolSpecificProperty`` fetches the
  NVMe SMART / Health Information log page, which is where the actual wear figures live.
  SATA drives and some controllers reject that query - then the wear fields stay None and
  the entry still reports model, bus type and media type.

The Win32 plumbing sits in three small seams - :func:`_load_kernel32`, :func:`_open_device`
and :func:`_device_io_control` - so a test can replace the operating system wholesale, while
the decoding of every buffer is done by pure ``bytes -> value`` functions that need no
hardware at all.
"""

from __future__ import annotations

import platform
import struct
from collections.abc import Sequence
from typing import Any

from .models import DriveHealth

#: Query codes. Both are ``FILE_ANY_ACCESS`` control codes, hence usable on a handle that
#: was opened without any access rights at all.
_IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x560000
_IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400

#: STORAGE_PROPERTY_ID values used below (ntddstor.h).
_STORAGE_DEVICE_PROPERTY = 0
_STORAGE_DEVICE_SEEK_PENALTY_PROPERTY = 7
_STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY = 49
_PROPERTY_STANDARD_QUERY = 0

#: STORAGE_PROTOCOL_TYPE / NVMe log page selectors.
_PROTOCOL_TYPE_NVME = 3
_NVME_DATA_TYPE_LOG_PAGE = 2
_NVME_LOG_PAGE_HEALTH_INFO = 0x02

#: Byte sizes of the structures exchanged with the driver.
_PROPERTY_QUERY_BYTES = 12  # sizeof(STORAGE_PROPERTY_QUERY), padded to 4-byte alignment
_PROTOCOL_SPECIFIC_DATA_BYTES = 40  # sizeof(STORAGE_PROTOCOL_SPECIFIC_DATA)
_PROTOCOL_DESCRIPTOR_BYTES = 48  # Version + Size + the 40-byte protocol block
_NVME_HEALTH_LOG_BYTES = 512
_DEVICE_DESCRIPTOR_BUFFER_BYTES = 1024  # The descriptor's trailing strings need the room.
_SEEK_PENALTY_DESCRIPTOR_BYTES = 9  # Version + Size + BOOLEAN IncursSeekPenalty
_DISK_EXTENTS_BUFFER_BYTES = 8 + 24 * 4  # Header plus four DISK_EXTENT entries.

#: Field offsets inside STORAGE_DEVICE_DESCRIPTOR. SerialNumberOffset (24) is listed only to
#: document that it exists and is skipped on purpose - see the module docstring.
_DESCRIPTOR_HEADER_BYTES = 36
_DESCRIPTOR_VENDOR_ID_OFFSET = 12
_DESCRIPTOR_PRODUCT_ID_OFFSET = 16
_DESCRIPTOR_BUS_TYPE_OFFSET = 28

#: STORAGE_BUS_TYPE (ntddstor.h). 17 = NVMe is the value this project verified against real
#: hardware; the remaining names come straight from the header. An unlisted number stays
#: None rather than being guessed at.
_BUS_TYPES: dict[int, str] = {
    1: "SCSI",
    2: "ATAPI",
    3: "ATA",
    4: "IEEE 1394",
    5: "SSA",
    6: "Fibre Channel",
    7: "USB",
    8: "RAID",
    9: "iSCSI",
    10: "SAS",
    11: "SATA",
    12: "SD",
    13: "MMC",
    14: "Virtual",
    15: "File-backed virtual",
    16: "Storage Spaces",
    17: "NVMe",
    18: "SCM",
    19: "UFS",
}

#: Vendor strings that only repeat the bus and would make the model read "ATA ATA Disk".
_BUS_PLACEHOLDER_VENDORS = frozenset({"ata", "nvme", "sata", "scsi", "usb", "unknown"})

#: Plausibility limits. A figure outside them means the offsets are wrong or the controller
#: answered with filler, and a wrong number is worse than no number.
_MIN_TEMPERATURE_KELVIN = 233  # -40 C
_MAX_TEMPERATURE_KELVIN = 398  # +125 C, the top of the NVMe operating range
_MAX_POWER_ON_HOURS = 1_000_000  # ~114 years
_MAX_DATA_WRITTEN_BYTES = 10**18  # 1 EB; no drive this application will meet writes more
_NVME_DATA_UNIT_BYTES = 1000 * 512  # One "data unit" per the NVMe specification

#: Guard rails so a machine with an unusual storage layout cannot make the run long.
_MAX_DRIVES = 16
_MAX_DISK_NUMBER = 255
_MAX_MODEL_LENGTH = 96

#: ``\\.\C:`` and ``\\.\PhysicalDrive0`` are opened with these flags.
_FILE_SHARE_READ_WRITE = 0x00000001 | 0x00000002
_OPEN_EXISTING = 3
_DRIVE_FIXED = 3

_NVME_SOURCE = "NVMe SMART log"


def read_drive_health(drives: Sequence[str] | None = None) -> list[DriveHealth]:
    """
    Report wear and lifetime figures for the physical drives behind ``drives``.

    ``drives`` holds drive letters such as ``"C:\\"``; ``None`` means every fixed drive on
    the machine. Two volumes on one physical disk share one set of wear figures, so the disk
    is reported once, under the first letter that reaches it.

    Returns an empty list on a non-Windows platform, when no drive can be identified, or
    when Windows declines every query. It never raises.
    """
    if platform.system() != "Windows":
        return []

    try:
        kernel32 = _load_kernel32()
        if kernel32 is None:
            return []

        letters = _requested_letters(kernel32, drives)
        results: list[DriveHealth] = []
        seen_disks: set[int] = set()
        for letter in letters:
            try:
                entry = _read_drive(kernel32, letter, seen_disks)
            except Exception:
                # One uncooperative drive must not cost the others their report.
                entry = None
            if entry is not None:
                results.append(entry)
            if len(results) >= _MAX_DRIVES:
                break
        return results
    except Exception:
        return []


def _requested_letters(kernel32: Any, drives: Sequence[str] | None) -> list[str]:
    """Normalise the caller's drive list, or enumerate the fixed drives when it is None."""
    if drives is None:
        return _fixed_drive_letters(kernel32)

    letters: list[str] = []
    for drive in drives:
        letter = _drive_letter(drive)
        # A path that is not a lettered volume (a mount folder, a UNC share) has no
        # physical disk this module can name, so it is skipped rather than half-reported.
        if letter is not None and letter not in letters:
            letters.append(letter)
    return letters[:_MAX_DRIVES]


def _drive_letter(drive: object) -> str | None:
    """Extract the drive letter from ``"C:"``, ``"c:\\"`` or a bare ``"C"``."""
    text = str(drive or "").strip()
    if len(text) == 1 and text.isalpha():
        return text.upper()
    if len(text) >= 2 and text[0].isalpha() and text[1] == ":":
        return text[0].upper()
    return None


def _fixed_drive_letters(kernel32: Any) -> list[str]:
    """List the letters of the fixed drives. Removable, network and optical drives are out."""
    try:
        mask = int(kernel32.GetLogicalDrives())
    except Exception:
        return []
    if mask <= 0:
        return []

    letters: list[str] = []
    for index in range(26):
        if not mask & (1 << index):
            continue
        letter = chr(ord("A") + index)
        try:
            if int(kernel32.GetDriveTypeW(f"{letter}:\\")) != _DRIVE_FIXED:
                continue
        except Exception:
            continue
        letters.append(letter)
        if len(letters) >= _MAX_DRIVES:
            break
    return letters


def _read_drive(kernel32: Any, letter: str, seen_disks: set[int]) -> DriveHealth | None:
    """Build one :class:`DriveHealth`, or None when the volume cannot be identified."""
    disk_number = _volume_disk_number(kernel32, letter)
    if disk_number is None or disk_number in seen_disks:
        return None
    seen_disks.add(disk_number)

    device = _open_device(kernel32, rf"\\.\PhysicalDrive{disk_number}")
    if device is None:
        return None
    try:
        model, bus_type = _read_device_identity(kernel32, device)
        media_type = _read_media_type(kernel32, device)
        health = _read_nvme_health(kernel32, device)
    finally:
        _close_handle(kernel32, device)

    entry = DriveHealth(
        drive=f"{letter}:\\",
        model=model,
        bus_type=bus_type,
        media_type=media_type,
        percentage_used=health.get("percentage_used"),  # type: ignore[arg-type]
        temperature_celsius=health.get("temperature_celsius"),  # type: ignore[arg-type]
        power_on_hours=health.get("power_on_hours"),  # type: ignore[arg-type]
        data_written_bytes=health.get("data_written_bytes"),  # type: ignore[arg-type]
        critical_warning=health.get("critical_warning"),  # type: ignore[arg-type]
        source=_NVME_SOURCE if health else None,
    )
    # A device that answered nothing at all would render as a row of N/A next to the drive
    # figures the snapshot already carries, so it is left out instead of padding the report.
    if model is None and bus_type is None and media_type is None and not health:
        return None
    return entry


def _volume_disk_number(kernel32: Any, letter: str) -> int | None:
    """Map a drive letter to the number of the single physical disk that carries it."""
    volume = _open_device(kernel32, rf"\\.\{letter}:")
    if volume is None:
        return None
    try:
        raw = _device_io_control(
            kernel32,
            volume,
            _IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            b"",
            _DISK_EXTENTS_BUFFER_BYTES,
        )
    finally:
        _close_handle(kernel32, volume)
    return _decode_disk_number(raw)


def _decode_disk_number(raw: bytes | None) -> int | None:
    """
    Read the disk number out of a VOLUME_DISK_EXTENTS buffer.

    The DISK_EXTENT array starts at offset 8: the DWORD count is followed by four bytes of
    padding, because the extent's LONGLONG members force 8-byte alignment. A volume spanning
    several disks has no single set of wear figures, so it is reported as unknown.
    """
    if not raw or len(raw) < 12:
        return None
    try:
        if struct.unpack_from("<I", raw, 0)[0] != 1:
            return None
        disk_number = struct.unpack_from("<I", raw, 8)[0]
    except struct.error:
        return None
    if disk_number > _MAX_DISK_NUMBER:
        return None
    return int(disk_number)


def _read_device_identity(kernel32: Any, device: Any) -> tuple[str | None, str | None]:
    """Return ``(model, bus_type)`` for an open physical device handle."""
    raw = _device_io_control(
        kernel32,
        device,
        _IOCTL_STORAGE_QUERY_PROPERTY,
        _build_property_query(_STORAGE_DEVICE_PROPERTY),
        _DEVICE_DESCRIPTOR_BUFFER_BYTES,
    )
    return _decode_device_descriptor(raw)


def _decode_device_descriptor(raw: bytes | None) -> tuple[str | None, str | None]:
    """
    Decode STORAGE_DEVICE_DESCRIPTOR into a model name and a bus name.

    Only VendorIdOffset and ProductIdOffset are followed. SerialNumberOffset is left
    untouched on purpose: this application must not collect a hardware identifier.
    """
    if not raw or len(raw) < _DESCRIPTOR_HEADER_BYTES:
        return None, None
    try:
        vendor_offset = struct.unpack_from("<I", raw, _DESCRIPTOR_VENDOR_ID_OFFSET)[0]
        product_offset = struct.unpack_from("<I", raw, _DESCRIPTOR_PRODUCT_ID_OFFSET)[0]
        bus_value = struct.unpack_from("<I", raw, _DESCRIPTOR_BUS_TYPE_OFFSET)[0]
    except struct.error:
        return None, None

    vendor = _read_c_string(raw, vendor_offset)
    product = _read_c_string(raw, product_offset)
    return _compose_model(vendor, product), _BUS_TYPES.get(int(bus_value))


def _read_c_string(raw: bytes, offset: int) -> str | None:
    """Read a NUL-terminated ANSI string living at ``offset`` inside the same buffer."""
    if not offset or offset >= len(raw):
        return None
    end = raw.find(b"\x00", offset)
    chunk = raw[offset:] if end < 0 else raw[offset:end]
    try:
        text = chunk.decode("latin-1")
    except (UnicodeDecodeError, ValueError):
        return None
    # Firmware pads these fields with spaces and the odd control character.
    text = " ".join("".join(char for char in text if char.isprintable()).split())
    return text[:_MAX_MODEL_LENGTH] or None


def _compose_model(vendor: str | None, product: str | None) -> str | None:
    """Join vendor and product, dropping a vendor that only repeats the bus or the product."""
    if not product:
        # A lone "ATA" or "NVMe" names the bus, not the drive, so it is not a model.
        if vendor and vendor.lower() not in _BUS_PLACEHOLDER_VENDORS:
            return vendor
        return None
    if not vendor or vendor.lower() in _BUS_PLACEHOLDER_VENDORS:
        return product
    if product.lower().startswith(vendor.lower()):
        return product
    return f"{vendor} {product}"[:_MAX_MODEL_LENGTH]


def _read_media_type(kernel32: Any, device: Any) -> str | None:
    """Classify the device as "SSD" or "HDD" from its seek penalty, or None when unknown."""
    raw = _device_io_control(
        kernel32,
        device,
        _IOCTL_STORAGE_QUERY_PROPERTY,
        _build_property_query(_STORAGE_DEVICE_SEEK_PENALTY_PROPERTY),
        64,
    )
    return _decode_seek_penalty(raw)


def _decode_seek_penalty(raw: bytes | None) -> str | None:
    if not raw or len(raw) < _SEEK_PENALTY_DESCRIPTOR_BYTES:
        return None
    return "HDD" if raw[8] else "SSD"


def _build_property_query(property_id: int) -> bytes:
    """Build a STORAGE_PROPERTY_QUERY with an empty AdditionalParameters block."""
    header = struct.pack("<II", property_id, _PROPERTY_STANDARD_QUERY)
    return header.ljust(_PROPERTY_QUERY_BYTES, b"\x00")


def _build_nvme_health_query() -> bytes:
    """
    Build the buffer that asks for the NVMe SMART / Health Information log page.

    The same buffer serves as input and output: its first eight bytes are the property
    query, the next forty are STORAGE_PROTOCOL_SPECIFIC_DATA, and the rest is the room the
    driver fills with the log page. ProtocolDataOffset is measured from the start of the
    protocol block, which is why it equals the size of that block.
    """
    header = struct.pack(
        "<II", _STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY, _PROPERTY_STANDARD_QUERY
    )
    protocol = struct.pack(
        "<10I",
        _PROTOCOL_TYPE_NVME,
        _NVME_DATA_TYPE_LOG_PAGE,
        _NVME_LOG_PAGE_HEALTH_INFO,
        0,  # ProtocolDataRequestSubValue: no namespace filter
        _PROTOCOL_SPECIFIC_DATA_BYTES,  # ProtocolDataOffset
        _NVME_HEALTH_LOG_BYTES,  # ProtocolDataLength
        0,  # FixedProtocolReturnData
        0,  # ProtocolDataRequestSubValue2
        0,  # ProtocolDataRequestSubValue3
        0,  # ProtocolDataRequestSubValue4
    )
    return header + protocol + b"\x00" * _NVME_HEALTH_LOG_BYTES


def _read_nvme_health(kernel32: Any, device: Any) -> dict[str, object]:
    """
    Fetch and decode the NVMe health log page.

    Returns an empty dict for every drive that is not NVMe, for controllers that filter the
    pass-through, and whenever the answer fails a plausibility check.
    """
    payload = _build_nvme_health_query()
    raw = _device_io_control(
        kernel32, device, _IOCTL_STORAGE_QUERY_PROPERTY, payload, len(payload)
    )
    log = _extract_protocol_log(raw)
    if log is None:
        return {}
    return _decode_nvme_health(log)


def _extract_protocol_log(raw: bytes | None) -> bytes | None:
    """Validate a STORAGE_PROTOCOL_DATA_DESCRIPTOR and slice the log page out of it."""
    if not raw or len(raw) < _PROTOCOL_DESCRIPTOR_BYTES:
        return None
    try:
        protocol_type, data_type, request_value = struct.unpack_from("<3I", raw, 8)
        data_offset, data_length = struct.unpack_from("<2I", raw, 24)
    except struct.error:
        return None

    # A controller that answered about something else is not answering about health.
    if protocol_type != _PROTOCOL_TYPE_NVME or data_type != _NVME_DATA_TYPE_LOG_PAGE:
        return None
    if request_value != _NVME_LOG_PAGE_HEALTH_INFO:
        return None
    if data_offset < _PROTOCOL_SPECIFIC_DATA_BYTES or not data_length:
        return None

    start = 8 + data_offset  # ProtocolDataOffset is relative to the protocol block.
    end = start + min(int(data_length), _NVME_HEALTH_LOG_BYTES)
    if end > len(raw):
        return None
    return raw[start:end]


def _decode_nvme_health(log: bytes) -> dict[str, object]:
    """
    Decode the NVMe SMART / Health Information log page (NVMe specification, log page 02h).

    Every figure that fails its plausibility check is simply left out, so the caller reports
    "N/A" for it instead of a number nobody can trust.
    """
    values: dict[str, object] = {}
    # Power-on hours end at byte 144; a shorter page cannot carry the figures we need.
    if len(log) < 144 or not any(log):
        return values

    values["critical_warning"] = bool(log[0])

    kelvin = struct.unpack_from("<H", log, 1)[0]
    if _MIN_TEMPERATURE_KELVIN <= kelvin <= _MAX_TEMPERATURE_KELVIN:
        values["temperature_celsius"] = int(kelvin) - 273

    # The specification allows values above 100 %: the drive has outlived its rated
    # endurance. That is still "fully used", so it is reported as 100 rather than dropped.
    values["percentage_used"] = min(100, int(log[5]))

    data_units_written = int.from_bytes(log[48:64], "little")
    written_bytes = data_units_written * _NVME_DATA_UNIT_BYTES
    if written_bytes <= _MAX_DATA_WRITTEN_BYTES:
        values["data_written_bytes"] = written_bytes

    power_on_hours = int.from_bytes(log[128:144], "little")
    if power_on_hours <= _MAX_POWER_ON_HOURS:
        values["power_on_hours"] = power_on_hours

    return values


def _load_kernel32() -> Any | None:
    """
    Return kernel32 with the prototypes this module needs, or None when that is impossible.

    Declaring argtypes matters on 64-bit Windows: without them ctypes would truncate the
    handle to 32 bits and every call would fail.
    """
    if platform.system() != "Windows":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.DeviceIoControl.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            wintypes.LPVOID,
        ]
        kernel32.DeviceIoControl.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        kernel32.GetLogicalDrives.argtypes = []
        kernel32.GetLogicalDrives.restype = wintypes.DWORD
        kernel32.GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
        kernel32.GetDriveTypeW.restype = wintypes.UINT
        return kernel32
    except Exception:
        return None


def _open_device(kernel32: Any, path: str) -> Any | None:
    """
    Open a volume or physical device for metadata queries only.

    ``dwDesiredAccess = 0`` is the whole reason this module needs no elevation: the handle
    can carry an IOCTL but cannot read or write a single sector.
    """
    try:
        import ctypes

        handle = kernel32.CreateFileW(
            path, 0, _FILE_SHARE_READ_WRITE, None, _OPEN_EXISTING, 0, None
        )
        if not handle or handle == ctypes.c_void_p(-1).value:
            return None
        return handle
    except Exception:
        return None


def _device_io_control(
    kernel32: Any,
    handle: Any,
    control_code: int,
    payload: bytes,
    out_size: int,
) -> bytes | None:
    """Send one query IOCTL and return exactly the bytes the driver wrote, or None."""
    try:
        import ctypes
        from ctypes import wintypes

        out_buffer = ctypes.create_string_buffer(out_size)
        returned = wintypes.DWORD(0)
        in_buffer = (
            ctypes.create_string_buffer(payload, len(payload)) if payload else None
        )
        ok = kernel32.DeviceIoControl(
            handle,
            control_code,
            ctypes.byref(in_buffer) if in_buffer is not None else None,
            len(payload),
            ctypes.byref(out_buffer),
            out_size,
            ctypes.byref(returned),
            None,
        )
        if not ok:
            return None
        written = min(int(returned.value), out_size)
        if written <= 0:
            return None
        return out_buffer.raw[:written]
    except Exception:
        return None


def _close_handle(kernel32: Any, handle: Any) -> None:
    """Close a handle, swallowing everything: a failed close must not hide a good reading."""
    try:
        kernel32.CloseHandle(handle)
    except Exception:
        pass
