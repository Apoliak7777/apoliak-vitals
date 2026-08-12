"""Read-only battery wear figures, straight from the ACPI battery driver.

psutil answers what the battery is *doing* - charge, plug state, time left. It cannot answer
what the pack has *become*, and on a laptop that is the number that matters: a battery whose
full charge is 75 Wh against a design of 80 Wh still shows "100 %" while holding a fifth less
than it did when new. Windows publishes exactly that pair through the battery class driver,
so this module asks it directly.

The route, all of it a query:

1. ``setupapi.dll`` enumerates the present battery device interfaces
   (``GUID_DEVCLASS_BATTERY``) and hands back a device path.
2. ``CreateFileW`` opens that path, and ``IOCTL_BATTERY_QUERY_TAG`` fetches the tag that
   identifies the pack currently in the bay.
3. ``IOCTL_BATTERY_QUERY_INFORMATION`` at level ``BatteryInformation`` returns the
   ``BATTERY_INFORMATION`` block: capabilities, chemistry, designed and full-charge capacity,
   and the cycle count.

**Access rights.** The rest of this project opens devices with ``dwDesiredAccess = 0``. The
battery IOCTLs are ``FILE_READ_ACCESS`` control codes, so a zero-access handle opens fine and
then fails the IOCTL with ``ERROR_ACCESS_DENIED`` - measured on the reference laptop. This
module therefore tries zero access first and only falls back to ``GENERIC_READ``, which is the
minimum Windows accepts here. ``GENERIC_READ`` on a battery interface needs **no
administrator rights**; it was verified from a standard, unelevated account. Nothing is ever
written: ``GENERIC_WRITE`` is never requested, no elevation is ever asked for, and a machine
that still refuses the query simply reports nothing.

Everything Win32 sits behind three seams - :func:`_load_api`, :func:`_open_battery_device` and
:func:`_device_io_control` - so a test can replace Windows wholesale, while the buffer
decoding is done by pure ``bytes -> value`` functions that need no hardware at all.
"""

from __future__ import annotations

import platform
import struct
from typing import Any

#: GUID_DEVCLASS_BATTERY / GUID_DEVICE_BATTERY {72631e54-78a4-11d0-bcf7-00aa00b7b32a}, split
#: into the four members of a Win32 GUID so no string parser is needed to build it.
_BATTERY_GUID_DATA1 = 0x72631E54
_BATTERY_GUID_DATA2 = 0x78A4
_BATTERY_GUID_DATA3 = 0x11D0
_BATTERY_GUID_DATA4 = (0xBC, 0xF7, 0x00, 0xAA, 0x00, 0xB7, 0xB3, 0x2A)

#: SetupDiGetClassDevs flags: only devices that are plugged in right now, and enumerate them
#: by device *interface* so each one yields a path CreateFileW can open.
_DIGCF_PRESENT = 0x00000002
_DIGCF_DEVICEINTERFACE = 0x00000010

#: Battery class IOCTLs (batclass.h). Both are METHOD_BUFFERED / FILE_READ_ACCESS queries.
_IOCTL_BATTERY_QUERY_TAG = 0x294040
_IOCTL_BATTERY_QUERY_INFORMATION = 0x294044

#: BATTERY_QUERY_INFORMATION_LEVEL: 0 = BatteryInformation, the only level this module needs.
_BATTERY_INFORMATION_LEVEL = 0

#: Ask for the tag without waiting: a bay whose pack is being swapped must not stall a run.
_QUERY_TAG_TIMEOUT_MS = 0
#: BATTERY_TAG_INVALID. Zero means "no battery in this bay", not "a battery numbered zero".
_BATTERY_TAG_INVALID = 0

#: sizeof(BATTERY_INFORMATION) and the offsets inside it. Technology (4) and the three
#: reserved bytes after it are read by nobody: the chemistry string says the same thing.
_BATTERY_INFORMATION_BYTES = 36
_INFORMATION_CAPABILITIES_OFFSET = 0
_INFORMATION_CHEMISTRY_OFFSET = 8
_INFORMATION_CHEMISTRY_BYTES = 4
_INFORMATION_DESIGNED_CAPACITY_OFFSET = 12
_INFORMATION_FULL_CHARGED_CAPACITY_OFFSET = 16
_INFORMATION_CYCLE_COUNT_OFFSET = 32

#: BATTERY_CAPACITY_RELATIVE. When this is set the capacities carry no unit at all - they are
#: bare numbers on a scale the firmware never publishes. Reporting them as mWh would be a
#: made-up measurement, so they are dropped and only the unit-free fields are kept.
_BATTERY_CAPACITY_RELATIVE = 0x40000000

#: BATTERY_UNKNOWN_CAPACITY: the driver's own "I do not know", not a real reading.
_BATTERY_UNKNOWN_CAPACITY = 0xFFFFFFFF

#: Plausibility limits. 1 000 000 mWh is a 1 kWh pack - an order of magnitude past the largest
#: laptop battery ever built - so anything above it means the offsets are wrong or the
#: firmware answered with filler. A wrong number is worse than no number.
_MAX_CAPACITY_MWH = 1_000_000
_MAX_CYCLE_COUNT = 100_000

#: Guard rail: a machine cannot make the run long by presenting many battery interfaces.
_MAX_BATTERY_DEVICES = 8
#: SP_DEVICE_INTERFACE_DETAIL_DATA_W never grows past a device path; anything larger is junk.
_MAX_INTERFACE_DETAIL_BYTES = 4096

_GENERIC_READ = 0x80000000
_FILE_SHARE_READ_WRITE = 0x00000001 | 0x00000002
_OPEN_EXISTING = 3

#: Tried in order, least privilege first. Zero access is what the rest of this project uses
#: for device queries; the battery driver rejects it, so GENERIC_READ is the documented
#: fallback. The ladder is kept rather than hard-coding GENERIC_READ so that a driver which
#: does honour a zero-access handle is never handed more rights than it needs.
_ACCESS_LEVELS = (0, _GENERIC_READ)


def read_battery_health() -> dict[str, object]:
    """
    Report what the battery pack has become, as far as the firmware will say.

    Keys, every one of them optional: ``design_capacity_mwh``, ``full_charge_capacity_mwh``,
    ``cycle_count``, ``chemistry``. A key that is absent was not reported - the caller renders
    it as N/A and never scores it. The wear percentage itself is not computed here;
    :attr:`models.BatteryInfo.health_percent` derives it from the two capacities, so there is
    exactly one definition of it in the project.

    Returns an empty dict on a machine with no battery, on a non-Windows platform, and
    whenever Windows declines the query. It never raises and never asks for elevation.
    """
    if platform.system() != "Windows":
        return {}

    try:
        api = _load_api()
        if api is None:
            return {}
        for path in _battery_device_paths(api):
            try:
                values = _read_battery(api, path)
            except Exception:
                # A bay that misbehaves must not cost the pack in the next one its reading.
                continue
            if values:
                # The first pack that answers is the one reported. A second pack is not merged
                # in: the snapshot holds one battery record, and adding two packs' capacities
                # together would state a combined figure no firmware ever published - while
                # one pack answering and the other staying silent would make that total wrong.
                return values
        return {}
    except Exception:
        return {}


def _read_battery(api: Any, path: str) -> dict[str, object]:
    """Query one battery device interface, escalating access rights only when forced to."""
    for access in _ACCESS_LEVELS:
        handle = _open_battery_device(api, path, access)
        if handle is None:
            continue
        try:
            tag = _query_battery_tag(api, handle)
            if tag is None:
                # Either this access level is not enough, or the bay is empty. Both mean
                # "nothing to read here"; the next level tells the two apart.
                continue
            raw = _device_io_control(
                api,
                handle,
                _IOCTL_BATTERY_QUERY_INFORMATION,
                _build_information_query(tag),
                _BATTERY_INFORMATION_BYTES,
            )
        finally:
            _close_handle(api, handle)

        values = _decode_battery_information(raw)
        if values:
            return values
    return {}


def _build_information_query(tag: int) -> bytes:
    """Build a BATTERY_QUERY_INFORMATION asking for the BatteryInformation block."""
    # ULONG BatteryTag, enum InformationLevel, LONG AtRate. AtRate applies only to the
    # runtime-estimate levels; at this level the driver ignores it.
    return struct.pack("<IIi", int(tag), _BATTERY_INFORMATION_LEVEL, 0)


def _decode_battery_information(raw: bytes | None) -> dict[str, object]:
    """
    Decode a BATTERY_INFORMATION block into the wear figures worth reporting.

    Pure: give it 36 bytes and it needs no battery, no Windows and no ctypes. Every figure
    that fails its plausibility check is left out rather than passed on, so the caller shows
    "N/A" instead of a number nobody can trust.
    """
    if not raw or len(raw) < _BATTERY_INFORMATION_BYTES:
        return {}
    try:
        capabilities = struct.unpack_from("<I", raw, _INFORMATION_CAPABILITIES_OFFSET)[0]
        designed = struct.unpack_from("<I", raw, _INFORMATION_DESIGNED_CAPACITY_OFFSET)[0]
        full_charged = struct.unpack_from(
            "<I", raw, _INFORMATION_FULL_CHARGED_CAPACITY_OFFSET
        )[0]
        cycle_count = struct.unpack_from("<I", raw, _INFORMATION_CYCLE_COUNT_OFFSET)[0]
    except struct.error:
        return {}

    values: dict[str, object] = {}

    chemistry = _decode_chemistry(
        raw[
            _INFORMATION_CHEMISTRY_OFFSET : _INFORMATION_CHEMISTRY_OFFSET
            + _INFORMATION_CHEMISTRY_BYTES
        ]
    )
    if chemistry:
        values["chemistry"] = chemistry

    # Without BATTERY_CAPACITY_RELATIVE the capacities are milliwatt-hours; with it they are
    # numbers on an undisclosed scale. There is no conversion between the two, so the flag
    # decides whether these fields exist at all.
    if not capabilities & _BATTERY_CAPACITY_RELATIVE:
        design_mwh = _capacity_mwh(designed)
        if design_mwh is not None:
            values["design_capacity_mwh"] = design_mwh
        full_mwh = _capacity_mwh(full_charged)
        if full_mwh is not None:
            values["full_charge_capacity_mwh"] = full_mwh

    # A cycle count of zero is the driver's placeholder for "not counted", which is why it is
    # dropped instead of reported as a factory-fresh pack.
    if 0 < cycle_count <= _MAX_CYCLE_COUNT:
        values["cycle_count"] = int(cycle_count)

    return values


def _capacity_mwh(value: int) -> int | None:
    """Keep a capacity that is a real milliwatt-hour reading, or None when it is not."""
    number = int(value)
    if number <= 0 or number == _BATTERY_UNKNOWN_CAPACITY or number > _MAX_CAPACITY_MWH:
        return None
    return number


def _decode_chemistry(raw: bytes) -> str | None:
    """
    Read the four-character ACPI chemistry code, e.g. ``LION``, ``LiP``, ``NiMH``.

    The code is passed on exactly as the firmware spells it. Expanding it into "Lithium
    Polymer" would mean guessing at codes this project has never seen on real hardware.
    """
    try:
        text = raw.decode("ascii", "ignore")
    except (UnicodeDecodeError, ValueError):
        return None
    # The field is space- or NUL-padded to four bytes, and some firmware pads with junk.
    return "".join(char for char in text if char.isprintable()).strip() or None


def _load_api() -> Any | None:
    """
    Load setupapi and kernel32 with the prototypes and structures this module needs.

    Returns None on any platform that is not Windows, and on a Windows where the libraries
    cannot be loaded. The imports are deliberately local: ``ctypes.wintypes`` does not exist
    off Windows, so importing it at module scope would break the test suite's Linux run.

    Declaring argtypes is not decoration. Without them ctypes would pass a 64-bit device
    handle as a 32-bit int and every call in this module would fail.
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

        class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
            # Reserved is an ULONG_PTR; a pointer field gives it the right width and the
            # right alignment on both 32- and 64-bit Python.
            _fields_ = [
                ("cbSize", wintypes.DWORD),
                ("InterfaceClassGuid", GUID),
                ("Flags", wintypes.DWORD),
                ("Reserved", ctypes.POINTER(ctypes.c_ulong)),
            ]

        setupapi = ctypes.WinDLL("setupapi", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

        setupapi.SetupDiGetClassDevsW.argtypes = [
            ctypes.POINTER(GUID),
            wintypes.LPCWSTR,
            wintypes.HWND,
            wintypes.DWORD,
        ]
        setupapi.SetupDiGetClassDevsW.restype = wintypes.HANDLE
        setupapi.SetupDiEnumDeviceInterfaces.argtypes = [
            wintypes.HANDLE,
            ctypes.c_void_p,
            ctypes.POINTER(GUID),
            wintypes.DWORD,
            ctypes.POINTER(SP_DEVICE_INTERFACE_DATA),
        ]
        setupapi.SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL
        setupapi.SetupDiGetDeviceInterfaceDetailW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(SP_DEVICE_INTERFACE_DATA),
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD),
            ctypes.c_void_p,
        ]
        setupapi.SetupDiGetDeviceInterfaceDetailW.restype = wintypes.BOOL
        setupapi.SetupDiDestroyDeviceInfoList.argtypes = [wintypes.HANDLE]
        setupapi.SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

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

        return SimpleNamespace(
            setupapi=setupapi,
            kernel32=kernel32,
            interface_data_type=SP_DEVICE_INTERFACE_DATA,
            battery_guid=GUID(
                _BATTERY_GUID_DATA1,
                _BATTERY_GUID_DATA2,
                _BATTERY_GUID_DATA3,
                (ctypes.c_ubyte * 8)(*_BATTERY_GUID_DATA4),
            ),
        )
    except Exception:
        return None


def _battery_device_paths(api: Any) -> list[str]:
    """
    List the device paths of the batteries that are present right now.

    The device-information set is a Windows allocation, so it is destroyed in a ``finally``
    even when the enumeration goes wrong halfway through.
    """
    try:
        import ctypes

        dev_info = api.setupapi.SetupDiGetClassDevsW(
            ctypes.byref(api.battery_guid),
            None,
            None,
            _DIGCF_PRESENT | _DIGCF_DEVICEINTERFACE,
        )
        if not dev_info or dev_info == ctypes.c_void_p(-1).value:
            return []
        try:
            paths: list[str] = []
            for index in range(_MAX_BATTERY_DEVICES):
                interface = api.interface_data_type()
                interface.cbSize = ctypes.sizeof(api.interface_data_type)
                found = api.setupapi.SetupDiEnumDeviceInterfaces(
                    dev_info,
                    None,
                    ctypes.byref(api.battery_guid),
                    index,
                    ctypes.byref(interface),
                )
                if not found:  # ERROR_NO_MORE_ITEMS: the list is exhausted.
                    break
                path = _interface_detail_path(api, dev_info, interface)
                if path:
                    paths.append(path)
            return paths
        finally:
            api.setupapi.SetupDiDestroyDeviceInfoList(dev_info)
    except Exception:
        return []


def _interface_detail_path(api: Any, dev_info: Any, interface: Any) -> str | None:
    """
    Turn one device interface into the path CreateFileW can open.

    Two calls, as the API requires: the first asks how much room the answer needs, the second
    fetches it. The buffer is a raw block rather than a declared structure because
    SP_DEVICE_INTERFACE_DETAIL_DATA_W ends in a variable-length string; its ``cbSize`` must
    still be the size of the *fixed* part, which is 8 bytes on 64-bit Windows and 6 on 32-bit.
    """
    try:
        import ctypes
        from ctypes import wintypes

        required = wintypes.DWORD(0)
        # This call is expected to fail with ERROR_INSUFFICIENT_BUFFER; the size is the point.
        api.setupapi.SetupDiGetDeviceInterfaceDetailW(
            dev_info, ctypes.byref(interface), None, 0, ctypes.byref(required), None
        )
        size = int(required.value)
        if size <= 4 or size > _MAX_INTERFACE_DETAIL_BYTES:
            return None

        buffer = ctypes.create_string_buffer(size)
        fixed_part = 8 if ctypes.sizeof(ctypes.c_void_p) == 8 else 6
        ctypes.memmove(buffer, struct.pack("<I", fixed_part), 4)
        ok = api.setupapi.SetupDiGetDeviceInterfaceDetailW(
            dev_info, ctypes.byref(interface), buffer, size, None, None
        )
        if not ok:
            return None
        # DevicePath starts right after the cbSize field and is NUL-terminated.
        path = ctypes.wstring_at(ctypes.addressof(buffer) + 4)
        return path or None
    except Exception:
        return None


def _open_battery_device(api: Any, path: str, access: int) -> Any | None:
    """
    Open a battery device interface for querying, with the given access rights.

    ``access`` is 0 or GENERIC_READ - see the module docstring. GENERIC_WRITE is never
    requested here, so the handle physically cannot change a battery setting.
    """
    try:
        import ctypes

        handle = api.kernel32.CreateFileW(
            path, access, _FILE_SHARE_READ_WRITE, None, _OPEN_EXISTING, 0, None
        )
        if not handle or handle == ctypes.c_void_p(-1).value:
            return None
        return handle
    except Exception:
        return None


def _query_battery_tag(api: Any, handle: Any) -> int | None:
    """Fetch the tag of the pack in this bay, or None when there is none to read."""
    raw = _device_io_control(
        api,
        handle,
        _IOCTL_BATTERY_QUERY_TAG,
        struct.pack("<I", _QUERY_TAG_TIMEOUT_MS),
        4,
    )
    if not raw or len(raw) < 4:
        return None
    try:
        tag = struct.unpack_from("<I", raw, 0)[0]
    except struct.error:
        return None
    return int(tag) if tag != _BATTERY_TAG_INVALID else None


def _device_io_control(
    api: Any,
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
        in_buffer = ctypes.create_string_buffer(payload, len(payload)) if payload else None
        ok = api.kernel32.DeviceIoControl(
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


def _close_handle(api: Any, handle: Any) -> None:
    """Close a handle, swallowing everything: a failed close must not hide a good reading."""
    try:
        api.kernel32.CloseHandle(handle)
    except Exception:
        pass
