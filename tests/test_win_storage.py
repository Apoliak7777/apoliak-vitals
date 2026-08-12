"""Tests for the read-only drive health collector in src/win_storage.py.

Two halves, deliberately separated.

The decoders are pure ``bytes -> value`` functions, so they are tested against buffers this
module builds itself: an NVMe SMART log page and a STORAGE_DEVICE_DESCRIPTOR assembled byte
by byte. Every offset is asserted by moving one field and watching exactly one value change,
which is what makes these tests fail when an offset drifts rather than merely when the code
raises. The 128-bit fields are checked with a value whose high half is set, because a
decoder that read only eight bytes would report a perfectly plausible number instead.

The collector itself is tested through the three seams the module documents -
``_load_kernel32``, ``_open_device`` and ``_device_io_control`` - so the whole of Windows is
replaced by a described machine and the suite behaves identically on a laptop with an NVMe
drive, a desktop with a SATA one, and a non-Windows host.
"""

from __future__ import annotations

import struct
import unittest
from typing import Any
from unittest.mock import patch

from src import win_storage
from src.models import DriveHealth
from src.win_storage import (
    _build_nvme_health_query,
    _build_property_query,
    _compose_model,
    _decode_device_descriptor,
    _decode_disk_number,
    _decode_nvme_health,
    _decode_seek_penalty,
    _drive_letter,
    _extract_protocol_log,
    _open_device,
    _requested_letters,
    read_drive_health,
)

#: Control codes, repeated here rather than imported: a test that reads the constant it is
#: checking cannot notice the constant changing.
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x560000
IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400

STORAGE_DEVICE_PROPERTY = 0
STORAGE_DEVICE_SEEK_PENALTY_PROPERTY = 7
STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY = 49

NVME_LOG_BYTES = 512
NVME_DATA_UNIT_BYTES = 1000 * 512

#: Kelvin the NVMe log reports for a drive running at 41 °C.
WARM_KELVIN = 314


def nvme_log(
    *,
    critical_warning: int = 0,
    kelvin: int = WARM_KELVIN,
    percentage_used: int = 6,
    data_units_written: int = 90_000,
    power_on_hours: int = 4_210,
) -> bytes:
    """Build one NVMe SMART / Health Information log page (log page 02h).

    Written from the specification's offsets rather than from the module's constants, so the
    two have to agree for the tests to pass.
    """
    log = bytearray(NVME_LOG_BYTES)
    log[0] = critical_warning & 0xFF
    struct.pack_into("<H", log, 1, kelvin)  # Composite Temperature, in Kelvin
    log[5] = percentage_used & 0xFF
    log[48:64] = int(data_units_written).to_bytes(16, "little")  # Data Units Written, 128-bit
    log[128:144] = int(power_on_hours).to_bytes(16, "little")  # Power On Hours, 128-bit
    return bytes(log)


def protocol_response(
    log: bytes,
    *,
    protocol_type: int = 3,
    data_type: int = 2,
    request_value: int = 0x02,
    data_offset: int = 40,
    data_length: int | None = None,
) -> bytes:
    """Wrap a log page in the STORAGE_PROTOCOL_DATA_DESCRIPTOR the driver answers with."""
    length = len(log) if data_length is None else data_length
    header = struct.pack("<II", 1, 48 + len(log))  # Version, Size
    protocol = struct.pack(
        "<10I",
        protocol_type,
        data_type,
        request_value,
        0,
        data_offset,
        length,
        0,
        0,
        0,
        0,
    )
    return header + protocol + log


def device_descriptor(
    *,
    vendor: str | None = "TESTCORP",
    product: str | None = "Test NVMe 1TB",
    serial: str | None = "SN-0123456789",
    bus_type: int = 17,
) -> bytes:
    """Build a STORAGE_DEVICE_DESCRIPTOR with its trailing NUL-terminated strings.

    ``serial`` is written into the buffer on purpose: the decoder must walk straight past it,
    and a test that never supplied one could not prove that.
    """
    header = bytearray(36)
    strings = bytearray()

    def place(text: str | None) -> int:
        if text is None:
            return 0
        offset = 36 + len(strings)
        strings.extend(text.encode("latin-1") + b"\x00")
        return offset

    vendor_offset = place(vendor)
    product_offset = place(product)
    serial_offset = place(serial)

    struct.pack_into("<I", header, 0, 36)  # Version
    struct.pack_into("<I", header, 4, 36 + len(strings))  # Size
    header[8] = 0  # DeviceType
    struct.pack_into("<I", header, 12, vendor_offset)  # VendorIdOffset
    struct.pack_into("<I", header, 16, product_offset)  # ProductIdOffset
    struct.pack_into("<I", header, 20, 0)  # ProductRevisionOffset
    struct.pack_into("<I", header, 24, serial_offset)  # SerialNumberOffset
    struct.pack_into("<I", header, 28, bus_type)  # BusType
    return bytes(header + strings)


def disk_extents(disk_number: int = 0, count: int = 1) -> bytes:
    """Build a VOLUME_DISK_EXTENTS answer: a count, four bytes of padding, then the extent."""
    buffer = bytearray(8 + 24)
    struct.pack_into("<I", buffer, 0, count)
    struct.pack_into("<I", buffer, 8, disk_number)  # DISK_EXTENT.DiskNumber
    return bytes(buffer)


def seek_penalty(incurs: bool) -> bytes:
    """DEVICE_SEEK_PENALTY_DESCRIPTOR: Version, Size, then the BOOLEAN at offset 8."""
    buffer = bytearray(12)
    struct.pack_into("<II", buffer, 0, 12, 12)
    buffer[8] = 1 if incurs else 0
    return bytes(buffer)


class NvmeHealthDecodingTests(unittest.TestCase):
    """The log page, byte by byte. These offsets are the whole measurement."""

    def decode(self, **overrides: object) -> dict[str, object]:
        return _decode_nvme_health(nvme_log(**overrides))  # type: ignore[arg-type]

    def test_a_healthy_drive_decodes_every_documented_figure(self) -> None:
        values = self.decode()
        self.assertEqual(
            values,
            {
                "critical_warning": False,
                "temperature_celsius": WARM_KELVIN - 273,
                "percentage_used": 6,
                "data_written_bytes": 90_000 * NVME_DATA_UNIT_BYTES,
                "power_on_hours": 4_210,
            },
        )

    def test_kelvin_is_converted_to_celsius(self) -> None:
        for kelvin, celsius in ((273, 0), (293, 20), (WARM_KELVIN, 41), (398, 125), (233, -40)):
            with self.subTest(kelvin=kelvin):
                self.assertEqual(self.decode(kelvin=kelvin)["temperature_celsius"], celsius)

    def test_an_implausible_temperature_is_dropped_rather_than_reported(self) -> None:
        # Outside the NVMe operating range the offsets are wrong or the controller answered
        # with filler, and a wrong number is worse than no number.
        for kelvin in (0, 1, 232, 399, 40_000, 0xFFFF):
            with self.subTest(kelvin=kelvin):
                self.assertNotIn("temperature_celsius", self.decode(kelvin=kelvin))

    def test_the_temperature_really_lives_at_offset_one(self) -> None:
        # Two bytes at offset 1, little-endian: reading them at 0 or at 2 gives a different
        # number, so this fails the moment the offset drifts.
        log = bytearray(nvme_log(kelvin=WARM_KELVIN))
        self.assertEqual(struct.unpack_from("<H", log, 1)[0], WARM_KELVIN)
        log[1] = (WARM_KELVIN + 1) & 0xFF
        self.assertEqual(_decode_nvme_health(bytes(log))["temperature_celsius"], 42)

    def test_the_critical_warning_is_the_first_byte(self) -> None:
        self.assertIs(self.decode(critical_warning=0)["critical_warning"], False)
        for raised in (1, 0x02, 0x10, 0xFF):
            with self.subTest(bits=raised):
                self.assertIs(self.decode(critical_warning=raised)["critical_warning"], True)

    def test_percentage_used_is_a_single_byte_at_offset_five(self) -> None:
        for used in (0, 1, 6, 94, 100):
            with self.subTest(used=used):
                self.assertEqual(self.decode(percentage_used=used)["percentage_used"], used)

    def test_a_drive_past_its_rated_endurance_reports_fully_used(self) -> None:
        # The specification allows values above 100%: the drive has outlived its rating.
        for used in (101, 150, 255):
            with self.subTest(used=used):
                self.assertEqual(self.decode(percentage_used=used)["percentage_used"], 100)

    def test_data_written_is_counted_in_units_of_512_000_bytes(self) -> None:
        self.assertEqual(
            self.decode(data_units_written=1)["data_written_bytes"], NVME_DATA_UNIT_BYTES
        )
        self.assertEqual(self.decode(data_units_written=0)["data_written_bytes"], 0)

    def test_the_two_128_bit_fields_are_read_across_all_sixteen_bytes(self) -> None:
        # A decoder that read only the low eight bytes would report 5 hours and 5 units -
        # both perfectly plausible - instead of noticing the figure is impossible. Rejecting
        # them is the point: the application says nothing rather than something wrong.
        beyond_64_bits = (1 << 64) + 5
        values = self.decode(
            data_units_written=beyond_64_bits, power_on_hours=beyond_64_bits
        )
        self.assertNotIn("power_on_hours", values)
        self.assertNotIn("data_written_bytes", values)

    def test_the_128_bit_fields_are_little_endian(self) -> None:
        log = bytearray(nvme_log(power_on_hours=0, data_units_written=0))
        log[128] = 0x01  # least significant byte first
        log[48] = 0x02
        values = _decode_nvme_health(bytes(log))
        self.assertEqual(values["power_on_hours"], 1)
        self.assertEqual(values["data_written_bytes"], 2 * NVME_DATA_UNIT_BYTES)

    def test_an_implausible_lifetime_is_dropped(self) -> None:
        self.assertEqual(self.decode(power_on_hours=1_000_000)["power_on_hours"], 1_000_000)
        self.assertNotIn("power_on_hours", self.decode(power_on_hours=1_000_001))

    def test_an_implausible_written_total_is_dropped(self) -> None:
        # 10^18 bytes is an exabyte; no drive this application will meet has written more.
        limit_units = 10**18 // NVME_DATA_UNIT_BYTES
        self.assertIn("data_written_bytes", self.decode(data_units_written=limit_units))
        self.assertNotIn("data_written_bytes", self.decode(data_units_written=limit_units + 1))

    def test_a_page_of_zeros_is_not_a_measurement(self) -> None:
        # A controller that answered with an empty buffer said nothing; reporting "0% used,
        # 0 hours, no warning" would turn silence into a brand-new drive.
        self.assertEqual(_decode_nvme_health(bytes(NVME_LOG_BYTES)), {})

    def test_a_page_too_short_to_carry_the_figures_is_refused(self) -> None:
        full = nvme_log()
        self.assertEqual(_decode_nvme_health(full[:143]), {})
        self.assertEqual(_decode_nvme_health(b""), {})
        # 144 bytes is exactly enough for the power-on hours to be complete.
        self.assertEqual(_decode_nvme_health(full[:144])["power_on_hours"], 4_210)


class ProtocolDescriptorTests(unittest.TestCase):
    def test_a_well_formed_answer_yields_the_log_page(self) -> None:
        log = nvme_log()
        self.assertEqual(_extract_protocol_log(protocol_response(log)), log)

    def test_an_answer_about_something_else_is_refused(self) -> None:
        log = nvme_log()
        for label, fields in (
            ("a different protocol", {"protocol_type": 1}),
            ("an identify page, not a log page", {"data_type": 1}),
            ("a different log page", {"request_value": 0x01}),
            ("an offset inside the protocol block", {"data_offset": 8}),
            ("no data at all", {"data_length": 0}),
        ):
            with self.subTest(case=label):
                self.assertIsNone(_extract_protocol_log(protocol_response(log, **fields)))

    def test_a_length_that_runs_past_the_buffer_is_refused(self) -> None:
        raw = protocol_response(nvme_log())[:200]
        self.assertIsNone(_extract_protocol_log(raw))

    def test_a_short_or_missing_answer_is_refused(self) -> None:
        self.assertIsNone(_extract_protocol_log(None))
        self.assertIsNone(_extract_protocol_log(b""))
        self.assertIsNone(_extract_protocol_log(b"\x00" * 47))

    def test_the_slice_never_exceeds_one_log_page(self) -> None:
        # A controller claiming a longer page must not make the decoder read past 512 bytes.
        raw = protocol_response(nvme_log() + b"\xff" * 64, data_length=NVME_LOG_BYTES + 64)
        log = _extract_protocol_log(raw)
        assert log is not None
        self.assertEqual(len(log), NVME_LOG_BYTES)


class QueryBuildingTests(unittest.TestCase):
    def test_a_property_query_is_a_padded_twelve_byte_block(self) -> None:
        query = _build_property_query(STORAGE_DEVICE_PROPERTY)
        self.assertEqual(len(query), 12)
        self.assertEqual(struct.unpack_from("<II", query, 0), (STORAGE_DEVICE_PROPERTY, 0))
        self.assertEqual(query[8:], b"\x00" * 4)

    def test_the_health_query_asks_for_the_smart_log_page(self) -> None:
        query = _build_nvme_health_query()
        self.assertEqual(len(query), 8 + 40 + NVME_LOG_BYTES)
        property_id, query_type = struct.unpack_from("<II", query, 0)
        self.assertEqual(property_id, STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY)
        self.assertEqual(query_type, 0)  # PropertyStandardQuery
        protocol = struct.unpack_from("<10I", query, 8)
        self.assertEqual(protocol[0], 3)  # ProtocolTypeNvme
        self.assertEqual(protocol[1], 2)  # NVMeDataTypeLogPage
        self.assertEqual(protocol[2], 0x02)  # SMART / Health Information
        self.assertEqual(protocol[4], 40)  # ProtocolDataOffset, from the protocol block
        self.assertEqual(protocol[5], NVME_LOG_BYTES)

    def test_the_query_the_module_builds_is_the_one_the_decoder_accepts(self) -> None:
        # A driver that echoes the request buffer back with the log page filled in is the
        # normal case, so the two halves have to fit each other exactly.
        payload = bytearray(_build_nvme_health_query())
        payload[48 : 48 + NVME_LOG_BYTES] = nvme_log()
        self.assertEqual(_extract_protocol_log(bytes(payload)), nvme_log())


class DeviceDescriptorTests(unittest.TestCase):
    def test_vendor_and_product_are_joined_into_a_model(self) -> None:
        model, bus = _decode_device_descriptor(device_descriptor())
        self.assertEqual(model, "TESTCORP Test NVMe 1TB")
        self.assertEqual(bus, "NVMe")

    def test_the_serial_number_is_never_read(self) -> None:
        # The descriptor carries one at offset 24 and this application collects no hardware
        # identifier, so it may not appear in any field the decoder returns.
        serial = "SN-DEADBEEF-0001"
        model, bus = _decode_device_descriptor(device_descriptor(serial=serial))
        self.assertNotIn(serial, str(model))
        self.assertNotIn(serial, str(bus))
        self.assertNotIn("SN-", str(model))

    def test_the_bus_type_is_read_at_offset_28(self) -> None:
        for value, name in ((3, "ATA"), (7, "USB"), (11, "SATA"), (17, "NVMe"), (19, "UFS")):
            with self.subTest(bus_type=value):
                descriptor = device_descriptor(bus_type=value)
                self.assertEqual(_decode_device_descriptor(descriptor)[1], name)

    def test_an_unlisted_bus_type_stays_unknown_instead_of_being_guessed(self) -> None:
        self.assertIsNone(_decode_device_descriptor(device_descriptor(bus_type=99))[1])

    def test_a_vendor_that_only_repeats_the_bus_is_dropped(self) -> None:
        model, _ = _decode_device_descriptor(device_descriptor(vendor="NVMe"))
        self.assertEqual(model, "Test NVMe 1TB")

    def test_firmware_padding_is_trimmed(self) -> None:
        model, _ = _decode_device_descriptor(
            device_descriptor(vendor="  ", product="  Test   SSD  ")
        )
        self.assertEqual(model, "Test SSD")

    def test_a_descriptor_without_strings_reports_no_model(self) -> None:
        model, bus = _decode_device_descriptor(device_descriptor(vendor=None, product=None))
        self.assertIsNone(model)
        self.assertEqual(bus, "NVMe")

    def test_a_short_or_missing_descriptor_is_refused(self) -> None:
        self.assertEqual(_decode_device_descriptor(None), (None, None))
        self.assertEqual(_decode_device_descriptor(b""), (None, None))
        self.assertEqual(_decode_device_descriptor(b"\x00" * 35), (None, None))

    def test_compose_model_rules(self) -> None:
        cases = (
            (("Samsung", "SSD 990 PRO"), "Samsung SSD 990 PRO"),
            (("Samsung", "Samsung SSD 990"), "Samsung SSD 990"),  # Not repeated twice.
            ((None, "SSD 990 PRO"), "SSD 990 PRO"),
            (("ATA", "WDC WD10"), "WDC WD10"),
            (("Kingston", None), "Kingston"),
            (("ATA", None), None),  # The bus is not a model.
            ((None, None), None),
        )
        for (vendor, product), expected in cases:
            with self.subTest(vendor=vendor, product=product):
                self.assertEqual(_compose_model(vendor, product), expected)


class VolumeMappingTests(unittest.TestCase):
    def test_a_single_extent_yields_its_disk_number(self) -> None:
        for number in (0, 1, 7, 255):
            with self.subTest(disk=number):
                self.assertEqual(_decode_disk_number(disk_extents(number)), number)

    def test_a_volume_spanning_several_disks_has_no_single_answer(self) -> None:
        self.assertIsNone(_decode_disk_number(disk_extents(0, count=2)))
        self.assertIsNone(_decode_disk_number(disk_extents(0, count=0)))

    def test_an_impossible_disk_number_is_refused(self) -> None:
        self.assertIsNone(_decode_disk_number(disk_extents(256)))
        self.assertIsNone(_decode_disk_number(disk_extents(0xFFFFFFFF)))

    def test_a_short_or_missing_buffer_is_refused(self) -> None:
        self.assertIsNone(_decode_disk_number(None))
        self.assertIsNone(_decode_disk_number(b""))
        self.assertIsNone(_decode_disk_number(b"\x01\x00\x00\x00\x00\x00\x00\x00"))

    def test_the_extent_array_starts_after_four_bytes_of_padding(self) -> None:
        # The DWORD count is followed by padding, because the extent's LONGLONG members
        # force 8-byte alignment. Reading the number at offset 4 would give the padding.
        buffer = bytearray(disk_extents(3))
        self.assertEqual(buffer[4:8], b"\x00\x00\x00\x00")
        self.assertEqual(_decode_disk_number(bytes(buffer)), 3)


class SeekPenaltyTests(unittest.TestCase):
    def test_a_rotating_disk_is_reported_as_an_hdd(self) -> None:
        self.assertEqual(_decode_seek_penalty(seek_penalty(True)), "HDD")

    def test_a_drive_without_a_seek_penalty_is_an_ssd(self) -> None:
        self.assertEqual(_decode_seek_penalty(seek_penalty(False)), "SSD")

    def test_a_refused_query_leaves_the_media_type_unknown(self) -> None:
        self.assertIsNone(_decode_seek_penalty(None))
        self.assertIsNone(_decode_seek_penalty(b""))
        self.assertIsNone(_decode_seek_penalty(b"\x00" * 8))


class DriveLetterTests(unittest.TestCase):
    def test_every_way_a_drive_can_be_written(self) -> None:
        for value, expected in (
            ("C:\\", "C"),
            ("c:", "C"),
            ("D", "D"),
            ("  e:\\  ", "E"),
            ("", None),
            ("  ", None),
            (None, None),
            (r"\\server\share", None),
            ("1:", None),
        ):
            with self.subTest(value=value):
                self.assertEqual(_drive_letter(value), expected)

    def test_a_requested_list_is_normalised_and_deduplicated(self) -> None:
        letters = _requested_letters(object(), ["C:\\", "c:", "D:", r"\\server\share", "E"])
        self.assertEqual(letters, ["C", "D", "E"])

    def test_an_empty_request_asks_about_nothing(self) -> None:
        self.assertEqual(_requested_letters(object(), []), [])


class FakeWindows:
    """A described machine standing in for the three Win32 seams of win_storage.

    ``volumes`` maps a drive letter to the physical disk behind it, ``disks`` maps a disk
    number to the answers that disk gives. Anything absent is a device that refuses to open,
    which is exactly what a locked-down or unusual machine produces.
    """

    def __init__(
        self,
        *,
        letters: str = "C",
        fixed: str | None = None,
        volumes: dict[str, int] | None = None,
        disks: dict[int, dict[str, bytes | None]] | None = None,
        unopenable: tuple[str, ...] = (),
    ) -> None:
        self.letters = letters
        self.fixed = letters if fixed is None else fixed
        self.volumes = volumes if volumes is not None else {"C": 0}
        self.disks = disks if disks is not None else {0: self.healthy_disk()}
        self.unopenable = unopenable
        self.opened: list[str] = []
        self.closed: list[str] = []
        self.queries: list[tuple[str, int]] = []

    @staticmethod
    def healthy_disk(**overrides: object) -> dict[str, bytes | None]:
        answers: dict[str, bytes | None] = {
            "descriptor": device_descriptor(),
            "seek": seek_penalty(False),
            "nvme": protocol_response(nvme_log()),
        }
        answers.update(overrides)  # type: ignore[arg-type]
        return answers

    # -- the seams ---------------------------------------------------------------------

    def load(self) -> Any:
        return self

    def GetLogicalDrives(self) -> int:  # noqa: N802 - the Win32 name is the contract
        mask = 0
        for letter in self.letters:
            mask |= 1 << (ord(letter.upper()) - ord("A"))
        return mask

    def GetDriveTypeW(self, root: str) -> int:  # noqa: N802
        return 3 if root[0].upper() in self.fixed else 2  # DRIVE_FIXED / DRIVE_REMOVABLE

    def open(self, kernel32: Any, path: str) -> Any:
        if path in self.unopenable:
            return None
        letter = path.rsplit("\\", 1)[-1]
        if letter.endswith(":") and letter[0].upper() not in self.volumes:
            return None
        self.opened.append(path)
        return path

    def io(
        self, kernel32: Any, handle: Any, code: int, payload: bytes, out_size: int
    ) -> bytes | None:
        self.queries.append((str(handle), code))
        if code == IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS:
            letter = str(handle).rsplit("\\", 1)[-1][0].upper()
            number = self.volumes.get(letter)
            return None if number is None else disk_extents(number)

        number = int(str(handle).rsplit("PhysicalDrive", 1)[-1])
        answers = self.disks.get(number, {})
        property_id = struct.unpack_from("<I", payload, 0)[0] if payload else -1
        if property_id == STORAGE_DEVICE_PROPERTY:
            return answers.get("descriptor")
        if property_id == STORAGE_DEVICE_SEEK_PENALTY_PROPERTY:
            return answers.get("seek")
        if property_id == STORAGE_DEVICE_PROTOCOL_SPECIFIC_PROPERTY:
            return answers.get("nvme")
        return None

    def close(self, kernel32: Any, handle: Any) -> None:
        self.closed.append(str(handle))


class ReadDriveHealthTests(unittest.TestCase):
    """The collector, with the whole operating system replaced by a described machine."""

    def read(self, machine: FakeWindows, drives: object = None) -> list[DriveHealth]:
        with patch.object(win_storage.platform, "system", return_value="Windows"):
            with patch.object(win_storage, "_load_kernel32", machine.load):
                with patch.object(win_storage, "_open_device", machine.open):
                    with patch.object(win_storage, "_device_io_control", machine.io):
                        with patch.object(win_storage, "_close_handle", machine.close):
                            return read_drive_health(drives)  # type: ignore[arg-type]

    def test_one_healthy_nvme_drive_is_described_in_full(self) -> None:
        entries = self.read(FakeWindows(), ["C:\\"])
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.drive, "C:\\")
        self.assertEqual(entry.model, "TESTCORP Test NVMe 1TB")
        self.assertEqual(entry.bus_type, "NVMe")
        self.assertEqual(entry.media_type, "SSD")
        self.assertEqual(entry.percentage_used, 6)
        self.assertEqual(entry.life_left_percent, 94)
        self.assertEqual(entry.temperature_celsius, 41)
        self.assertEqual(entry.power_on_hours, 4_210)
        self.assertIs(entry.critical_warning, False)
        self.assertEqual(entry.source, "NVMe SMART log")

    def test_a_sata_drive_that_refuses_the_log_page_still_reports_its_identity(self) -> None:
        machine = FakeWindows(
            disks={
                0: {
                    "descriptor": device_descriptor(vendor="ATA", product="WDC WD10", bus_type=11),
                    "seek": seek_penalty(True),
                    "nvme": None,  # The controller filters the pass-through.
                }
            }
        )
        entry = self.read(machine, ["C:\\"])[0]
        self.assertEqual(entry.model, "WDC WD10")
        self.assertEqual(entry.bus_type, "SATA")
        self.assertEqual(entry.media_type, "HDD")
        self.assertIsNone(entry.percentage_used)
        self.assertIsNone(entry.life_left_percent)
        self.assertIsNone(entry.critical_warning)
        self.assertIsNone(entry.source)  # No figure came from anywhere, so nothing is claimed.

    def test_two_volumes_on_one_disk_are_reported_once(self) -> None:
        machine = FakeWindows(letters="CD", volumes={"C": 0, "D": 0})
        entries = self.read(machine, ["C:\\", "D:\\"])
        self.assertEqual([entry.drive for entry in entries], ["C:\\"])

    def test_two_disks_are_reported_separately(self) -> None:
        machine = FakeWindows(
            letters="CD",
            volumes={"C": 0, "D": 1},
            disks={
                0: FakeWindows.healthy_disk(),
                1: FakeWindows.healthy_disk(
                    descriptor=device_descriptor(product="Test SATA 2TB", bus_type=11)
                ),
            },
        )
        entries = self.read(machine, ["C:\\", "D:\\"])
        self.assertEqual([entry.drive for entry in entries], ["C:\\", "D:\\"])
        self.assertEqual(entries[1].bus_type, "SATA")

    def test_a_disk_that_answers_nothing_at_all_is_left_out(self) -> None:
        # A row of N/A next to a drive letter is noise, not a measurement.
        machine = FakeWindows(disks={0: {"descriptor": None, "seek": None, "nvme": None}})
        self.assertEqual(self.read(machine, ["C:\\"]), [])

    def test_a_volume_that_cannot_be_opened_costs_only_itself(self) -> None:
        machine = FakeWindows(
            letters="CD", volumes={"C": 0, "D": 1}, disks={0: FakeWindows.healthy_disk()},
            unopenable=(r"\\.\D:",),
        )
        entries = self.read(machine, ["C:\\", "D:\\"])
        self.assertEqual([entry.drive for entry in entries], ["C:\\"])

    def test_a_device_that_explodes_never_reaches_the_caller(self) -> None:
        machine = FakeWindows()

        def hostile(*args: object, **kwargs: object) -> bytes:
            raise OSError("the device went away")

        with patch.object(win_storage.platform, "system", return_value="Windows"):
            with patch.object(win_storage, "_load_kernel32", machine.load):
                with patch.object(win_storage, "_open_device", machine.open):
                    with patch.object(win_storage, "_device_io_control", hostile):
                        self.assertEqual(read_drive_health(["C:\\"]), [])

    def test_every_handle_that_was_opened_is_closed_again(self) -> None:
        machine = FakeWindows()
        self.read(machine, ["C:\\"])
        self.assertEqual(sorted(machine.closed), sorted(machine.opened))
        self.assertIn(r"\\.\PhysicalDrive0", machine.opened)

    def test_without_a_list_the_fixed_drives_are_enumerated(self) -> None:
        machine = FakeWindows(letters="ACD", fixed="AC", volumes={"C": 0, "A": 2, "D": 1})
        entries = self.read(machine, None)
        # A: is fixed in this fixture but answers nothing; D: is removable and never asked.
        self.assertEqual([entry.drive for entry in entries], ["C:\\"])
        self.assertNotIn(r"\\.\D:", machine.opened)

    def test_a_kernel32_that_will_not_load_reports_nothing(self) -> None:
        with patch.object(win_storage.platform, "system", return_value="Windows"):
            with patch.object(win_storage, "_load_kernel32", return_value=None):
                self.assertEqual(read_drive_health(["C:\\"]), [])

    def test_a_machine_that_is_not_windows_reports_nothing(self) -> None:
        for system in ("Linux", "Darwin", "", "Java"):
            with self.subTest(system=system):
                with patch.object(win_storage.platform, "system", return_value=system):
                    self.assertEqual(read_drive_health(None), [])
                    self.assertEqual(read_drive_health(["C:\\"]), [])

    def test_the_platform_is_checked_before_any_library_is_loaded(self) -> None:
        with patch.object(win_storage.platform, "system", return_value="Linux"):
            with patch.object(win_storage, "_load_kernel32") as loader:
                self.assertEqual(read_drive_health(None), [])
        loader.assert_not_called()

    def test_the_number_of_drives_is_capped(self) -> None:
        letters = "ABCDEFGHIJKLMNOPQRST"
        machine = FakeWindows(
            letters=letters,
            volumes={letter: index for index, letter in enumerate(letters)},
            disks={index: FakeWindows.healthy_disk() for index in range(len(letters))},
        )
        self.assertLessEqual(len(self.read(machine, None)), 16)

    def test_a_reader_that_is_handed_nonsense_still_never_raises(self) -> None:
        machine = FakeWindows()
        for drives in ([], [None], [123], ["", "  "], [r"\\server\share"]):
            with self.subTest(drives=drives):
                self.assertEqual(self.read(machine, drives), [])


class AccessRightsTests(unittest.TestCase):
    """No elevation, ever: every device handle is opened with no access rights at all."""

    def test_a_device_is_opened_with_zero_desired_access(self) -> None:
        recorded: list[tuple[object, ...]] = []

        class Recorder:
            @staticmethod
            def CreateFileW(*args: object) -> int:  # noqa: N802 - the Win32 name
                recorded.append(args)
                return 7

        handle = _open_device(Recorder(), r"\\.\PhysicalDrive0")
        self.assertEqual(handle, 7)
        self.assertEqual(len(recorded), 1)
        path, access, share, security, disposition, flags, template = recorded[0]
        self.assertEqual(path, r"\\.\PhysicalDrive0")
        self.assertEqual(access, 0, "a metadata query needs no access rights at all")
        self.assertEqual(disposition, 3)  # OPEN_EXISTING: never creates a device
        self.assertIsNone(template)

    def test_a_refused_open_is_none_rather_than_an_exception(self) -> None:
        class Refusing:
            @staticmethod
            def CreateFileW(*args: object) -> int:  # noqa: N802
                return 0

        class Exploding:
            @staticmethod
            def CreateFileW(*args: object) -> int:  # noqa: N802
                raise OSError("access denied")

        self.assertIsNone(_open_device(Refusing(), r"\\.\PhysicalDrive0"))
        self.assertIsNone(_open_device(Exploding(), r"\\.\PhysicalDrive0"))

    def test_the_module_never_names_a_write_or_a_generic_right(self) -> None:
        # Asserted against the source: a read-only collector may not so much as mention
        # GENERIC_WRITE, and the two control codes it uses are queries.
        source = win_storage.__file__
        with open(source, "r", encoding="utf-8") as handle:
            text = handle.read()
        for forbidden in ("GENERIC_WRITE", "0x40000000", "FILE_WRITE", "SetupDiSetDevice"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
