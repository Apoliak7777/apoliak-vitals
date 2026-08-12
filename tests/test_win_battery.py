"""Tests for the read-only battery wear collector in src/win_battery.py.

The valuable half is the decoder: ``BATTERY_INFORMATION`` is 36 bytes with six fields this
module cares about, and every offset here is asserted by moving one field and watching
exactly one value change. A buffer built from the Windows header - rather than from the
module's own constants - is what makes these tests fail when an offset drifts.

The collector is driven through the seams the module documents (``_load_api``,
``_open_battery_device``, ``_device_io_control``), so a desktop with no battery, a laptop
with one, and a non-Windows host all run the same assertions.
"""

from __future__ import annotations

import struct
import unittest
from typing import Any
from unittest.mock import patch

from src import win_battery
from src.win_battery import (
    _build_information_query,
    _decode_battery_information,
    _decode_chemistry,
    _query_battery_tag,
    read_battery_health,
)

#: Repeated from the Windows headers rather than imported: a test that reads the constant it
#: checks cannot notice the constant changing.
BATTERY_CAPACITY_RELATIVE = 0x40000000
BATTERY_UNKNOWN_CAPACITY = 0xFFFFFFFF
GENERIC_READ = 0x80000000

IOCTL_BATTERY_QUERY_TAG = 0x294040
IOCTL_BATTERY_QUERY_INFORMATION = 0x294044

DEVICE_PATH = r"\\?\ACPI#PNP0C0A#1#{72631e54-78a4-11d0-bcf7-00aa00b7b32a}"


def battery_information(
    *,
    capabilities: int = 0,
    technology: int = 1,
    chemistry: bytes = b"LION",
    designed: int = 99_000,
    full_charged: int = 74_250,
    cycle_count: int = 231,
) -> bytes:
    """Build a BATTERY_INFORMATION block exactly as batclass.h lays it out.

    ULONG Capabilities; UCHAR Technology; UCHAR Reserved1[3]; UCHAR Chemistry[4];
    ULONG DesignedCapacity; ULONG FullChargedCapacity; ULONG DefaultAlert1;
    ULONG DefaultAlert2; ULONG CriticalBias; ULONG CycleCount.
    """
    buffer = bytearray(36)
    struct.pack_into("<I", buffer, 0, capabilities)
    buffer[4] = technology
    buffer[5:8] = b"\x00\x00\x00"  # Reserved1
    buffer[8:12] = chemistry.ljust(4, b"\x00")[:4]
    struct.pack_into("<I", buffer, 12, designed)
    struct.pack_into("<I", buffer, 16, full_charged)
    struct.pack_into("<I", buffer, 20, 7_500)  # DefaultAlert1 - never read
    struct.pack_into("<I", buffer, 24, 3_000)  # DefaultAlert2 - never read
    struct.pack_into("<I", buffer, 28, 100)  # CriticalBias - never read
    struct.pack_into("<I", buffer, 32, cycle_count)
    return bytes(buffer)


class InformationDecodingTests(unittest.TestCase):
    """The 36-byte block, field by field."""

    def decode(self, **overrides: object) -> dict[str, object]:
        raw = battery_information(**overrides)  # type: ignore[arg-type]
        return _decode_battery_information(raw)

    def test_a_worn_pack_decodes_every_documented_figure(self) -> None:
        self.assertEqual(
            self.decode(),
            {
                "chemistry": "LION",
                "design_capacity_mwh": 99_000,
                "full_charge_capacity_mwh": 74_250,
                "cycle_count": 231,
            },
        )

    def test_the_capacities_are_read_at_offsets_twelve_and_sixteen(self) -> None:
        # Swapping the two proves neither is read from the other's offset.
        values = self.decode(designed=80_000, full_charged=41_000)
        self.assertEqual(values["design_capacity_mwh"], 80_000)
        self.assertEqual(values["full_charge_capacity_mwh"], 41_000)

    def test_the_cycle_count_is_the_last_field_of_the_block(self) -> None:
        raw = bytearray(battery_information(cycle_count=0))
        self.assertNotIn("cycle_count", _decode_battery_information(bytes(raw)))
        struct.pack_into("<I", raw, 32, 412)
        self.assertEqual(_decode_battery_information(bytes(raw))["cycle_count"], 412)

    def test_the_fields_between_the_capacities_and_the_cycles_are_never_read(self) -> None:
        # DefaultAlert1/2 and CriticalBias sit at 20, 24 and 28. Changing them may not move
        # a single reported figure - if it did, an offset would be off by one field.
        baseline = self.decode()
        raw = bytearray(battery_information())
        for offset in (20, 24, 28):
            struct.pack_into("<I", raw, offset, 0xDEADBEEF)
        self.assertEqual(_decode_battery_information(bytes(raw)), baseline)

    def test_the_technology_byte_and_its_padding_are_never_read(self) -> None:
        baseline = self.decode()
        raw = bytearray(battery_information())
        raw[4] = 0xFF
        raw[5:8] = b"\xff\xff\xff"
        self.assertEqual(_decode_battery_information(bytes(raw)), baseline)

    def test_a_relative_pack_reports_no_capacity_at_all(self) -> None:
        # With BATTERY_CAPACITY_RELATIVE the capacities carry no unit; calling them mWh
        # would be an invented measurement, so both fields simply do not exist.
        values = self.decode(capabilities=BATTERY_CAPACITY_RELATIVE)
        self.assertNotIn("design_capacity_mwh", values)
        self.assertNotIn("full_charge_capacity_mwh", values)
        # The unit-free figures survive: they mean the same thing on either scale.
        self.assertEqual(values["chemistry"], "LION")
        self.assertEqual(values["cycle_count"], 231)

    def test_other_capability_bits_do_not_hide_the_capacities(self) -> None:
        for bit in (0x00000001, 0x00000002, 0x00000004, 0x80000000):
            with self.subTest(capabilities=hex(bit)):
                self.assertIn("design_capacity_mwh", self.decode(capabilities=bit))

    def test_the_drivers_own_unknown_marker_is_not_a_capacity(self) -> None:
        unknown = BATTERY_UNKNOWN_CAPACITY
        values = self.decode(designed=unknown, full_charged=unknown)
        self.assertNotIn("design_capacity_mwh", values)
        self.assertNotIn("full_charge_capacity_mwh", values)

    def test_a_capacity_of_zero_is_a_placeholder_not_an_empty_pack(self) -> None:
        values = self.decode(designed=0, full_charged=0)
        self.assertNotIn("design_capacity_mwh", values)
        self.assertNotIn("full_charge_capacity_mwh", values)

    def test_an_implausible_capacity_is_refused(self) -> None:
        # 1 000 000 mWh is a 1 kWh pack: an order of magnitude past the largest laptop
        # battery ever built, so anything above it means the offsets are wrong.
        self.assertEqual(self.decode(designed=1_000_000)["design_capacity_mwh"], 1_000_000)
        self.assertNotIn("design_capacity_mwh", self.decode(designed=1_000_001))

    def test_one_readable_capacity_does_not_cost_the_other(self) -> None:
        values = self.decode(designed=80_000, full_charged=BATTERY_UNKNOWN_CAPACITY)
        self.assertEqual(values["design_capacity_mwh"], 80_000)
        self.assertNotIn("full_charge_capacity_mwh", values)

    def test_an_implausible_cycle_count_is_refused(self) -> None:
        self.assertEqual(self.decode(cycle_count=100_000)["cycle_count"], 100_000)
        self.assertNotIn("cycle_count", self.decode(cycle_count=100_001))

    def test_a_short_or_missing_block_reports_nothing(self) -> None:
        self.assertEqual(_decode_battery_information(None), {})
        self.assertEqual(_decode_battery_information(b""), {})
        self.assertEqual(_decode_battery_information(battery_information()[:35]), {})

    def test_a_block_of_zeros_reports_nothing_rather_than_a_dead_battery(self) -> None:
        self.assertEqual(_decode_battery_information(bytes(36)), {})

    def test_the_decoder_needs_no_windows_and_no_ctypes(self) -> None:
        # It is a pure bytes -> value function, which is why the offsets above can be
        # asserted at all. Proven by decoding on whatever platform runs the suite.
        with patch.object(win_battery.platform, "system", return_value="Linux"):
            self.assertEqual(self.decode()["cycle_count"], 231)


class ChemistryTests(unittest.TestCase):
    def test_the_four_character_code_is_passed_on_as_the_firmware_spells_it(self) -> None:
        for raw, expected in (
            (b"LION", "LION"),
            (b"LiP\x00", "LiP"),
            (b"NiMH", "NiMH"),
            (b"PbAc", "PbAc"),
            (b"LI  ", "LI"),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(_decode_chemistry(raw), expected)

    def test_padding_and_junk_leave_nothing_behind(self) -> None:
        for raw in (b"\x00\x00\x00\x00", b"    ", b"", b"\x01\x02\x03\x04"):
            with self.subTest(raw=raw):
                self.assertIsNone(_decode_chemistry(raw))

    def test_a_code_is_never_expanded_into_a_word(self) -> None:
        # "Lithium Polymer" would be a guess about codes this project has never met.
        self.assertEqual(_decode_chemistry(b"LiP\x00"), "LiP")


class QueryBuildingTests(unittest.TestCase):
    def test_the_information_query_names_the_tag_and_the_level(self) -> None:
        query = _build_information_query(0x1234)
        self.assertEqual(len(query), 12)
        tag, level, at_rate = struct.unpack("<IIi", query)
        self.assertEqual(tag, 0x1234)
        self.assertEqual(level, 0)  # BatteryInformation
        self.assertEqual(at_rate, 0)

    def test_a_tag_answer_is_read_as_a_little_endian_dword(self) -> None:
        api = object()
        with patch.object(win_battery, "_device_io_control", return_value=struct.pack("<I", 9)):
            self.assertEqual(_query_battery_tag(api, "handle"), 9)

    def test_an_empty_bay_reports_no_tag(self) -> None:
        # BATTERY_TAG_INVALID is zero: "no battery here", not "a battery numbered zero".
        api = object()
        for answer in (struct.pack("<I", 0), b"", b"\x00\x00", None):
            with self.subTest(answer=answer):
                with patch.object(win_battery, "_device_io_control", return_value=answer):
                    self.assertIsNone(_query_battery_tag(api, "handle"))


class FakeBattery:
    """A described battery bay standing in for the Win32 seams of win_battery."""

    def __init__(
        self,
        *,
        paths: tuple[str, ...] = (DEVICE_PATH,),
        accepts: tuple[int, ...] = (GENERIC_READ,),
        tags: dict[str, int | None] | None = None,
        information: dict[str, bytes | None] | None = None,
    ) -> None:
        self.paths = paths
        self.accepts = accepts
        self.tags = tags if tags is not None else {path: 1 for path in paths}
        self.information = (
            information
            if information is not None
            else {path: battery_information() for path in paths}
        )
        self.opened: list[tuple[str, int]] = []
        self.closed: list[str] = []

    def load(self) -> Any:
        return self

    def list_paths(self, api: Any) -> list[str]:
        return list(self.paths)

    def open(self, api: Any, path: str, access: int) -> Any:
        self.opened.append((path, access))
        if access not in self.accepts:
            return None  # The battery driver rejects a handle with too few rights.
        return f"{path}@{access}"

    def io(
        self, api: Any, handle: Any, code: int, payload: bytes, out_size: int
    ) -> bytes | None:
        path = str(handle).rsplit("@", 1)[0]
        if code == IOCTL_BATTERY_QUERY_TAG:
            tag = self.tags.get(path)
            return None if tag is None else struct.pack("<I", tag)
        if code == IOCTL_BATTERY_QUERY_INFORMATION:
            return self.information.get(path)
        return None

    def close(self, api: Any, handle: Any) -> None:
        self.closed.append(str(handle))


class ReadBatteryHealthTests(unittest.TestCase):
    def read(self, bay: FakeBattery) -> dict[str, object]:
        with patch.object(win_battery.platform, "system", return_value="Windows"):
            with patch.object(win_battery, "_load_api", bay.load):
                with patch.object(win_battery, "_battery_device_paths", bay.list_paths):
                    with patch.object(win_battery, "_open_battery_device", bay.open):
                        with patch.object(win_battery, "_device_io_control", bay.io):
                            with patch.object(win_battery, "_close_handle", bay.close):
                                return read_battery_health()

    def test_a_laptop_battery_reports_its_wear(self) -> None:
        self.assertEqual(
            self.read(FakeBattery()),
            {
                "chemistry": "LION",
                "design_capacity_mwh": 99_000,
                "full_charge_capacity_mwh": 74_250,
                "cycle_count": 231,
            },
        )

    def test_the_least_privileged_handle_is_tried_first(self) -> None:
        # Zero access is what the rest of this project uses for device queries; GENERIC_READ
        # is only reached because the battery driver refuses the zero-access handle.
        bay = FakeBattery()
        self.read(bay)
        self.assertEqual([access for _, access in bay.opened], [0, GENERIC_READ])

    def test_a_driver_that_honours_a_zero_access_handle_is_never_asked_for_more(self) -> None:
        bay = FakeBattery(accepts=(0, GENERIC_READ))
        self.assertTrue(self.read(bay))
        self.assertEqual([access for _, access in bay.opened], [0])

    def test_write_access_is_never_requested(self) -> None:
        bay = FakeBattery(accepts=())
        self.read(bay)
        for _, access in bay.opened:
            with self.subTest(access=hex(access)):
                self.assertEqual(access & 0x40000000, 0, "GENERIC_WRITE must never be asked for")
                self.assertIn(access, (0, GENERIC_READ))

    def test_a_machine_with_no_battery_interface_reports_nothing(self) -> None:
        self.assertEqual(self.read(FakeBattery(paths=())), {})

    def test_an_empty_bay_reports_nothing(self) -> None:
        self.assertEqual(self.read(FakeBattery(tags={DEVICE_PATH: None})), {})

    def test_a_bay_that_answers_no_information_reports_nothing(self) -> None:
        self.assertEqual(self.read(FakeBattery(information={DEVICE_PATH: None})), {})

    def test_the_first_pack_that_answers_is_the_one_reported(self) -> None:
        # Adding two packs' capacities together would state a total no firmware published.
        second = r"\\?\ACPI#PNP0C0A#2#{72631e54}"
        bay = FakeBattery(
            paths=(DEVICE_PATH, second),
            tags={DEVICE_PATH: 1, second: 2},
            information={
                DEVICE_PATH: battery_information(designed=50_000, full_charged=45_000),
                second: battery_information(designed=60_000, full_charged=30_000),
            },
        )
        values = self.read(bay)
        self.assertEqual(values["design_capacity_mwh"], 50_000)
        self.assertEqual(values["full_charge_capacity_mwh"], 45_000)

    def test_a_silent_bay_does_not_cost_the_next_one_its_reading(self) -> None:
        second = r"\\?\ACPI#PNP0C0A#2#{72631e54}"
        bay = FakeBattery(
            paths=(DEVICE_PATH, second),
            tags={DEVICE_PATH: None, second: 2},
            information={second: battery_information(designed=60_000, full_charged=30_000)},
        )
        self.assertEqual(self.read(bay)["design_capacity_mwh"], 60_000)

    def test_every_handle_that_opened_is_closed_again(self) -> None:
        bay = FakeBattery()
        self.read(bay)
        self.assertEqual(bay.closed, [f"{DEVICE_PATH}@{GENERIC_READ}"])

    def test_a_bay_that_explodes_never_reaches_the_caller(self) -> None:
        bay = FakeBattery()

        def hostile(*args: object, **kwargs: object) -> bytes:
            raise OSError("the battery was removed")

        with patch.object(win_battery.platform, "system", return_value="Windows"):
            with patch.object(win_battery, "_load_api", bay.load):
                with patch.object(win_battery, "_battery_device_paths", bay.list_paths):
                    with patch.object(win_battery, "_open_battery_device", bay.open):
                        with patch.object(win_battery, "_device_io_control", hostile):
                            self.assertEqual(read_battery_health(), {})

    def test_an_enumeration_that_explodes_never_reaches_the_caller(self) -> None:
        with patch.object(win_battery.platform, "system", return_value="Windows"):
            with patch.object(win_battery, "_load_api", return_value=object()):
                with patch.object(
                    win_battery, "_battery_device_paths", side_effect=OSError("setupapi")
                ):
                    self.assertEqual(read_battery_health(), {})

    def test_an_api_that_will_not_load_reports_nothing(self) -> None:
        with patch.object(win_battery.platform, "system", return_value="Windows"):
            with patch.object(win_battery, "_load_api", return_value=None):
                self.assertEqual(read_battery_health(), {})

    def test_a_machine_that_is_not_windows_reports_nothing(self) -> None:
        for system in ("Linux", "Darwin", "", "Java"):
            with self.subTest(system=system):
                with patch.object(win_battery.platform, "system", return_value=system):
                    self.assertEqual(read_battery_health(), {})

    def test_the_platform_is_checked_before_any_library_is_loaded(self) -> None:
        with patch.object(win_battery.platform, "system", return_value="Linux"):
            with patch.object(win_battery, "_load_api") as loader:
                self.assertEqual(read_battery_health(), {})
        loader.assert_not_called()

    def test_the_documented_return_shape_is_all_a_caller_gets(self) -> None:
        allowed = {
            "design_capacity_mwh",
            "full_charge_capacity_mwh",
            "cycle_count",
            "chemistry",
        }
        values = self.read(FakeBattery())
        self.assertLessEqual(set(values), allowed)
        # The wear percentage is derived by models.BatteryInfo, never computed here, so
        # there is exactly one definition of it in the project.
        self.assertNotIn("health_percent", values)


if __name__ == "__main__":
    unittest.main()
