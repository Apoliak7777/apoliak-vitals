"""
The version is declared in five places. This module proves they never drift apart again.

They did drift: v2.1 shipped a window titled 2.1.0 whose every exported report claimed to
have been produced by 2.0.0. Python code now reads one constant; the two build files cannot
import Python, so they are checked here instead.
"""

from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

import gui
import main
import src
from src import report

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class VersionConsistencyTests(unittest.TestCase):
    def test_the_package_version_looks_like_a_release(self) -> None:
        self.assertRegex(src.__version__, r"^\d+\.\d+\.\d+$")

    def test_every_python_entry_point_reports_the_package_version(self) -> None:
        for name, value in (
            ("main.APP_VERSION", main.APP_VERSION),
            ("gui.APP_VERSION", gui.APP_VERSION),
            ("src.report.APP_VERSION", report.APP_VERSION),
        ):
            with self.subTest(name):
                self.assertEqual(value, src.__version__)

    def test_pyproject_declares_the_same_version(self) -> None:
        data = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["version"], src.__version__)

    def test_the_windows_version_resource_declares_the_same_version(self) -> None:
        text = (PROJECT_ROOT / "version_info.txt").read_text(encoding="utf-8")
        major, minor, patch = (int(part) for part in src.__version__.split("."))

        for field in ("filevers", "prodvers"):
            match = re.search(rf"{field}=\((\d+), *(\d+), *(\d+), *(\d+)\)", text)
            self.assertIsNotNone(match, f"{field} is missing from version_info.txt")
            assert match is not None
            self.assertEqual(
                tuple(int(match.group(index)) for index in (1, 2, 3)),
                (major, minor, patch),
                f"{field} does not match src.__version__",
            )

        for field in ("FileVersion", "ProductVersion"):
            self.assertIn(
                f"StringStruct('{field}', '{src.__version__}')",
                text,
                f"{field} does not match src.__version__",
            )

    def test_an_exported_report_is_stamped_with_the_running_version(self) -> None:
        """The drift was invisible precisely because nothing asserted this."""
        from tests.helpers import make_analysis  # noqa: PLC0415 - avoids an import cycle

        from src.exporters import snapshot_to_dict
        from src.health_score import calculate_health_details
        from src.recommendations import generate_recommendations

        data = make_analysis()
        payload = snapshot_to_dict(
            data, generate_recommendations(data), calculate_health_details(data)
        )
        self.assertEqual(payload["generated_by"]["version"], src.__version__)


if __name__ == "__main__":
    unittest.main()
