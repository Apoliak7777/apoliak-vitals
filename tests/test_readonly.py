"""The read-only promise, asserted by the interpreter rather than by review.

v2.1 is the first release that may launch anything at all: the window can call
``os.startfile`` on an ``ms-settings:`` page when the user clicks a button. That one
exception is the reason this module exists. Two properties have to hold, and neither is
provable by reading the source:

* **Analysis and rendering launch nothing and write nothing.** Proved with an audit hook
  (:func:`sys.addaudithook`), which sees every process launch, every file opened for
  writing, every socket and every registry mutation the CPython runtime performs -
  including the ones made from inside ``ctypes`` wrappers and inside ``psutil``, where a
  source-level grep sees nothing at all.
* **The one privileged call is fenced off.** :func:`gui.is_settings_uri` is the fence, and
  :meth:`gui.ApoliakAnalyzerApp.open_setting` may not step over it.

The hook runs in a child interpreter on purpose. An audit hook cannot be removed once it is
installed, and one that fires on every event would slow the rest of this suite down for the
whole session; a child process pays that cost once and takes it with it when it exits.

The probe starts with its own negative control: it writes a file and launches a process
while armed, and reports what it saw. A hook that noticed neither would make every other
assertion here vacuous, which is the one way a test like this fails silently.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from src.i18n import get_translator
from src.recommendations import RECOMMENDATION_ACTIONS

PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: Generous, because the child really does analyse this machine: it walks TEMP and the user
#: folders (on a short budget), reads the drives and asks the Security Center.
PROBE_TIMEOUT_SECONDS = 300

try:  # gui.py raises SystemExit when CustomTkinter is not installed.
    import gui as _gui
except BaseException as error:  # noqa: BLE001 - any import problem means "no GUI here"
    _gui = None
    GUI_UNAVAILABLE = f"{type(error).__name__}: {error}"
else:
    GUI_UNAVAILABLE = ""

#: The probe's source. Kept as a string so the hook is installed before anything else runs,
#: and so the child shares no module state with this process.
PROBE_SOURCE = r'''
import json, os, subprocess, sys, tempfile

sys.path.insert(0, sys.argv[1])

WRITE_FLAGS = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC

MUTATION_EVENTS = {
    "os.rename", "os.remove", "os.unlink", "os.rmdir", "os.mkdir", "os.makedirs",
    "os.chmod", "os.chown", "os.link", "os.symlink", "os.truncate", "os.utime",
    "os.replace", "shutil.copyfile", "shutil.copymode", "shutil.copystat",
    "shutil.copytree", "shutil.move", "shutil.rmtree", "tempfile.mkstemp",
    "tempfile.mkdtemp",
}
EXEC_EVENTS = {
    "subprocess.Popen", "os.system", "os.exec", "os.spawn", "os.posix_spawn",
    "os.fork", "os.forkpty", "os.startfile", "winreg.LoadKey",
}
SOCKET_EVENTS = {
    "socket.__new__", "socket.bind", "socket.connect", "socket.getaddrinfo",
    "socket.gethostbyname", "socket.gethostbyaddr", "socket.sendto", "urllib.Request",
}
REGISTRY_WRITE_EVENTS = {
    "winreg.CreateKey", "winreg.DeleteKey", "winreg.DeleteValue", "winreg.SetValue",
    "winreg.SaveKey", "winreg.LoadKey", "winreg.DisableReflectionKey",
    "winreg.EnableReflectionKey", "winreg.ConnectRegistry",
}
# KEY_SET_VALUE | KEY_CREATE_SUB_KEY | KEY_CREATE_LINK | DELETE | WRITE_DAC | WRITE_OWNER
REGISTRY_WRITE_ACCESS = 0x2 | 0x4 | 0x20 | 0x10000 | 0x40000 | 0x80000

armed = [False]
findings = []


def hook(event, args):
    if not armed[0]:
        return
    if event == "open":
        path, mode, flags = (list(args) + [None, None, None])[:3]
        writing = isinstance(mode, str) and any(char in mode for char in "wax+")
        writing = writing or (isinstance(flags, int) and bool(flags & WRITE_FLAGS))
        if writing:
            findings.append("write-open: %r mode=%r flags=%r" % (path, mode, flags))
    elif event in MUTATION_EVENTS:
        findings.append("file-mutation: %s %r" % (event, args))
    elif event in EXEC_EVENTS:
        findings.append("exec: %s %r" % (event, args))
    elif event in SOCKET_EVENTS:
        findings.append("socket: %s %r" % (event, args))
    elif event in REGISTRY_WRITE_EVENTS:
        findings.append("registry-write: %s %r" % (event, args))
    elif event == "winreg.OpenKey":
        access = args[2] if len(args) > 2 else None
        if isinstance(access, int) and access & REGISTRY_WRITE_ACCESS:
            findings.append("registry-write-access: %r" % (args,))


sys.addaudithook(hook)

# --- negative control: the hook has to notice a real write and a real launch --------------
armed[0] = True
with tempfile.TemporaryDirectory() as folder:
    with open(os.path.join(folder, "proof.txt"), "w", encoding="utf-8") as handle:
        handle.write("written")
    try:
        subprocess.Popen(["apoliak-no-such-program-at-all"])
    except (OSError, ValueError):
        pass
armed[0] = False
control = list(findings)
findings.clear()

from src.analyzer import analyze_pc
from src.exporters import FORMATS, render
from src.health_score import calculate_health_details
from src.i18n import LANGUAGES, get_translator
from src.recommendations import generate_recommendations
from src.report import build_report

# Short budgets: this test is about which calls happen, not about how much disk is walked.
SHARED = dict(cpu_interval=0.0, top_process_limit=0,
              temp_scan_seconds=0.2, folder_scan_seconds=0.2)

armed[0] = True
try:
    # 1. Defaults - what both interfaces actually run.
    data = analyze_pc(**SHARED)
    # 2. Every v2.1 collector explicitly on.
    analyze_pc(include_security=True, include_drive_health=True, scan_folders=True,
               scan_temp=True, include_startup=True, include_gpu=True, **SHARED)
    # 3. Every optional collector off - the skip paths must not write either.
    analyze_pc(include_security=False, include_drive_health=False, scan_folders=False,
               scan_temp=False, include_startup=False, include_gpu=False, **SHARED)

    # 4. All four renderers, in both languages, plain and redacted, plus the console report.
    assessment = calculate_health_details(data)
    advice = generate_recommendations(data)
    for language in LANGUAGES:
        words = get_translator(language)
        for fmt in FORMATS:
            render(fmt, data, advice, assessment, translator=words)
            render(fmt, data, advice, assessment, translator=words, redact=True)
        build_report(data, advice, assessment, translator=words, colors=None)
        build_report(data, advice, assessment, translator=words, redact=True)
    # 5. The advice may name a settings page; nothing here may follow one.
    pages = sorted({item.action_uri for item in advice if item.action_uri})
    failure = None
except BaseException as error:
    pages = []
    failure = "%s: %s" % (type(error).__name__, error)
armed[0] = False

print("###AUDIT###" + json.dumps({
    "findings": findings[:40], "control": control[:10], "pages": pages, "failure": failure,
}))
'''


def run_probe() -> dict[str, Any]:
    """Run the audit probe in a child interpreter and return what it saw."""
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, our own source
        [sys.executable, "-c", PROBE_SOURCE, str(PROJECT_ROOT)],
        capture_output=True,
        text=True,
        timeout=PROBE_TIMEOUT_SECONDS,
        cwd=str(PROJECT_ROOT),
    )
    marker = "###AUDIT###"
    for line in completed.stdout.splitlines():
        if line.startswith(marker):
            return json.loads(line[len(marker) :])
    raise AssertionError(
        f"the audit probe produced no verdict (exit {completed.returncode})\n"
        f"stdout: {completed.stdout[-2000:]}\nstderr: {completed.stderr[-2000:]}"
    )


class AuditHookTests(unittest.TestCase):
    """Analysis and rendering must be invisible to the operating system."""

    @classmethod
    def setUpClass(cls) -> None:
        try:
            cls.verdict = run_probe()
        except (OSError, subprocess.SubprocessError) as error:
            raise unittest.SkipTest(f"the audit probe could not be started: {error}") from error

    def test_the_probe_itself_completed(self) -> None:
        self.assertIsNone(self.verdict["failure"], self.verdict["failure"])

    def test_the_hook_really_notices_a_write_and_a_launch(self) -> None:
        # Without this the sweep below could pass simply by never seeing anything.
        control = list(self.verdict["control"])
        self.assertTrue(
            any(item.startswith("write-open") for item in control),
            f"the hook missed a file that was really written: {control}",
        )
        self.assertTrue(
            any(item.startswith("exec") for item in control),
            f"the hook missed a process launch: {control}",
        )

    def test_analysis_and_rendering_touch_nothing(self) -> None:
        """No write-open, no subprocess, no socket, no registry write - not one."""
        findings = list(self.verdict["findings"])
        self.assertEqual(findings, [], "\n".join(str(item) for item in findings))

    def test_the_advice_named_pages_without_following_any_of_them(self) -> None:
        # The pointer exists; following it is the window's job, and only on a click.
        for uri in self.verdict["pages"]:
            with self.subTest(uri=uri):
                self.assertIn(uri, set(RECOMMENDATION_ACTIONS.values()))


@unittest.skipIf(_gui is None, f"the GUI cannot be imported here ({GUI_UNAVAILABLE})")
class SettingsUriFenceTests(unittest.TestCase):
    """``is_settings_uri`` is the only thing standing between a click and ``os.startfile``."""

    ACCEPTED = (
        "ms-settings:windowsdefender",
        "ms-settings:windowsupdate",
        "ms-settings:storagesense",
        "ms-settings:batterysaver",
        "ms-settings:startupapps",
        "ms-settings:",  # The Settings home page; harmless, and still only a page.
        "  ms-settings:windowsdefender  ",  # Surrounding space is trimmed, not a new URI.
    )

    REFUSED = (
        "http://example.com",
        "https://example.com/x",
        "file:///C:/Windows/System32/cmd.exe",
        "cmd",
        "cmd.exe",
        r"C:\Windows\System32\cmd.exe",
        r"\\server\share\payload.exe",
        "",
        "   ",
        "ms-settings:windowsdefender extra",
        "ms-settings:windowsdefender /c calc",
        'ms-settings:windowsdefender"&calc',
        "ms-settings:windowsdefender\ncalc",
        "ms-settings:x y",
        r"ms-settings:..\..\evil",
        "MS-SETTINGS:windowsdefender",  # Repaired capitalisation would be a repaired URI.
        "MS-Settings:windowsdefender",
        "xms-settings:windowsdefender",
        "ms-settings",
        "ms-settingsx:foo",
        "javascript:alert(1)",
        "shell:startup",
        None,
        123,
        b"ms-settings:windowsdefender",
        ["ms-settings:windowsdefender"],
    )

    def test_only_a_settings_page_is_accepted(self) -> None:
        for value in self.ACCEPTED:
            with self.subTest(accepted=value):
                self.assertTrue(_gui.is_settings_uri(value))
        for value in self.REFUSED:
            with self.subTest(refused=value):
                self.assertFalse(_gui.is_settings_uri(value))

    def test_every_page_the_advice_points_at_passes_its_own_fence(self) -> None:
        # A key whose page the fence would refuse is a button that can only ever fail.
        self.assertTrue(RECOMMENDATION_ACTIONS)
        for key, uri in RECOMMENDATION_ACTIONS.items():
            with self.subTest(key=key):
                self.assertTrue(uri.startswith("ms-settings:"))
                self.assertTrue(_gui.is_settings_uri(uri), f"{key} -> {uri!r}")

    def test_the_opener_is_reached_from_exactly_one_place(self) -> None:
        """
        Nothing in the analysis or render path can look ``os.startfile`` up.

        Parsed rather than grepped, so a mention inside a docstring - the module has one -
        does not count, and a second real lookup could not hide inside a comment either.
        """
        import ast
        import inspect

        tree = ast.parse(inspect.getsource(_gui))
        holders = sorted(
            {
                node.name
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and any(
                    isinstance(child, ast.Constant)
                    and isinstance(child.value, str)
                    and child.value == "startfile"
                    for child in ast.walk(node)
                )
            }
        )
        self.assertEqual(holders, ["open_setting"], holders)


@unittest.skipIf(_gui is None, f"the GUI cannot be imported here ({GUI_UNAVAILABLE})")
class OpenSettingTests(unittest.TestCase):
    """The single privileged call, exercised without a display and without launching."""

    def window(self) -> Any:
        window = _gui.ApoliakAnalyzerApp.__new__(_gui.ApoliakAnalyzerApp)
        window.tk = None  # Tk forwards unknown attributes; None makes lookups fail cleanly.
        window.translator = get_translator("en")
        window.language = "en"
        window.status_lines = []
        window._set_status_line = window.status_lines.append  # type: ignore[assignment]
        return window

    def test_a_refused_uri_never_reaches_the_opener(self) -> None:
        for uri in SettingsUriFenceTests.REFUSED:
            window = self.window()
            with self.subTest(uri=uri), patch.object(os, "startfile", create=True) as opener:
                window.open_setting(uri)
                opener.assert_not_called()
            self.assertTrue(window.status_lines, "a refusal must be reported, not swallowed")

    def test_an_accepted_uri_is_opened_exactly_once_and_unchanged(self) -> None:
        window = self.window()
        with patch.object(os, "startfile", create=True) as opener:
            window.open_setting("  ms-settings:windowsdefender  ")
        opener.assert_called_once_with("ms-settings:windowsdefender")
        self.assertTrue(window.status_lines)

    def test_the_opener_is_never_asked_to_elevate(self) -> None:
        # os.startfile takes an operation ("runas" is the elevating one); ours stays "open".
        calls: list[tuple[tuple[object, ...], dict[str, object]]] = []
        window = self.window()
        with patch.object(
            os, "startfile", create=True, side_effect=lambda *a, **kw: calls.append((a, kw))
        ):
            window.open_setting("ms-settings:windowsupdate")
        self.assertEqual(calls, [(("ms-settings:windowsupdate",), {})])

    def test_a_failing_opener_is_reported_rather_than_raised(self) -> None:
        window = self.window()
        with patch.object(os, "startfile", create=True, side_effect=OSError("no association")):
            window.open_setting("ms-settings:storagesense")  # Must not raise.
        self.assertTrue(window.status_lines)

    def test_a_machine_with_no_opener_at_all_says_so(self) -> None:
        # os.startfile does not exist off Windows; the button must report, never explode.
        window = self.window()
        with patch.object(os, "startfile", None, create=True):
            window.open_setting("ms-settings:storagesense")
        self.assertTrue(window.status_lines)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
