"""Tests for the desktop window's output plumbing in gui.py.

Only the plumbing is exercised, never a widget: the window needs a display and a Tk main
loop, neither of which belongs in a unit test. Instances are therefore built with
``__new__`` and given exactly the attributes the method under test reads, which is enough to
prove the one thing that matters here - that the "Redact personal data" choice reaches every
writer. Before v2.0 it could not: the checkbox did not exist, so every GUI export and every
clipboard copy carried the Windows account name.

The whole module skips when CustomTkinter is missing or cannot be imported.
"""

from __future__ import annotations

import inspect
import os
import tempfile
import unittest
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from src.health_score import calculate_health_details
from src.i18n import get_translator
from src.recommendations import generate_recommendations
from tests.helpers import make_analysis

ACCOUNT = "testaccount"
TEMP_PATH = rf"C:\Users\{ACCOUNT}\AppData\Local\Temp"

try:  # gui.py raises SystemExit when CustomTkinter is not installed.
    import gui as _gui
except BaseException as error:  # noqa: BLE001 - any import problem means "no GUI here"
    _gui = None
    GUI_UNAVAILABLE = f"{type(error).__name__}: {error}"
else:
    GUI_UNAVAILABLE = ""


@contextmanager
def temporary_folder() -> Iterator[Path]:
    """A folder that disappears again; no test may leave a file behind."""
    with tempfile.TemporaryDirectory() as name:
        yield Path(name)


class FakeVariable:
    """Stand-in for ``ctk.BooleanVar`` - the checkbox state without a Tk interpreter."""

    def __init__(self, value: bool = False, *, broken: bool = False) -> None:
        self._value = bool(value)
        self.broken = broken

    def get(self) -> bool:
        if self.broken:  # A destroyed widget raises here; the stored flag has to cover it.
            raise RuntimeError("this variable no longer has an interpreter")
        return self._value

    def set(self, value: object) -> None:
        if self.broken:
            raise RuntimeError("this variable no longer has an interpreter")
        self._value = bool(value)


@unittest.skipIf(_gui is None, f"the GUI cannot be imported here ({GUI_UNAVAILABLE})")
class GuiTestCase(unittest.TestCase):
    """Builds a window object without ever starting Tk."""

    def app(self, **attributes: Any) -> Any:
        data = make_analysis(temp_path=TEMP_PATH)
        window = _gui.ApoliakAnalyzerApp.__new__(_gui.ApoliakAnalyzerApp)
        # Tk forwards every unknown attribute to its interpreter object; without one, a
        # plain getattr() would recurse forever. None makes the lookup fail cleanly, which
        # is exactly the "the widget is not there" case the fallbacks are written for.
        window.tk = None
        window.translator = get_translator("en")
        window.language = "en"
        window.analysis = data
        window.assessment = calculate_health_details(data)
        window.recommendations = generate_recommendations(data)
        window.export_format = "text"
        window.redact = False
        for name, value in attributes.items():
            setattr(window, name, value)
        return window


class RedactionStateTests(GuiTestCase):
    """The checkbox is the authority; the stored flag covers a torn-down widget."""

    def test_the_checkbox_is_read_when_it_exists(self) -> None:
        window = self.app(redact=False, redact_var=FakeVariable(True))
        self.assertTrue(window._read_redact_choice())

    def test_the_stored_flag_is_used_when_there_is_no_checkbox(self) -> None:
        window = self.app(redact=True)
        self.assertTrue(window._read_redact_choice())

    def test_a_dead_checkbox_falls_back_to_the_stored_flag(self) -> None:
        window = self.app(redact=True, redact_var=FakeVariable(False, broken=True))
        self.assertTrue(window._read_redact_choice())

    def test_toggling_stores_the_new_choice(self) -> None:
        window = self.app(redact=False, redact_var=FakeVariable(True))
        window._on_redact_toggled()
        self.assertTrue(window.redact)

    def test_setting_it_from_code_keeps_the_checkbox_in_step(self) -> None:
        variable = FakeVariable(False)
        window = self.app(redact_var=variable)
        window.set_redact(True)
        self.assertTrue(window.redact)
        self.assertTrue(variable.get())
        window.set_redact(False)
        self.assertFalse(window.redact)
        self.assertFalse(variable.get())

    def test_redaction_is_off_until_the_user_asks_for_it(self) -> None:
        # Asserted against the source because the default lives in __init__, and __init__
        # needs a display. The on-screen report is for the owner of the PC, who gains
        # nothing from masking their own name.
        source = inspect.getsource(_gui.ApoliakAnalyzerApp.__init__)
        self.assertIn("self.redact = False", source)


class OutputOptionTests(GuiTestCase):
    """Every writer is called through one options helper, so none can be forgotten."""

    def test_redaction_is_passed_on_when_it_is_switched_on(self) -> None:
        options = self.app()._output_options(True)
        self.assertIs(options["redact"], True)

    def test_nothing_is_passed_when_it_is_switched_off(self) -> None:
        # Omitting the keyword keeps a writer that predates it working with redaction off,
        # and makes it fail loudly - instead of leaking - when the user asked for masking.
        options = self.app()._output_options(False)
        self.assertNotIn("redact", options)

    def test_the_translator_always_travels_with_it(self) -> None:
        window = self.app()
        for redact in (False, True):
            with self.subTest(redact=redact):
                self.assertIs(window._output_options(redact)["translator"], window.translator)


class TextReportTests(GuiTestCase):
    """The preview and the clipboard copy share one builder, so both honour the choice."""

    def test_the_choice_reaches_the_report_builder(self) -> None:
        window = self.app()
        with patch.object(_gui, "build_report", return_value="report") as build:
            window._text_report(redact=True)
        self.assertIs(build.call_args.kwargs["redact"], True)

    def test_an_unredacted_report_asks_for_no_masking(self) -> None:
        window = self.app()
        with patch.object(_gui, "build_report", return_value="report") as build:
            window._text_report(redact=False)
        self.assertNotIn("redact", build.call_args.kwargs)

    def test_the_account_name_really_disappears(self) -> None:
        window = self.app()
        with patch.dict(os.environ, {"USERNAME": ACCOUNT}):
            masked = window._text_report(redact=True)
            plain = window._text_report(redact=False)
        self.assertNotIn(ACCOUNT, masked)
        self.assertIn("<user>", masked)
        self.assertIn(ACCOUNT, plain)

    def test_a_writer_that_cannot_redact_fails_instead_of_leaking(self) -> None:
        window = self.app()
        with patch.object(_gui, "build_report", side_effect=TypeError("no redact keyword")):
            with self.assertRaises(RuntimeError):
                window._text_report(redact=True)

    def test_the_same_old_writer_still_works_with_redaction_off(self) -> None:
        window = self.app()
        calls: list[int] = []

        def old_signature(*args: object, **kwargs: object) -> str:
            calls.append(len(kwargs))
            if kwargs:
                raise TypeError("unexpected keyword argument")
            return "v1.0 report"

        with patch.object(_gui, "build_report", side_effect=old_signature):
            self.assertEqual(window._text_report(redact=False), "v1.0 report")
        self.assertEqual(len(calls), 2)  # One rejected modern call, one v1.0 fallback.


class ClipboardTests(GuiTestCase):
    """Copying to the clipboard is an export too, and carries the same flag."""

    def app(self, **attributes: Any) -> Any:
        window = super().app(**attributes)
        window.copied: list[str] = []
        window.clipboard_clear = lambda: None
        window.clipboard_append = window.copied.append
        window.update_idletasks = lambda: None
        window.after = lambda delay, callback=None: None
        window.copy_button = SimpleNamespace(configure=lambda **kwargs: None)
        return window

    def test_the_copy_uses_the_checkbox_state(self) -> None:
        window = self.app(redact_var=FakeVariable(True))
        with patch.object(_gui, "build_report", return_value="report") as build:
            window.copy_report_to_clipboard()
        self.assertIs(build.call_args.kwargs["redact"], True)
        self.assertEqual(window.copied, ["report"])

    def test_the_copied_text_carries_no_account_name(self) -> None:
        window = self.app(redact_var=FakeVariable(True))
        with patch.dict(os.environ, {"USERNAME": ACCOUNT}):
            window.copy_report_to_clipboard()
        self.assertEqual(len(window.copied), 1)
        self.assertNotIn(ACCOUNT, window.copied[0])

    def test_an_unticked_box_copies_the_report_unchanged(self) -> None:
        window = self.app(redact_var=FakeVariable(False))
        with patch.dict(os.environ, {"USERNAME": ACCOUNT}):
            window.copy_report_to_clipboard()
        self.assertIn(ACCOUNT, window.copied[0])


class FakeCanvas:
    """A Tk canvas that records what was drawn on it instead of drawing anything.

    Only the four calls the chart makes are implemented, which is the point: an item the
    chart starts drawing with some other call shows up here as an AttributeError rather than
    as a silently missing line.
    """

    def __init__(self, width: int = 640, height: int = 176, *, exists: bool = True) -> None:
        self.width = width
        self.height = height
        self.exists = exists
        self.items: list[tuple[str, tuple[object, ...], dict[str, object]]] = []
        self.clears = 0
        self.background: str | None = None

    # -- the surface the chart draws on ------------------------------------------------

    def winfo_exists(self) -> bool:
        return self.exists

    def winfo_width(self) -> int:
        return self.width

    def winfo_height(self) -> int:
        return self.height

    def configure(self, **kwargs: object) -> None:
        self.background = str(kwargs.get("background", self.background))

    def delete(self, what: str) -> None:
        self.clears += 1
        self.items.clear()

    def create_text(self, *args: object, **kwargs: object) -> int:
        self.items.append(("text", args, kwargs))
        return len(self.items)

    def create_line(self, *args: object, **kwargs: object) -> int:
        self.items.append(("line", args, kwargs))
        return len(self.items)

    def create_oval(self, *args: object, **kwargs: object) -> int:
        self.items.append(("oval", args, kwargs))
        return len(self.items)

    def create_rectangle(self, *args: object, **kwargs: object) -> int:
        self.items.append(("rectangle", args, kwargs))
        return len(self.items)

    # -- what the tests ask it afterwards ----------------------------------------------

    def kinds(self) -> list[str]:
        return [kind for kind, _, _ in self.items]

    def of(self, kind: str) -> list[tuple[tuple[object, ...], dict[str, object]]]:
        return [(args, kwargs) for name, args, kwargs in self.items if name == kind]

    def texts(self) -> list[str]:
        return [str(kwargs.get("text", "")) for name, _, kwargs in self.items if name == "text"]


class HistoryChartTests(GuiTestCase):
    """The score-over-time chart, drawn onto a recording canvas instead of a window.

    A chart is the one part of the window that computes coordinates, so it is the one part
    that can be wrong rather than merely ugly: a point off the plot, a label drawn outside
    the canvas, or a division by "one run minus one". Zero, one and many runs are therefore
    all exercised, and every drawn item is checked to sit inside the canvas.
    """

    def chart(self, scores: object, **attributes: Any) -> Any:
        canvas = attributes.pop("canvas", None) or FakeCanvas()
        window = self.app(history_canvas=canvas, _chart_scores=tuple(scores), **attributes)
        window.theme = "dark"
        window._draw_history_chart()
        return canvas

    def test_no_history_yet_says_so_instead_of_drawing_an_empty_chart(self) -> None:
        canvas = self.chart(())
        self.assertEqual(canvas.kinds(), ["text"])
        self.assertIn("trend", canvas.texts()[0])

    def test_a_single_run_is_drawn_as_one_point_in_the_middle(self) -> None:
        # The x position of run 1 of 1 is where a "index / (count - 1)" would divide by zero.
        canvas = self.chart((72,))
        ovals = canvas.of("oval")
        self.assertEqual(len(ovals), 1)
        (left, top, right, bottom), _ = ovals[0]
        self.assertAlmostEqual((left + right) / 2, 34 + (640 - 34 - 16) / 2, places=6)
        # One point is not a trend: there is no line to draw between a single run and itself.
        self.assertEqual([args for args, _ in canvas.of("line") if len(args) > 4], [])

    def test_many_runs_are_drawn_left_to_right_with_a_line_through_them(self) -> None:
        scores = [100, 88, 74, 51, 33]
        canvas = self.chart(scores)
        ovals = canvas.of("oval")
        self.assertEqual(len(ovals), len(scores))
        centres = [((args[0] + args[2]) / 2, (args[1] + args[3]) / 2) for args, _ in ovals]
        self.assertEqual([x for x, _ in centres], sorted(x for x, _ in centres))
        # A falling score is drawn lower, so the line has to descend as the scores do.
        self.assertEqual([y for _, y in centres], sorted(y for _, y in centres))
        polyline = [args for args, _ in canvas.of("line") if len(args) == 2 * len(scores)]
        self.assertEqual(len(polyline), 1)

    def test_every_item_is_drawn_inside_the_canvas(self) -> None:
        canvas = self.chart([100, 0, 50, 3, 97, 12])
        for kind, args, kwargs in canvas.items:
            numbers = [value for value in args if isinstance(value, (int, float))]
            with self.subTest(item=kind):
                for index, value in enumerate(numbers):
                    axis = canvas.width if index % 2 == 0 else canvas.height
                    self.assertGreaterEqual(value, -1)
                    self.assertLessEqual(value, axis + 1)

    def test_the_newest_the_best_and_the_worst_run_are_labelled(self) -> None:
        canvas = self.chart([60, 95, 40, 77])
        labels = canvas.texts()
        for score in ("77", "95", "40"):
            with self.subTest(score=score):
                self.assertIn(score, labels)

    def test_one_point_that_is_two_of_the_three_is_labelled_once(self) -> None:
        # A single run is the newest, the best and the worst at the same time; three labels
        # drawn on top of each other would read as one smudged number.
        canvas = self.chart((64,))
        self.assertEqual([text for text in canvas.texts() if text == "64"], ["64"])

    def test_a_score_outside_the_scale_is_clamped_rather_than_drawn_off_the_chart(self) -> None:
        canvas = self.chart([-20, 250])
        ovals = canvas.of("oval")
        self.assertEqual(len(ovals), 2)
        for args, _ in ovals:
            with self.subTest(point=args):
                self.assertGreaterEqual(args[1], 0)
                self.assertLessEqual(args[3], canvas.height)

    def test_a_long_history_drops_labels_instead_of_overlapping_them(self) -> None:
        canvas = self.chart(list(range(1, 61)))
        run_labels = [text for text in canvas.texts() if text.isdigit()]
        self.assertLess(len(run_labels), 60)
        self.assertTrue(run_labels)

    def test_redrawing_clears_the_canvas_first(self) -> None:
        # Every item is created fresh, so a resize, a theme switch or a language switch
        # cannot pile items up on the canvas.
        canvas = FakeCanvas()
        window = self.app(history_canvas=canvas, _chart_scores=())
        window.theme = "dark"
        for _ in range(3):
            window._draw_history_chart()
        self.assertEqual(canvas.clears, 3)
        self.assertEqual(len(canvas.items), 1)

    def test_a_canvas_too_small_to_read_is_left_blank(self) -> None:
        canvas = self.chart([50, 60], canvas=FakeCanvas(width=40, height=20))
        self.assertEqual(canvas.items, [])

    def test_a_canvas_tk_has_not_laid_out_yet_falls_back_to_a_readable_size(self) -> None:
        # Before the first layout pass Tk reports 1x1; the <Configure> binding redraws later.
        canvas = self.chart([50, 60], canvas=FakeCanvas(width=1, height=1))
        self.assertTrue(canvas.items)

    def test_a_canvas_that_is_being_torn_down_is_not_drawn_on(self) -> None:
        canvas = self.chart([50, 60], canvas=FakeCanvas(exists=False))
        self.assertEqual(canvas.items, [])

    def test_a_window_with_no_chart_at_all_simply_does_nothing(self) -> None:
        window = self.app(_chart_scores=(50,))
        window.theme = "dark"
        window._draw_history_chart()  # No history_canvas attribute: must not raise.

    def test_setting_the_scores_redraws_immediately(self) -> None:
        canvas = FakeCanvas()
        window = self.app(history_canvas=canvas, _chart_scores=())
        window.theme = "dark"
        window._set_chart_scores([80, 90])
        self.assertEqual(window._chart_scores, (80, 90))
        self.assertEqual(len(canvas.of("oval")), 2)

    def test_a_resize_to_the_same_size_is_not_redrawn(self) -> None:
        # Tk sends a <Configure> for every pixel of a window drag; coalescing them into one
        # delayed redraw is what keeps dragging the window smooth.
        scheduled: list[tuple[int, object]] = []
        window = self.app(
            history_canvas=FakeCanvas(),
            _chart_scores=(50,),
            _chart_size=(0, 0),
            _chart_job=None,
        )
        window.theme = "dark"
        window.after = lambda delay, callback=None: scheduled.append((delay, callback)) or "job"
        window.after_cancel = lambda job: None

        window._on_chart_resize(SimpleNamespace(width=800, height=200))
        self.assertEqual(len(scheduled), 1)
        window._on_chart_resize(SimpleNamespace(width=800, height=200))
        self.assertEqual(len(scheduled), 1, "the same size must not schedule a second redraw")
        window._on_chart_resize(SimpleNamespace(width=900, height=200))
        self.assertEqual(len(scheduled), 2)

    def test_a_resize_with_no_interpreter_to_schedule_on_draws_at_once(self) -> None:
        canvas = FakeCanvas()
        window = self.app(
            history_canvas=canvas, _chart_scores=(50,), _chart_size=(0, 0), _chart_job=None
        )
        window.theme = "dark"

        def no_scheduler(delay: int, callback: object = None) -> str:
            raise RuntimeError("this window has no interpreter any more")

        window.after = no_scheduler
        window.after_cancel = lambda job: None
        window._on_chart_resize(SimpleNamespace(width=700, height=180))
        self.assertTrue(canvas.of("oval"))


class ExportPlumbingTests(GuiTestCase):
    """The file dialog path: the flag has to survive all the way into the exporter."""

    def export(self, window: Any, destination: Path) -> Any:
        with patch.object(_gui.filedialog, "asksaveasfilename", return_value=str(destination)):
            with patch.object(_gui.messagebox, "showinfo") as told:
                with patch.object(_gui._exporters, "export") as writer:
                    writer.return_value = destination
                    window.export_current_report()
        told.assert_called_once()
        return writer

    def test_the_checkbox_reaches_the_exporter(self) -> None:
        window = self.app(redact_var=FakeVariable(True))
        with temporary_folder() as folder:
            writer = self.export(window, folder / "report.txt")
        self.assertIs(writer.call_args.kwargs["redact"], True)
        self.assertIs(writer.call_args.kwargs["translator"], window.translator)

    def test_an_unticked_box_exports_without_masking(self) -> None:
        window = self.app(redact_var=FakeVariable(False))
        with temporary_folder() as folder:
            writer = self.export(window, folder / "report.txt")
        self.assertNotIn("redact", writer.call_args.kwargs)

    def test_every_format_carries_the_flag(self) -> None:
        for fmt, _extension, _label, _dialog in _gui.FORMAT_SPECS:
            with self.subTest(fmt=fmt):
                window = self.app(export_format=fmt, redact_var=FakeVariable(True))
                with temporary_folder() as folder:
                    writer = self.export(window, folder / f"report.{fmt}")
                self.assertEqual(writer.call_args.args[0], fmt)
                self.assertIs(writer.call_args.kwargs["redact"], True)

    def test_a_cancelled_dialog_writes_nothing(self) -> None:
        window = self.app(redact_var=FakeVariable(True))
        with patch.object(_gui.filedialog, "asksaveasfilename", return_value=""):
            with patch.object(_gui._exporters, "export") as writer:
                window.export_current_report()
        writer.assert_not_called()

    def test_a_writer_that_cannot_redact_reports_it_and_saves_nothing(self) -> None:
        window = self.app(redact_var=FakeVariable(True))
        with temporary_folder() as folder:
            destination = folder / "report.txt"
            with patch.object(_gui.filedialog, "asksaveasfilename", return_value=str(destination)):
                with patch.object(_gui.messagebox, "showerror") as told:
                    with patch.object(
                        _gui._exporters, "export", side_effect=TypeError("no redact keyword")
                    ):
                        window.export_current_report()
            self.assertFalse(destination.exists())
        told.assert_called_once()
        self.assertIn("mask personal data", " ".join(str(item) for item in told.call_args.args))


if __name__ == "__main__":
    unittest.main()
