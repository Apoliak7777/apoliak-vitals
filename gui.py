"""Modern desktop interface for Apoliak Vitals.

The window is a pure viewer over one immutable ``AnalysisData`` snapshot: it reads, formats,
and exports. It never offers an action that would change the machine, which is why the
process view has no terminate button and the local history is strictly opt-in.

Threading contract: the analysis runs on a daemon worker thread, every message crosses back
through a ``queue.Queue``, and only ``after()`` callbacks on Tk's main thread touch a widget.
``analyze_pc`` reports progress as ``(step_key, fraction)``, so the worker queues the bare key
and the translation happens on the Tk thread - the progress line follows the chosen language.

v2.1 adds the one thing this window may launch: an "Open setting" button beside a piece of
advice that names a Windows settings page. It runs ``os.startfile`` on an ``ms-settings:``
URI and nothing else, only from a deliberate click, and opening a page never changes the
setting behind it. Rendering never launches anything - see :func:`is_settings_uri` and
:meth:`ApoliakAnalyzerApp.open_setting`.
"""

from __future__ import annotations

import inspect
import os
import re
import threading
from datetime import datetime
from pathlib import Path
from queue import Empty, Queue
from tkinter import filedialog, messagebox
from typing import Any, Callable, Sequence

try:
    import customtkinter as ctk
except ImportError as error:
    raise SystemExit(
        "CustomTkinter is required for the GUI. "
        "Run: python -m pip install -r requirements.txt"
    ) from error

# The module itself is imported alongside the function because the English step labels are
# read lazily from it: a collector that predates PROGRESS_LABELS must still drive this window.
from src import analyzer as _analyzer
from src.analyzer import analyze_pc
from src.health_score import calculate_health_details
from src.models import (
    CATEGORY_CPU,
    CATEGORY_MAINTENANCE,
    CATEGORY_MEMORY,
    CATEGORY_POWER,
    CATEGORY_SECURITY,
    CATEGORY_STORAGE,
    STATE_BAD,
    STATE_GOOD,
    STATE_UNKNOWN,
    STATE_WEAK,
    AnalysisData,
    HealthAssessment,
)
from src.recommendations import generate_recommendations
from src.report import build_report, export_report
from src.utils import (
    format_bytes,
    format_count,
    format_duration,
    format_frequency,
    format_percent,
    format_uptime,
)

# The translation, exporter, and history layers are optional at runtime. A trimmed
# installation must still open the window in English instead of dying on an import.
try:
    from src import i18n as _i18n
except ImportError:  # pragma: no cover - depends on how the app was packaged
    _i18n = None

try:
    from src import exporters as _exporters
except ImportError:  # pragma: no cover - depends on how the app was packaged
    _exporters = None

try:
    from src import history as _history
except ImportError:  # pragma: no cover - depends on how the app was packaged
    _history = None

try:
    from src import __version__ as APP_VERSION
except ImportError:  # pragma: no cover - depends on how the app was packaged
    APP_VERSION = "2.1.0"

#: Unknown values are rendered exactly the way ``src.utils`` renders them, in every language.
NA = "N/A"

DARK_PALETTE: dict[str, str] = {
    "bg": "#070B14",
    "sidebar": "#0B1120",
    "card": "#111827",
    "card_alt": "#0F172A",
    "row": "#0C1424",
    "border": "#263348",
    "text": "#F8FAFC",
    "muted": "#94A3B8",
    "faint": "#64748B",
    "accent": "#22D3EE",
    "accent_hover": "#06B6D4",
    "accent_text": "#04212A",
    "success": "#34D399",
    "warning": "#FBBF24",
    "danger": "#FB7185",
    "track": "#1E293B",
    "icon_bg": "#143246",
    "notice_bg": "#0D1F25",
    "notice_border": "#164E63",
    "notice_text": "#B6CDD5",
    "pill_ok": "#12251F",
    "pill_warn": "#33290D",
    "pill_bad": "#35151D",
    "scroll": "#243247",
    "scroll_hover": "#334155",
    "hover": "#182437",
}

LIGHT_PALETTE: dict[str, str] = {
    "bg": "#EEF2F7",
    "sidebar": "#FFFFFF",
    "card": "#FFFFFF",
    "card_alt": "#F6F8FB",
    "row": "#F1F5F9",
    "border": "#D5DEEA",
    "text": "#0F172A",
    "muted": "#55647C",
    "faint": "#7A8798",
    "accent": "#0E7490",
    "accent_hover": "#0891B2",
    "accent_text": "#FFFFFF",
    "success": "#047857",
    "warning": "#B45309",
    "danger": "#BE123C",
    "track": "#DBE3EE",
    "icon_bg": "#DDF1F6",
    "notice_bg": "#ECFEFF",
    "notice_border": "#A5DFE9",
    "notice_text": "#33566B",
    "pill_ok": "#DCFCE7",
    "pill_warn": "#FEF3C7",
    "pill_bad": "#FFE4E6",
    "scroll": "#C3CEDC",
    "scroll_hover": "#9FAEC2",
    "hover": "#E6ECF4",
}

PALETTES: dict[str, dict[str, str]] = {"dark": DARK_PALETTE, "light": LIGHT_PALETTE}

VIEWS: tuple[str, ...] = (
    "overview",
    "processes",
    "storage",
    "security",
    "system",
    "history",
)

VIEW_DEFAULT_LABELS: dict[str, str] = {
    "overview": "Overview",
    "processes": "Processes",
    "storage": "Storage",
    "security": "Security",
    "system": "System",
    "history": "History",
}

CATEGORY_ORDER: tuple[str, ...] = (
    CATEGORY_CPU,
    CATEGORY_MEMORY,
    CATEGORY_STORAGE,
    CATEGORY_MAINTENANCE,
    CATEGORY_POWER,
    CATEGORY_SECURITY,
)

CATEGORY_DEFAULT_LABELS: dict[str, str] = {
    CATEGORY_CPU: "CPU",
    CATEGORY_MEMORY: "Memory",
    CATEGORY_STORAGE: "Storage",
    CATEGORY_MAINTENANCE: "Maintenance",
    CATEGORY_POWER: "Power",
    CATEGORY_SECURITY: "Security",
}

#: How each protection verdict is worded - the same keys the text report words it with, so
#: the window and the exported report can never disagree. "unknown" is deliberately neutral:
#: this app not being able to read a setting says nothing about the PC.
SECURITY_STATE_LABELS: dict[str, tuple[str, str]] = {
    STATE_GOOD: ("field.state_good", "On"),
    STATE_WEAK: ("field.state_weak", "Needs attention"),
    STATE_BAD: ("field.state_bad", "Off"),
    STATE_UNKNOWN: ("field.state_unknown", "Unknown"),
}

#: Notes ``SecurityInfo.details`` can carry, and the row each one belongs beside. A note the
#: window does not know about is skipped rather than shown as a raw slug.
SECURITY_DETAIL_FIREWALL = "firewall_profiles_off"
SECURITY_DETAIL_REBOOT = "reboot_sources"
SECURITY_DETAIL_CENTER = "security_center"

#: The only scheme this window may hand to the operating system. An ``ms-settings:`` URI
#: opens a Windows settings page; it cannot carry a command and it changes no setting.
ACTION_URI_PREFIX = "ms-settings:"

#: Deliberately narrow, and deliberately case-sensitive on the scheme. Every page in our own
#: advice table is lower-case plain letters; anything with a space, a quote, a backslash or a
#: second scheme in it is refused rather than repaired.
_ACTION_URI_PATTERN = re.compile(r"^ms-settings:[A-Za-z0-9._~%!$&*+,;=:@/?-]*$")

#: Chart geometry: (left, right, top, bottom) margins around the plotting area, in pixels.
CHART_MARGINS: tuple[int, int, int, int] = (34, 16, 16, 24)
CHART_HEIGHT = 176
#: Width assumed for the very first draw, before Tk has laid the canvas out. The
#: ``<Configure>`` binding redraws at the real width as soon as there is one.
CHART_FALLBACK_WIDTH = 640
#: Pixels of horizontal room one x-axis label needs before its neighbour has to be dropped.
CHART_LABEL_SPACING = 46
CHART_FONT = "Segoe UI"

#: Export formats offered in the sidebar, with the file dialog metadata for each one.
FORMAT_SPECS: tuple[tuple[str, str, str, str], ...] = (
    ("text", ".txt", "Text (.txt)", "Text report"),
    ("json", ".json", "JSON (.json)", "JSON data"),
    ("html", ".html", "HTML (.html)", "HTML report"),
    ("markdown", ".md", "Markdown (.md)", "Markdown report"),
)


def _display(value: object | None) -> str:
    """Render any plain value, keeping the project-wide 'unknown stays N/A' rule."""
    if value is None:
        return NA
    text = str(value).strip()
    return text or NA


def _datetime_text(value: object | None) -> str:
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    return _display(value)


def _one_line(value: object | None, limit: int) -> str:
    """
    Render a value as a single short line, for the one-line status caption.

    Only ever used on a value the window is refusing to act on. A newline or a tab in such a
    value would otherwise decide how tall the caption is and push the header about, so every
    run of whitespace collapses to one space before the text is cut to ``limit``.
    """
    text = " ".join(_display(value).split())
    return text[:limit] if text else NA


def _params_of(item: object) -> dict[str, str]:
    """Return the substitution values of a deduction or recommendation, if it carries any."""
    values = getattr(item, "values", None)
    if isinstance(values, dict):
        return {str(key): str(value) for key, value in values.items()}
    return {}


def _percent_text(value: object | None) -> str:
    """
    Render a percentage exactly like the other output layers do.

    Unknown stays N/A, and a value that is not a number at all - a hand-built or v1.0 snapshot
    can carry one - degrades to N/A instead of putting ``None`` in a column.
    """
    if value is None or isinstance(value, bool):
        return NA
    try:
        return format_percent(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return NA


def is_settings_uri(value: object) -> bool:
    """
    True only for an ``ms-settings:`` page this window is allowed to open.

    The URI always comes from our own recommendation table, and it is still checked here:
    "we wrote it" is not a property this function can verify, and the check is the whole
    reason the button is safe. Anything else - a file, a program, a web address, a string
    with a space in it, or the same scheme in different capitals - is refused outright
    rather than repaired.
    """
    if not isinstance(value, str):
        return False
    uri = value.strip()
    if not uri.startswith(ACTION_URI_PREFIX):
        return False
    return bool(_ACTION_URI_PATTERN.match(uri))


def _canvas_class() -> Any:
    """The canvas widget to draw the history chart on, with a plain Tk fallback."""
    canvas = getattr(ctk, "CTkCanvas", None)
    if canvas is not None:
        return canvas
    from tkinter import Canvas  # pragma: no cover - only a very old CustomTkinter gets here

    return Canvas


def _detail_pairs(details: object) -> list[tuple[str, str]]:
    """Read ``SecurityInfo.details`` defensively; a note in an odd shape is skipped."""
    pairs: list[tuple[str, str]] = []
    for item in tuple(details or ()):
        try:
            key, value = item  # type: ignore[misc]
        except (TypeError, ValueError):
            continue
        pairs.append((str(key), str(value)))
    return pairs


#: Every figure a drive can answer with. An entry that answered none of them carries nothing
#: but a letter, and is left out of the table the same way the text report leaves it out.
_DRIVE_FIGURES: tuple[str, ...] = (
    "model",
    "bus_type",
    "media_type",
    "percentage_used",
    "temperature_celsius",
    "power_on_hours",
    "data_written_bytes",
    "critical_warning",
)


def _drive_answered(drive: object) -> bool:
    """True when a drive answered at least one query; a row of pure N/A is noise."""
    return any(getattr(drive, name, None) is not None for name in _DRIVE_FIGURES)


def _size_key(value: object | None) -> int:
    """Sort weight for a folder size. An unmeasured folder sorts below every measured one."""
    number = _as_int(value)
    return -1 if number is None else number


def _as_int(value: object | None) -> int | None:
    """Read a whole number from a snapshot field, or None when there is nothing to read."""
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _fraction(percent: float | int | None) -> float:
    """Convert a 0-100 percentage into the 0-1 value a CTkProgressBar expects."""
    if percent is None:
        return 0.0
    try:
        return max(0.0, min(1.0, float(percent) / 100.0))
    except (TypeError, ValueError):
        return 0.0


class _FallbackTranslator:
    """Stand-in used when :mod:`src.i18n` is unavailable, so the UI still renders English."""

    language = "en"

    def t(self, key: str, default: str | None = None, **params: object) -> str:
        text = default if default is not None else key
        if not params:
            return text
        try:
            return text.format(**params)
        except Exception:  # A malformed template must never break a label.
            return text

    __call__ = t

    def has(self, key: str) -> bool:
        return False

    def missing_keys(self) -> tuple[str, ...]:
        return ()


def _make_translator(language: str) -> Any:
    if _i18n is None:
        return _FallbackTranslator()
    try:
        return _i18n.get_translator(language)
    except Exception:
        return _FallbackTranslator()


def _available_languages() -> tuple[str, ...]:
    if _i18n is None:
        return ("en",)
    try:
        languages = tuple(str(code) for code in _i18n.available_languages())
    except Exception:
        return ("en",)
    return languages or ("en",)


def _language_label(code: str) -> str:
    if _i18n is not None:
        try:
            return str(_i18n.language_label(code))
        except Exception:
            pass
    return {"en": "English", "sk": "Slovencina"}.get(code, code)


def _detect_language() -> str:
    if _i18n is not None:
        try:
            detected = str(_i18n.detect_language())
        except Exception:
            detected = "en"
        if detected in _available_languages():
            return detected
    return "en"


class MetricCard(ctk.CTkFrame):
    """Reusable dashboard card with a title and a list of label/value rows."""

    def __init__(self, master: Any, palette: dict[str, str], title: str, icon: str) -> None:
        super().__init__(
            master,
            fg_color=palette["card"],
            corner_radius=16,
            border_width=1,
            border_color=palette["border"],
        )
        self._palette = palette
        self._rows: list[Any] = []
        self.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            self,
            text=icon,
            width=36,
            height=36,
            corner_radius=10,
            fg_color=palette["icon_bg"],
            text_color=palette["accent"],
            font=ctk.CTkFont(size=13, weight="bold"),
        ).grid(row=0, column=0, padx=(16, 10), pady=(16, 12), sticky="w")
        ctk.CTkLabel(
            self,
            text=title,
            text_color=palette["text"],
            font=ctk.CTkFont(size=15, weight="bold"),
            anchor="w",
        ).grid(row=0, column=1, padx=(0, 16), pady=(16, 12), sticky="w")

    def set_rows(self, rows: Sequence[tuple[str, str]]) -> None:
        for widget in self._rows:
            widget.destroy()
        self._rows.clear()

        for index, (key, value) in enumerate(rows, start=1):
            name_label = ctk.CTkLabel(
                self,
                text=key,
                text_color=self._palette["muted"],
                font=ctk.CTkFont(size=12),
                anchor="w",
            )
            name_label.grid(row=index, column=0, padx=(16, 8), pady=(0, 9), sticky="w")
            value_label = ctk.CTkLabel(
                self,
                text=value,
                text_color=self._palette["text"],
                font=ctk.CTkFont(size=12, weight="bold"),
                anchor="e",
                justify="right",
                wraplength=260,
            )
            value_label.grid(row=index, column=1, padx=(8, 16), pady=(0, 9), sticky="e")
            self._rows.extend((name_label, value_label))


class ApoliakAnalyzerApp(ctk.CTk):
    """Main window: sidebar with actions, five stacked views, one worker thread."""

    def __init__(self, *, theme: str = "dark", language: str | None = None) -> None:
        super().__init__(fg_color=PALETTES.get(theme, DARK_PALETTE)["bg"])
        self.theme = theme if theme in PALETTES else "dark"
        self.language = language if language in _available_languages() else _detect_language()
        self.translator: Any = _make_translator(self.language)

        self.geometry("1280x860")
        self.minsize(1040, 720)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        self.analysis: AnalysisData | None = None
        self.assessment: HealthAssessment | None = None
        # v1.0 returned plain strings here, v2.0 returns Recommendation objects; both render.
        self.recommendations: list[Any] = []
        self.export_format = "text"
        self.current_view = "overview"
        self.save_history = False
        self.history_note: str | None = None
        # Off by default: the on-screen report is for the owner of the PC, who gains nothing
        # from masking their own name. It is switched on before a report leaves the machine.
        self.redact = False

        self._running = False
        self._result_queue: Queue[tuple[Any, ...]] = Queue()
        self._poll_job: str | None = None
        #: Pending "Copied" -> "Copy to clipboard" reset, so it can be cancelled on teardown.
        self._copy_job: str | None = None
        #: Pending history-chart redraw after a resize, cancelled on teardown and on rebuild.
        self._chart_job: str | None = None
        #: Scores behind the history chart, oldest first, and the canvas size last drawn at.
        self._chart_scores: tuple[int, ...] = ()
        self._chart_size: tuple[int, int] = (0, 0)
        #: The current progress caption as ``(translation key, English default)`` rather than
        #: finished text, so a language switch re-translates the line instead of freezing it.
        self._progress_key: tuple[str, str] | None = None
        self._progress_value = 0.0

        try:
            ctk.set_appearance_mode(self.theme)
        except Exception:  # Appearance mode is cosmetic; never let it stop startup.
            pass

        self._build_ui()
        self._render_all()

    # ----------------------------------------------------------------- helpers

    @property
    def palette(self) -> dict[str, str]:
        return PALETTES[self.theme]

    def t(self, key: str, default: str, **params: object) -> str:
        """Translate, always with an English default so a missing key never leaks to the UI."""
        try:
            return str(self.translator.t(key, default=default, **params))
        except Exception:
            return default

    def t_plural(
        self, base_key: str, count: object, default: str, /, **params: object
    ) -> str:
        """
        Translate a label whose wording depends on ``count``.

        Which noun form a number takes is a property of the language, not of the widget:
        Slovak needs "1 upozornenie", "3 upozornenia" and "5 upozornení". The translator
        therefore decides; a fallback translator that predates ``t_plural`` gets the plain
        key and the English default.

        The first three arguments are positional-only, exactly as in the translator, so that
        a caller can pass ``count="12 345"`` for the text without colliding with the number
        the grammar is chosen from.
        """
        # ``count`` is the default substitution and a caller may override it - a formatted
        # "12 345" reads better than a bare 12345, and the grammatical form still follows the
        # real number. Building one dict keeps that override from colliding with the keyword.
        values: dict[str, object] = {"count": count}
        values.update(params)
        method = getattr(self.translator, "t_plural", None)
        if callable(method):
            try:
                return str(method(base_key, count, default, **values))
            except Exception:
                pass
        return self.t(base_key, default, **values)

    def _score_color(self, score: int | None) -> str:
        palette = self.palette
        if score is None:
            return palette["muted"]
        if score >= 90:
            return palette["success"]
        if score >= 75:
            return palette["accent"]
        if score >= 50:
            return palette["warning"]
        return palette["danger"]

    def _severity_color(self, severity: str) -> str:
        palette = self.palette
        return {
            "critical": palette["danger"],
            "warning": palette["warning"],
            "info": palette["accent"],
        }.get(str(severity), palette["accent"])

    def _state_color(self, state: str) -> str:
        """Colour of one protection verdict. Unknown is muted grey, never a warning."""
        palette = self.palette
        return {
            STATE_GOOD: palette["success"],
            STATE_WEAK: palette["warning"],
            STATE_BAD: palette["danger"],
        }.get(str(state), palette["muted"])

    def _state_pill_color(self, state: str) -> str:
        palette = self.palette
        return {
            STATE_GOOD: palette["pill_ok"],
            STATE_WEAK: palette["pill_warn"],
            STATE_BAD: palette["pill_bad"],
        }.get(str(state), palette["card_alt"])

    def _state_label(self, state: str) -> str:
        key, default = SECURITY_STATE_LABELS.get(
            str(state), SECURITY_STATE_LABELS[STATE_UNKNOWN]
        )
        return self.t(key, default)

    @staticmethod
    def _milliwatt_hours(value: object | None) -> str:
        """A battery capacity with its unit symbol, grouped like every other count."""
        number = _as_int(value)
        if number is None:
            return NA
        return f"{format_count(number)} mWh"

    @staticmethod
    def _celsius(value: object | None) -> str:
        """A temperature with its unit symbol. "C" is a symbol, not a word, so it is no key."""
        number = _as_int(value)
        if number is None:
            return NA
        return f"{number} °C"

    def _hours(self, value: object | None) -> str:
        """A number of hours, declined by the language. Drives report five-figure counts."""
        number = _as_int(value)
        if number is None:
            return NA
        return self.t_plural("report.hours", number, "{count} hours", count=format_count(number))

    def _days(self, value: object | None) -> str:
        """Whole days, in the grammatical number the chosen language needs."""
        number = _as_int(value)
        if number is None:
            return NA
        return self.t_plural("report.days", number, "{count} days", count=format_count(number))

    def _severity_label(self, severity: str) -> str:
        defaults = {"info": "Info", "warning": "Warning", "critical": "Critical"}
        key = str(severity) if str(severity) in defaults else "info"
        return self.t(f"severity.{key}", defaults[key])

    def _category_label(self, key: str) -> str:
        return self.t(f"category.{key}", CATEGORY_DEFAULT_LABELS.get(key, key.title()))

    def _view_label(self, key: str) -> str:
        return self.t(f"gui.nav.{key}", VIEW_DEFAULT_LABELS.get(key, key.title()))

    def _format_label(self, fmt: str) -> str:
        for key, _extension, default_label, _dialog in FORMAT_SPECS:
            if key == fmt:
                return self.t(f"gui.format.{key}", default_label)
        return fmt

    @staticmethod
    def _clear(frame: Any) -> None:
        for child in frame.winfo_children():
            child.destroy()

    # ------------------------------------------------------------ construction

    def _window_title(self) -> str:
        """
        Text of the title bar.

        ``gui.title`` is the product name a translation may localise; ``gui.window_title`` is
        the older key and stays the fallback, so a table that ships only one of the two still
        names the window instead of falling back to the English literal.
        """
        return self.t("gui.title", self.t("gui.window_title", "Apoliak Vitals"))

    def _apply_window_icon(self) -> None:
        """
        Put the app icon on the window and the taskbar button.

        The icon travels inside the one-file executable, where PyInstaller unpacks it to
        ``sys._MEIPASS``. A missing or rejected icon is never worth failing a startup over.
        """
        import sys

        roots = [Path(getattr(sys, "_MEIPASS", "")), Path(__file__).resolve().parent]
        for root in roots:
            candidate = root / "app.ico"
            try:
                if candidate.is_file():
                    self.iconbitmap(default=str(candidate))
                    return
            except Exception:
                continue

    def _build_ui(self) -> None:
        self.title(self._window_title())
        self._apply_window_icon()
        self.configure(fg_color=self.palette["bg"])
        self._build_sidebar()
        self._build_main()

    def _build_sidebar(self) -> None:
        palette = self.palette
        sidebar = ctk.CTkFrame(self, width=272, corner_radius=0, fg_color=palette["sidebar"])
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(15, weight=1)
        self.sidebar = sidebar

        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, padx=20, pady=(22, 20), sticky="ew")
        ctk.CTkLabel(
            brand,
            text="A",
            width=42,
            height=42,
            corner_radius=13,
            fg_color=palette["accent"],
            text_color=palette["accent_text"],
            font=ctk.CTkFont(size=22, weight="bold"),
        ).grid(row=0, column=0, rowspan=2, padx=(0, 12))
        ctk.CTkLabel(
            brand,
            text=self.t("gui.brand.name", "APOLIAK"),
            text_color=palette["text"],
            font=ctk.CTkFont(size=18, weight="bold"),
        ).grid(row=0, column=1, sticky="sw")
        ctk.CTkLabel(
            brand,
            text=self.t("gui.brand.tagline", "VITALS"),
            text_color=palette["accent"],
            font=ctk.CTkFont(size=10, weight="bold"),
        ).grid(row=1, column=1, sticky="nw")

        self._sidebar_caption(sidebar, 1, self.t("gui.sidebar.analysis", "ANALYSIS"))
        self.analyze_button = ctk.CTkButton(
            sidebar,
            text=self.t("gui.button.analyze", "Analyze my PC"),
            height=44,
            corner_radius=12,
            fg_color=palette["accent"],
            hover_color=palette["accent_hover"],
            text_color=palette["accent_text"],
            font=ctk.CTkFont(size=14, weight="bold"),
            command=self.start_analysis,
        )
        self.analyze_button.grid(row=2, column=0, padx=18, pady=(0, 16), sticky="ew")

        self._sidebar_caption(sidebar, 3, self.t("gui.sidebar.export", "EXPORT"))
        self.format_menu = ctk.CTkOptionMenu(
            sidebar,
            values=[self._format_label(spec[0]) for spec in FORMAT_SPECS],
            height=32,
            corner_radius=10,
            fg_color=palette["card"],
            button_color=palette["card"],
            button_hover_color=palette["hover"],
            text_color=palette["text"],
            dropdown_fg_color=palette["card"],
            dropdown_hover_color=palette["hover"],
            dropdown_text_color=palette["text"],
            font=ctk.CTkFont(size=12),
            dropdown_font=ctk.CTkFont(size=12),
            command=self._on_format_selected,
        )
        self.format_menu.set(self._format_label(self.export_format))
        self.format_menu.grid(row=4, column=0, padx=18, pady=(0, 8), sticky="ew")

        self.export_button = ctk.CTkButton(
            sidebar,
            text=self.t("gui.button.export", "Export report"),
            height=38,
            corner_radius=12,
            fg_color="transparent",
            border_width=1,
            border_color=palette["border"],
            hover_color=palette["hover"],
            text_color=palette["text"],
            font=ctk.CTkFont(size=12),
            state="disabled",
            command=self.export_current_report,
        )
        self.export_button.grid(row=5, column=0, padx=18, pady=(0, 8), sticky="ew")

        self.copy_button = ctk.CTkButton(
            sidebar,
            text=self.t("gui.button.copy", "Copy to clipboard"),
            height=38,
            corner_radius=12,
            fg_color="transparent",
            border_width=1,
            border_color=palette["border"],
            hover_color=palette["hover"],
            text_color=palette["text"],
            font=ctk.CTkFont(size=12),
            state="disabled",
            command=self.copy_report_to_clipboard,
        )
        self.copy_button.grid(row=6, column=0, padx=18, pady=(0, 10), sticky="ew")

        # Sits with the export controls because that is the only moment it matters: the
        # snapshot on screen never leaves this PC, an exported or copied report does.
        self.redact_var = ctk.BooleanVar(value=self.redact)
        self.redact_checkbox = ctk.CTkCheckBox(
            sidebar,
            text=self.t("gui.label.redact", "Redact personal data"),
            variable=self.redact_var,
            onvalue=True,
            offvalue=False,
            checkbox_width=18,
            checkbox_height=18,
            corner_radius=5,
            fg_color=palette["accent"],
            hover_color=palette["accent_hover"],
            border_color=palette["border"],
            checkmark_color=palette["accent_text"],
            text_color=palette["text"],
            font=ctk.CTkFont(size=12),
            command=self._on_redact_toggled,
        )
        self.redact_checkbox.grid(row=7, column=0, padx=20, pady=(0, 3), sticky="w")
        ctk.CTkLabel(
            sidebar,
            text=self.t(
                "gui.label.redact_hint",
                "Replaces your Windows account name with <user> in exported and copied "
                "reports, so they are safe to share.",
            ),
            text_color=palette["faint"],
            justify="left",
            anchor="w",
            wraplength=210,
            font=ctk.CTkFont(size=10),
        ).grid(row=8, column=0, padx=20, pady=(0, 14), sticky="w")

        notice = ctk.CTkFrame(
            sidebar,
            fg_color=palette["notice_bg"],
            corner_radius=14,
            border_width=1,
            border_color=palette["notice_border"],
        )
        notice.grid(row=9, column=0, padx=18, pady=(0, 16), sticky="ew")
        ctk.CTkLabel(
            notice,
            text=self.t("gui.label.readonly_title", "Read-only mode").upper(),
            text_color=palette["success"],
            font=ctk.CTkFont(size=10, weight="bold"),
        ).pack(anchor="w", padx=14, pady=(12, 4))
        ctk.CTkLabel(
            notice,
            text=self.t(
                "gui.label.readonly_body",
                "This app only reads system information. It never deletes files, edits the "
                "registry, stops services, or changes Windows settings.",
            ),
            text_color=palette["notice_text"],
            justify="left",
            anchor="w",
            wraplength=200,
            font=ctk.CTkFont(size=11),
        ).pack(anchor="w", padx=14, pady=(0, 12))

        self._sidebar_caption(sidebar, 10, self.t("gui.nav.settings", "Settings").upper())
        self._sidebar_field(sidebar, 11, self.t("gui.label.language", "Language"))
        self.language_menu = ctk.CTkOptionMenu(
            sidebar,
            values=[_language_label(code) for code in _available_languages()],
            height=32,
            corner_radius=10,
            fg_color=palette["card"],
            button_color=palette["card"],
            button_hover_color=palette["hover"],
            text_color=palette["text"],
            dropdown_fg_color=palette["card"],
            dropdown_hover_color=palette["hover"],
            dropdown_text_color=palette["text"],
            font=ctk.CTkFont(size=12),
            dropdown_font=ctk.CTkFont(size=12),
            command=self._on_language_selected,
        )
        self.language_menu.set(_language_label(self.language))
        self.language_menu.grid(row=12, column=0, padx=18, pady=(0, 8), sticky="ew")

        self._sidebar_field(sidebar, 13, self.t("gui.label.theme", "Theme"))
        self.theme_switch = ctk.CTkSegmentedButton(
            sidebar,
            values=[self.t("gui.theme.dark", "Dark"), self.t("gui.theme.light", "Light")],
            height=30,
            corner_radius=10,
            fg_color=palette["card"],
            selected_color=palette["accent"],
            selected_hover_color=palette["accent_hover"],
            unselected_color=palette["card"],
            unselected_hover_color=palette["hover"],
            text_color=palette["text"],
            font=ctk.CTkFont(size=12),
            command=self._on_theme_selected,
        )
        self.theme_switch.set(
            self.t("gui.theme.dark", "Dark")
            if self.theme == "dark"
            else self.t("gui.theme.light", "Light")
        )
        self.theme_switch.grid(row=14, column=0, padx=18, pady=(0, 14), sticky="ew")

        ctk.CTkLabel(
            sidebar,
            text="{version}\n{subtitle}".format(
                version=self.t("gui.version", "Version {version}", version=APP_VERSION),
                subtitle=self.t("gui.subtitle", "Read-only Windows health check"),
            ),
            text_color=palette["faint"],
            justify="left",
            anchor="w",
            wraplength=210,
            font=ctk.CTkFont(size=10),
        ).grid(row=16, column=0, padx=20, pady=(0, 16), sticky="sw")

    def _sidebar_caption(self, parent: Any, row: int, text: str) -> None:
        ctk.CTkLabel(
            parent,
            text=text,
            text_color=self.palette["faint"],
            font=ctk.CTkFont(size=10, weight="bold"),
        ).grid(row=row, column=0, padx=22, pady=(0, 7), sticky="w")

    def _sidebar_field(self, parent: Any, row: int, text: str) -> None:
        ctk.CTkLabel(
            parent,
            text=text,
            text_color=self.palette["muted"],
            font=ctk.CTkFont(size=11),
        ).grid(row=row, column=0, padx=22, pady=(0, 3), sticky="w")

    def _build_main(self) -> None:
        palette = self.palette
        main = ctk.CTkFrame(self, fg_color=palette["bg"], corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(2, weight=1)
        self.main = main

        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, padx=26, pady=(22, 8), sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        self.heading_label = ctk.CTkLabel(
            header,
            text=self._view_label(self.current_view),
            text_color=palette["text"],
            font=ctk.CTkFont(size=26, weight="bold"),
            anchor="w",
        )
        self.heading_label.grid(row=0, column=0, sticky="w")
        self.state_pill = ctk.CTkLabel(
            header,
            text=f"  {self.t('gui.state.ready', 'Ready')}  ",
            height=28,
            corner_radius=14,
            fg_color=palette["pill_ok"],
            text_color=palette["success"],
            font=ctk.CTkFont(size=11, weight="bold"),
        )
        self.state_pill.grid(row=0, column=1, rowspan=2, padx=(12, 0), sticky="e")
        self.subtitle_label = ctk.CTkLabel(
            header,
            text=self.t("gui.label.not_analyzed", "Not analyzed yet"),
            text_color=palette["muted"],
            font=ctk.CTkFont(size=11),
            anchor="w",
        )
        self.subtitle_label.grid(row=1, column=0, pady=(3, 0), sticky="w")
        self.progress_bar = ctk.CTkProgressBar(
            header,
            height=8,
            corner_radius=6,
            fg_color=palette["track"],
            progress_color=palette["accent"],
        )
        self.progress_bar.grid(row=2, column=0, columnspan=2, pady=(14, 4), sticky="ew")
        self.progress_bar.set(self._progress_value)
        self.progress_label = ctk.CTkLabel(
            header,
            text=self._progress_line(),
            text_color=palette["faint"],
            font=ctk.CTkFont(size=10),
            anchor="w",
        )
        self.progress_label.grid(row=3, column=0, columnspan=2, sticky="w")

        self._nav_labels = {key: self._view_label(key) for key in VIEWS}
        self._nav_lookup = {label: key for key, label in self._nav_labels.items()}
        self.nav = ctk.CTkSegmentedButton(
            main,
            values=[self._nav_labels[key] for key in VIEWS],
            height=34,
            corner_radius=10,
            fg_color=palette["card_alt"],
            selected_color=palette["accent"],
            selected_hover_color=palette["accent_hover"],
            unselected_color=palette["card_alt"],
            unselected_hover_color=palette["hover"],
            text_color=palette["text"],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_nav_selected,
        )
        self.nav.grid(row=1, column=0, padx=26, pady=(6, 12), sticky="w")
        self.nav.set(self._nav_labels[self.current_view])

        container = ctk.CTkFrame(main, fg_color="transparent")
        container.grid(row=2, column=0, sticky="nsew")
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        self.view_container = container

        # Views are created once and shown on demand, so switching never rebuilds widgets.
        self.views: dict[str, Any] = {}
        for key in VIEWS:
            frame = ctk.CTkScrollableFrame(
                container,
                fg_color=palette["bg"],
                corner_radius=0,
                scrollbar_button_color=palette["scroll"],
                scrollbar_button_hover_color=palette["scroll_hover"],
            )
            frame.grid(row=0, column=0, sticky="nsew")
            frame.grid_columnconfigure(0, weight=1)
            self.views[key] = frame

        self._build_overview(self.views["overview"])
        self._build_processes(self.views["processes"])
        self._build_storage(self.views["storage"])
        self._build_security(self.views["security"])
        self._build_system(self.views["system"])
        self._build_history(self.views["history"])
        self._show_view(self.current_view)
        self._apply_run_state()

    def _card(self, parent: Any) -> Any:
        palette = self.palette
        return ctk.CTkFrame(
            parent,
            fg_color=palette["card"],
            corner_radius=16,
            border_width=1,
            border_color=palette["border"],
        )

    def _section(self, parent: Any, title: str) -> tuple[Any, Any]:
        """Create a titled card and return ``(card, body)``; the caller fills the body."""
        palette = self.palette
        card = self._card(parent)
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card,
            text=title,
            text_color=palette["text"],
            font=ctk.CTkFont(size=15, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=18, pady=(16, 8), sticky="w")
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=0, padx=18, pady=(0, 16), sticky="ew")
        body.grid_columnconfigure(0, weight=1)
        return card, body

    def _kv_row(self, parent: Any, row: int, label: str, value: str) -> None:
        palette = self.palette
        parent.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            parent,
            text=label,
            text_color=palette["muted"],
            font=ctk.CTkFont(size=12),
            anchor="w",
        ).grid(row=row, column=0, padx=(0, 14), pady=3, sticky="w")
        ctk.CTkLabel(
            parent,
            text=value,
            text_color=palette["text"],
            font=ctk.CTkFont(size=12, weight="bold"),
            anchor="w",
            justify="left",
            wraplength=520,
        ).grid(row=row, column=1, pady=3, sticky="w")

    def _empty_label(self, parent: Any, text: str) -> Any:
        return ctk.CTkLabel(
            parent,
            text=text,
            text_color=self.palette["muted"],
            font=ctk.CTkFont(size=12),
            anchor="w",
            justify="left",
            wraplength=740,
        )

    # ------------------------------------------------------------------ views

    def _build_overview(self, parent: Any) -> None:
        palette = self.palette

        health = self._card(parent)
        health.grid(row=0, column=0, padx=26, pady=(18, 12), sticky="ew")
        health.grid_columnconfigure(2, weight=1)
        ctk.CTkLabel(
            health,
            text=self.t("gui.label.score", "Health score").upper(),
            text_color=palette["muted"],
            font=ctk.CTkFont(size=10, weight="bold"),
        ).grid(row=0, column=0, padx=(20, 14), pady=(16, 2), sticky="w")
        self.score_label = ctk.CTkLabel(
            health,
            text=self.t("gui.label.placeholder", "--"),
            width=96,
            text_color=palette["accent"],
            font=ctk.CTkFont(size=42, weight="bold"),
        )
        self.score_label.grid(row=1, column=0, padx=(18, 8), pady=(0, 6), sticky="w")
        ctk.CTkLabel(
            health,
            text=self.t("gui.health.of100", "/ 100"),
            text_color=palette["muted"],
            font=ctk.CTkFont(size=14),
        ).grid(row=1, column=1, padx=(0, 22), pady=(10, 6), sticky="w")
        self.status_label = ctk.CTkLabel(
            health,
            text=self.t("gui.label.no_data", "No data yet"),
            text_color=palette["text"],
            font=ctk.CTkFont(size=15, weight="bold"),
            anchor="w",
        )
        self.status_label.grid(row=0, column=2, padx=(0, 22), pady=(16, 4), sticky="sw")
        self.score_progress = ctk.CTkProgressBar(
            health,
            height=12,
            corner_radius=8,
            fg_color=palette["track"],
            progress_color=palette["accent"],
        )
        self.score_progress.grid(row=1, column=2, padx=(0, 22), pady=(8, 6), sticky="ew")
        self.score_progress.set(0)
        ctk.CTkLabel(
            health,
            text=self.t("gui.label.score_hint", "100 points minus every issue listed below."),
            text_color=palette["faint"],
            font=ctk.CTkFont(size=10),
            anchor="w",
        ).grid(row=2, column=0, columnspan=3, padx=20, pady=(0, 16), sticky="w")

        categories_card, categories_body = self._section(
            parent, self.t("gui.section.categories", "Category scores")
        )
        categories_card.grid(row=1, column=0, padx=26, pady=(0, 12), sticky="ew")
        categories_body.grid_columnconfigure(1, weight=1)
        self.category_widgets: dict[str, tuple[Any, Any]] = {}
        for index, key in enumerate(CATEGORY_ORDER):
            ctk.CTkLabel(
                categories_body,
                text=self._category_label(key),
                text_color=palette["muted"],
                font=ctk.CTkFont(size=12),
                width=120,
                anchor="w",
            ).grid(row=index, column=0, padx=(0, 12), pady=5, sticky="w")
            bar = ctk.CTkProgressBar(
                categories_body,
                height=9,
                corner_radius=6,
                fg_color=palette["track"],
                progress_color=palette["accent"],
            )
            bar.grid(row=index, column=1, pady=5, sticky="ew")
            bar.set(0)
            value = ctk.CTkLabel(
                categories_body,
                text=NA,
                text_color=palette["muted"],
                font=ctk.CTkFont(size=12, weight="bold"),
                width=54,
                anchor="e",
            )
            value.grid(row=index, column=2, padx=(12, 0), pady=5, sticky="e")
            self.category_widgets[key] = (bar, value)

        cards_frame = ctk.CTkFrame(parent, fg_color="transparent")
        cards_frame.grid(row=2, column=0, padx=17, pady=0, sticky="ew")
        cards_frame.grid_columnconfigure((0, 1), weight=1, uniform="cards")
        self.cards_frame = cards_frame

        card_titles = (
            ("system", "System", "OS"),
            ("cpu", "Processor", "CPU"),
            ("ram", "Memory", "RAM"),
            ("disk", "System Drive", "DSK"),
            ("activity", "Activity", "RUN"),
            ("temp", "Temporary Files", "TMP"),
            ("battery", "Battery", "BAT"),
            ("network", "Network", "NET"),
            ("gpu", "Graphics", "GPU"),
        )
        self.cards: dict[str, MetricCard] = {}
        for key, default_title, icon in card_titles:
            self.cards[key] = MetricCard(
                cards_frame, palette, self.t(f"gui.card.{key}", default_title), icon
            )

        deductions_card, deductions_body = self._section(
            parent, self.t("gui.section.deductions", "Score deductions")
        )
        deductions_card.grid(row=3, column=0, padx=26, pady=(12, 12), sticky="ew")
        self.deductions_body = deductions_body

        recommendations_card, recommendations_body = self._section(
            parent, self.t("gui.section.recommendations", "Recommendations")
        )
        recommendations_card.grid(row=4, column=0, padx=26, pady=(0, 24), sticky="ew")
        self.recommendations_body = recommendations_body

    def _build_processes(self, parent: Any) -> None:
        card, body = self._section(parent, self.t("gui.section.processes", "Top processes"))
        card.grid(row=0, column=0, padx=26, pady=(18, 24), sticky="ew")
        ctk.CTkLabel(
            body,
            text=self.t(
                "gui.processes.subtitle",
                "Sorted by memory use. This list is read-only - nothing is ever terminated.",
            ),
            text_color=self.palette["muted"],
            font=ctk.CTkFont(size=11),
            anchor="w",
            justify="left",
            wraplength=740,
        ).grid(row=0, column=0, pady=(0, 10), sticky="w")
        table = ctk.CTkFrame(body, fg_color="transparent")
        table.grid(row=1, column=0, sticky="ew")
        table.grid_columnconfigure(0, weight=1)
        self.process_table = table

    def _build_storage(self, parent: Any) -> None:
        card, body = self._section(parent, self.t("gui.storage.title", "Drives and partitions"))
        card.grid(row=0, column=0, padx=26, pady=(18, 12), sticky="ew")
        self.storage_body = body

        health_card, health_body = self._section(
            parent, self.t("gui.section.drive_health", "Drive health")
        )
        health_card.grid(row=1, column=0, padx=26, pady=(0, 12), sticky="ew")
        self.storage_health_body = health_body

        folders_card, folders_body = self._section(
            parent, self.t("gui.section.folders", "Biggest folders")
        )
        folders_card.grid(row=2, column=0, padx=26, pady=(0, 24), sticky="ew")
        self.storage_folders_body = folders_body

    def _build_security(self, parent: Any) -> None:
        """The protection view: what Windows reports, plus what the score made of it."""
        palette = self.palette
        status_card, status_body = self._section(parent, self.t("gui.card.security", "Security"))
        status_card.grid(row=0, column=0, padx=26, pady=(18, 12), sticky="ew")
        # The read-only promise, in the one place a reader is most likely to doubt it.
        ctk.CTkLabel(
            status_body,
            text=self.t(
                "gui.label.readonly_body",
                "This app only reads system information. It never deletes files, edits the "
                "registry, stops services, or changes Windows settings.",
            ),
            text_color=palette["muted"],
            font=ctk.CTkFont(size=11),
            anchor="w",
            justify="left",
            wraplength=740,
        ).grid(row=0, column=0, pady=(0, 10), sticky="w")
        rows = ctk.CTkFrame(status_body, fg_color="transparent")
        rows.grid(row=1, column=0, sticky="ew")
        rows.grid_columnconfigure(0, weight=1)
        self.security_rows = rows

        deductions_card, deductions_body = self._section(
            parent, self.t("gui.section.deductions", "Score deductions")
        )
        deductions_card.grid(row=1, column=0, padx=26, pady=(0, 12), sticky="ew")
        self.security_deductions_body = deductions_body

        advice_card, advice_body = self._section(
            parent, self.t("gui.section.recommendations", "Recommendations")
        )
        advice_card.grid(row=2, column=0, padx=26, pady=(0, 24), sticky="ew")
        self.security_recommendations_body = advice_body

    def _build_system(self, parent: Any) -> None:
        os_card, os_body = self._section(parent, self.t("gui.system.title", "Operating system"))
        os_card.grid(row=0, column=0, padx=26, pady=(18, 12), sticky="ew")
        self.system_os_body = os_body

        firmware_card, firmware_body = self._section(
            parent, self.t("gui.system.firmware", "Firmware")
        )
        firmware_card.grid(row=1, column=0, padx=26, pady=(0, 12), sticky="ew")
        self.system_firmware_body = firmware_body

        gpu_card, gpu_body = self._section(parent, self.t("gui.system.gpus", "Graphics adapters"))
        gpu_card.grid(row=2, column=0, padx=26, pady=(0, 12), sticky="ew")
        self.system_gpu_body = gpu_body

        startup_card, startup_body = self._section(
            parent, self.t("field.startup_items", "Startup Items")
        )
        startup_card.grid(row=3, column=0, padx=26, pady=(0, 12), sticky="ew")
        self.system_startup_body = startup_body

        warnings_card, warnings_body = self._section(
            parent, self.t("gui.section.warnings", "Analysis warnings")
        )
        warnings_card.grid(row=4, column=0, padx=26, pady=(0, 24), sticky="ew")
        self.system_warnings_body = warnings_body

    def _build_history(self, parent: Any) -> None:
        palette = self.palette
        card, body = self._section(parent, self.t("gui.history.title", "Local history"))
        card.grid(row=0, column=0, padx=26, pady=(18, 24), sticky="ew")

        self.history_var = ctk.BooleanVar(value=self.save_history)
        self.history_checkbox = ctk.CTkCheckBox(
            body,
            text=self.t("gui.history.optin", "Save this analysis locally"),
            variable=self.history_var,
            onvalue=True,
            offvalue=False,
            checkbox_width=20,
            checkbox_height=20,
            corner_radius=6,
            fg_color=palette["accent"],
            hover_color=palette["accent_hover"],
            border_color=palette["border"],
            checkmark_color=palette["accent_text"],
            text_color=palette["text"],
            font=ctk.CTkFont(size=12, weight="bold"),
            command=self._on_history_toggled,
        )
        self.history_checkbox.grid(row=0, column=0, pady=(0, 6), sticky="w")
        ctk.CTkLabel(
            body,
            text=self.t(
                "gui.label.history_hint",
                "History is optional and stored only on this PC.",
            ),
            text_color=palette["muted"],
            font=ctk.CTkFont(size=11),
            anchor="w",
            justify="left",
            wraplength=740,
        ).grid(row=1, column=0, pady=(0, 4), sticky="w")
        ctk.CTkLabel(
            body,
            text=self.t(
                "gui.history.explain",
                "While the box above is unchecked, nothing is written to disk.",
            ),
            text_color=palette["muted"],
            font=ctk.CTkFont(size=11),
            anchor="w",
            justify="left",
            wraplength=740,
        ).grid(row=2, column=0, pady=(0, 10), sticky="w")

        location = ctk.CTkFrame(body, fg_color=palette["card_alt"], corner_radius=10)
        location.grid(row=3, column=0, pady=(0, 12), sticky="ew")
        location.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            location,
            text=self.t("gui.history.location", "Storage location"),
            text_color=palette["muted"],
            font=ctk.CTkFont(size=10, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=14, pady=(10, 0), sticky="w")
        self.history_path_label = ctk.CTkLabel(
            location,
            text=self._history_path_text(),
            text_color=palette["text"],
            font=ctk.CTkFont(size=11),
            anchor="w",
            justify="left",
            wraplength=700,
        )
        self.history_path_label.grid(row=1, column=0, padx=14, pady=(2, 10), sticky="w")

        self.history_status_label = ctk.CTkLabel(
            body,
            text="",
            text_color=palette["muted"],
            font=ctk.CTkFont(size=11),
            anchor="w",
            justify="left",
            wraplength=740,
        )
        self.history_status_label.grid(row=4, column=0, pady=(0, 8), sticky="w")

        ctk.CTkButton(
            body,
            text=self.t("gui.history.refresh", "Refresh list"),
            height=32,
            width=140,
            corner_radius=10,
            fg_color="transparent",
            border_width=1,
            border_color=palette["border"],
            hover_color=palette["hover"],
            text_color=palette["text"],
            font=ctk.CTkFont(size=12),
            command=self._render_history,
        ).grid(row=5, column=0, pady=(0, 12), sticky="w")

        chart = ctk.CTkFrame(body, fg_color=palette["card_alt"], corner_radius=12)
        chart.grid(row=6, column=0, pady=(0, 12), sticky="ew")
        chart.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            chart,
            text=self.t("gui.section.history_chart", "Score over time"),
            text_color=palette["muted"],
            font=ctk.CTkFont(size=10, weight="bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=14, pady=(10, 0), sticky="w")
        self.history_canvas = _canvas_class()(
            chart,
            height=CHART_HEIGHT,
            highlightthickness=0,
            borderwidth=0,
            background=palette["card_alt"],
        )
        self.history_canvas.grid(row=1, column=0, padx=12, pady=(6, 12), sticky="ew")
        # Tk lays the canvas out after this call, so the first draw uses a fallback width and
        # this binding redraws it at the real one - and again after every window resize.
        self.history_canvas.bind("<Configure>", self._on_chart_resize)
        self._chart_size = (0, 0)

        rows = ctk.CTkFrame(body, fg_color="transparent")
        rows.grid(row=7, column=0, sticky="ew")
        rows.grid_columnconfigure(0, weight=1)
        self.history_rows = rows

        if _history is None:
            self.history_checkbox.configure(state="disabled")

    # -------------------------------------------------------------- rerender

    def _rebuild_ui(self) -> None:
        """Rebuild every widget from stored state, so theme and language switches are clean."""
        self.save_history = self._read_history_choice()
        # Read before the widgets die: a rebuilt checkbox must not silently drop redaction.
        self.redact = self._read_redact_choice()
        # A queued redraw would come back to a canvas that no longer exists.
        self._cancel_job("_chart_job")
        self._chart_size = (0, 0)
        for child in self.winfo_children():
            child.destroy()
        self.configure(fg_color=self.palette["bg"])
        self._build_ui()
        self._render_all()

    def _read_history_choice(self) -> bool:
        variable = getattr(self, "history_var", None)
        if variable is None:
            return self.save_history
        try:
            return bool(variable.get())
        except Exception:
            return self.save_history

    def _read_redact_choice(self) -> bool:
        """The checkbox is the authority; the stored flag covers a torn-down or absent widget."""
        variable = getattr(self, "redact_var", None)
        if variable is None:
            return self.redact
        try:
            return bool(variable.get())
        except Exception:
            return self.redact

    def _on_nav_selected(self, label: str) -> None:
        self.select_view(self._nav_lookup.get(label, "overview"))

    def _show_view(self, key: str) -> None:
        """Map exactly one view; CTkScrollableFrame forwards grid calls to its outer frame."""
        for name, frame in self.views.items():
            if name == key:
                frame.grid(row=0, column=0, sticky="nsew")
            else:
                frame.grid_remove()
        self.heading_label.configure(text=self._view_label(key))

    def select_view(self, key: str) -> None:
        if key not in self.views:
            return
        self.current_view = key
        self._show_view(key)
        try:
            self.nav.set(self._nav_labels[key])
        except Exception:  # Setting the segmented button is cosmetic only.
            pass

    def _on_language_selected(self, label: str) -> None:
        for code in _available_languages():
            if _language_label(code) == label:
                self.set_language(code)
                return

    def set_language(self, code: str) -> None:
        if code == self.language:
            return
        self.language = code
        self.translator = _make_translator(code)
        self._rebuild_ui()

    def _on_theme_selected(self, label: str) -> None:
        light = self.t("gui.theme.light", "Light")
        self.set_theme("light" if label == light else "dark")

    def set_theme(self, name: str) -> None:
        if name not in PALETTES or name == self.theme:
            return
        self.theme = name
        try:
            ctk.set_appearance_mode(name)
        except Exception:
            pass
        self._rebuild_ui()

    def _on_format_selected(self, label: str) -> None:
        for key, _extension, _default, _dialog in FORMAT_SPECS:
            if self._format_label(key) == label:
                self.export_format = key
                return

    def _on_history_toggled(self) -> None:
        self.save_history = self._read_history_choice()

    def _on_redact_toggled(self) -> None:
        self.redact = self._read_redact_choice()

    def set_redact(self, enabled: bool) -> None:
        """Set redaction from code (tests, future CLI hand-off) and keep the checkbox in sync."""
        self.redact = bool(enabled)
        variable = getattr(self, "redact_var", None)
        if variable is None:
            return
        try:
            variable.set(self.redact)
        except Exception:  # The checkbox is cosmetic here; the flag above is what is used.
            pass

    # -------------------------------------------------------------- rendering

    def _render_all(self) -> None:
        self._render_overview()
        self._render_processes()
        self._render_storage()
        self._render_security()
        self._render_system()
        self._render_history()
        self._render_subtitle()

    def _render_subtitle(self) -> None:
        data = self.analysis
        if data is None:
            self.subtitle_label.configure(
                text=self.t("gui.label.not_analyzed", "Not analyzed yet")
            )
            return
        parts = [
            self.t(
                "gui.label.last_analyzed",
                "Last analysis: {value}",
                value=data.analyzed_at.strftime("%Y-%m-%d %H:%M:%S"),
            )
        ]
        if data.duration_seconds is not None:
            parts.append(
                self.t(
                    "gui.status.duration",
                    "took {duration}",
                    duration=format_duration(data.duration_seconds),
                )
            )
        if data.warnings:
            parts.append(
                self.t_plural("gui.status.warnings", len(data.warnings), "{count} warnings")
            )
        self.subtitle_label.configure(text="  -  ".join(parts))

    def _render_overview(self) -> None:
        palette = self.palette
        data = self.analysis
        assessment = self.assessment

        if assessment is None:
            self.score_label.configure(
                text=self.t("gui.label.placeholder", "--"), text_color=palette["muted"]
            )
            self.status_label.configure(
                text=self.t("gui.label.no_data", "No data yet"), text_color=palette["text"]
            )
            self.score_progress.configure(progress_color=palette["accent"])
            self.score_progress.set(0)
        else:
            color = self._score_color(assessment.score)
            self.score_label.configure(text=str(assessment.score), text_color=color)
            self.status_label.configure(
                text=self._status_text(assessment.status), text_color=color
            )
            self.score_progress.configure(progress_color=color)
            self.score_progress.set(_fraction(assessment.score))

        for key, (bar, value_label) in self.category_widgets.items():
            category = assessment.category(key) if assessment is not None else None
            if category is None or not getattr(category, "available", True):
                bar.configure(progress_color=palette["track"])
                bar.set(0)
                value_label.configure(text=NA, text_color=palette["muted"])
                continue
            color = self._score_color(category.score)
            bar.configure(progress_color=color)
            bar.set(_fraction(category.score))
            value_label.configure(text=str(category.score), text_color=color)

        self._render_cards(data, assessment)
        self._render_deductions(assessment)
        self._render_recommendations()

    def _status_text(self, status: str) -> str:
        keys = {
            "Excellent": "status.excellent",
            "Good": "status.good",
            "Needs Optimization": "status.needs_optimization",
            "Poor": "status.poor",
        }
        key = keys.get(status)
        if key is None:  # A custom status from a future scoring build still renders as-is.
            return status
        return self.t(key, status)

    def _render_cards(self, data: AnalysisData | None, assessment: HealthAssessment | None) -> None:
        if data is None:
            status = self.t("field.status", "Status")
            waiting = self.t("gui.label.no_data", "No data yet")
            for card in self.cards.values():
                card.set_rows([(status, waiting)])
            self._layout_cards(("system", "cpu", "ram", "disk", "activity", "temp"))
            return

        system = data.system
        self.cards["system"].set_rows(
            [
                (self.t("field.os", "System"), _display(system.os_name)),
                (self.t("field.edition", "Edition"), _display(system.edition)),
                (
                    self.t("field.display_version", "Windows Version"),
                    _display(system.display_version),
                ),
                (self.t("field.build", "Build"), _display(system.build or system.version)),
                (self.t("field.architecture", "Architecture"), _display(system.architecture)),
            ]
        )
        self.cards["cpu"].set_rows(
            [
                (self.t("field.usage", "Usage"), format_percent(data.cpu.usage_percent)),
                (
                    self.t("field.physical_cores", "Physical Cores"),
                    _display(data.cpu.physical_cores),
                ),
                (
                    self.t("field.logical_cores", "Logical Cores"),
                    _display(data.cpu.logical_cores),
                ),
                (
                    self.t("field.frequency", "CPU Frequency"),
                    format_frequency(data.cpu.frequency_mhz),
                ),
                (self.t("field.processor", "Processor"), _display(system.processor)),
            ]
        )
        ram_rows = [
            (self.t("field.usage", "Usage"), format_percent(data.ram.usage_percent)),
            (self.t("field.used", "Used"), format_bytes(data.ram.used_bytes)),
            (self.t("field.available", "Available"), format_bytes(data.ram.available_bytes)),
            (self.t("field.installed", "Installed RAM"), format_bytes(data.ram.total_bytes)),
        ]
        if data.ram.swap_total_bytes:
            ram_rows.append(
                (
                    self.t("field.swap", "Page File"),
                    "{used} / {total} ({percent})".format(
                        used=format_bytes(data.ram.swap_used_bytes),
                        total=format_bytes(data.ram.swap_total_bytes),
                        percent=format_percent(data.ram.swap_percent),
                    ),
                )
            )
        self.cards["ram"].set_rows(ram_rows)
        self.cards["disk"].set_rows(
            [
                (self.t("field.drive", "Drive"), _display(data.disk.drive)),
                (self.t("field.usage", "Usage"), format_percent(data.disk.usage_percent)),
                (self.t("field.free", "Free"), format_bytes(data.disk.free_bytes)),
                (self.t("field.total", "Total"), format_bytes(data.disk.total_bytes)),
                (self.t("field.media_type", "Media Type"), _display(data.disk.media_type)),
            ]
        )
        yes = self.t("field.yes", "Yes")
        no = self.t("field.no", "No")
        self.cards["activity"].set_rows(
            [
                (
                    self.t("field.processes", "Running Processes"),
                    format_count(data.process_count),
                ),
                (self.t("field.uptime", "System Uptime"), format_uptime(data.uptime_seconds)),
                (self.t("field.boot_time", "Last Boot"), _datetime_text(system.boot_time)),
                (
                    self.t("field.data_complete", "Data Complete"),
                    (yes if assessment.data_complete else no) if assessment else NA,
                ),
                (
                    self.t("field.duration", "Duration"),
                    format_duration(data.duration_seconds),
                ),
            ]
        )
        # A truncated scan ran out of time, so the size is a lower bound. Labelling it the way
        # the text report does keeps the user from reading a partial number as a measurement.
        temp_size = format_bytes(data.temp_size_bytes)
        if data.temp_truncated:
            temp_size = f"{temp_size} ({self.t('report.partial_scan', 'partial scan')})"
        temp_rows = [
            (self.t("field.folder_size", "Folder Size"), temp_size),
            (self.t("field.path", "Path"), _display(data.temp_path)),
        ]
        if data.temp_locations:
            temp_rows.append(
                (
                    self.t("gui.field.locations", "Locations"),
                    format_count(len(data.temp_locations)),
                )
            )
        temp_rows.append((self.t("gui.field.files_changed", "Files changed"), no))
        self.cards["temp"].set_rows(temp_rows)

        visible = ["system", "cpu", "ram", "disk", "activity", "temp"]

        if data.battery is not None:
            seconds_left = data.battery.seconds_left
            remaining = (
                format_duration(seconds_left)
                if seconds_left is not None and seconds_left >= 0
                else NA
            )
            if data.battery.plugged_in is None:
                power = NA
            elif data.battery.plugged_in:
                power = self.t("gui.value.plugged", "Plugged in")
            else:
                power = self.t("gui.value.on_battery", "On battery")
            battery_rows = [
                (self.t("gui.field.charge", "Charge"), format_percent(data.battery.percent)),
                (self.t("field.plugged_in", "Plugged In"), power),
                (self.t("field.time_left", "Time Left"), remaining),
            ]
            # Wear, not charge: how much of the pack's original capacity is still there.
            # Each row appears only when the firmware actually reported that figure - a
            # battery that answers nothing simply keeps the three charge rows above.
            health = getattr(data.battery, "health_percent", None)
            if health is not None:
                battery_rows.append(
                    (self.t("field.battery_health", "Battery Health"), format_percent(health))
                )
            full_charge = getattr(data.battery, "full_charge_capacity_mwh", None)
            if full_charge is not None:
                battery_rows.append(
                    (
                        self.t("field.full_charge_capacity", "Full Charge Capacity"),
                        self._milliwatt_hours(full_charge),
                    )
                )
            design = getattr(data.battery, "design_capacity_mwh", None)
            if design is not None:
                battery_rows.append(
                    (
                        self.t("field.design_capacity", "Design Capacity"),
                        self._milliwatt_hours(design),
                    )
                )
            cycles = getattr(data.battery, "cycle_count", None)
            if cycles is not None:
                battery_rows.append(
                    (self.t("field.cycle_count", "Charge Cycles"), format_count(cycles))
                )
            self.cards["battery"].set_rows(battery_rows)
            visible.append("battery")

        network = data.network
        if network is not None:
            active = sum(1 for item in network.interfaces if item.is_up)
            self.cards["network"].set_rows(
                [
                    (self.t("field.sent", "Sent"), format_bytes(network.bytes_sent)),
                    (
                        self.t("field.received", "Received"),
                        format_bytes(network.bytes_received),
                    ),
                    (
                        self.t("field.interfaces", "Interfaces"),
                        format_count(active) if network.interfaces else NA,
                    ),
                ]
            )
            visible.append("network")

        if data.gpus:
            primary = data.gpus[0]
            gpu_rows = [
                (self.t("field.name", "Name"), _display(primary.name)),
                (self.t("field.driver", "Driver"), _display(primary.driver_version)),
                (self.t("field.gpu_memory", "Graphics Memory"), format_bytes(primary.memory_bytes)),
            ]
            if len(data.gpus) > 1:
                gpu_rows.append(
                    (self.t("gui.field.adapters", "Adapters"), format_count(len(data.gpus)))
                )
            self.cards["gpu"].set_rows(gpu_rows)
            visible.append("gpu")

        self._layout_cards(tuple(visible))

    def _layout_cards(self, visible: Sequence[str]) -> None:
        """Grid only the cards backed by real data, two per row, with no gaps."""
        for card in self.cards.values():
            card.grid_remove()
        for index, key in enumerate(visible):
            card = self.cards.get(key)
            if card is None:
                continue
            row, column = divmod(index, 2)
            card.grid(row=row, column=column, padx=9, pady=9, sticky="nsew")

    def _render_deductions(self, assessment: HealthAssessment | None) -> None:
        if assessment is None:
            self._clear(self.deductions_body)
            self._empty_label(
                self.deductions_body, self.t("gui.label.no_data", "No data yet")
            ).grid(row=0, column=0, sticky="w")
            return
        self._fill_deductions(
            self.deductions_body,
            assessment.deductions,
            self.t("gui.msg.no_deductions", "No points were deducted."),
        )

    def _fill_deductions(self, body: Any, items: Sequence[Any], empty_text: str) -> None:
        """Render a list of deductions into ``body``; shared by the overview and Security."""
        palette = self.palette
        self._clear(body)
        if not items:
            self._empty_label(body, empty_text).grid(row=0, column=0, sticky="w")
            return

        for index, item in enumerate(items):
            row = ctk.CTkFrame(body, fg_color=palette["row"], corner_radius=10)
            row.grid(row=index, column=0, pady=3, sticky="ew")
            row.grid_columnconfigure(1, weight=1)
            severity = str(getattr(item, "severity", "warning"))
            ctk.CTkLabel(
                row,
                text=self.t("gui.deductions.points", "-{points} pts", points=item.points),
                text_color=self._severity_color(severity),
                font=ctk.CTkFont(size=12, weight="bold"),
                width=70,
                anchor="w",
            ).grid(row=0, column=0, padx=(14, 10), pady=9, sticky="w")
            ctk.CTkLabel(
                row,
                text=self.t(f"deduction.{item.key}", item.reason, **_params_of(item)),
                text_color=palette["text"],
                font=ctk.CTkFont(size=12),
                anchor="w",
                justify="left",
                wraplength=540,
            ).grid(row=0, column=1, padx=(0, 10), pady=9, sticky="w")
            ctk.CTkLabel(
                row,
                text=self._category_label(str(getattr(item, "category", "general"))),
                text_color=palette["faint"],
                font=ctk.CTkFont(size=10, weight="bold"),
                anchor="e",
            ).grid(row=0, column=2, padx=(0, 14), pady=9, sticky="e")

    def _render_recommendations(self) -> None:
        self._fill_recommendations(
            self.recommendations_body,
            self.recommendations,
            self.t("gui.msg.no_recommendations", "No recommendations for this snapshot."),
        )

    def _fill_recommendations(self, body: Any, items: Sequence[Any], empty_text: str) -> None:
        """
        Render advice into ``body``; shared by the overview and the Security view.

        A piece of advice that names a Windows settings page gets a button next to it. The
        button is built here, but nothing is launched here: ``command`` fires on a click and
        on nothing else, which is what keeps rendering free of side effects.
        """
        palette = self.palette
        self._clear(body)
        if not items:
            self._empty_label(body, empty_text).grid(row=0, column=0, sticky="w")
            return

        actionable = False
        for index, item in enumerate(items):
            severity = str(getattr(item, "severity", "info"))
            key = getattr(item, "key", None)
            text = getattr(item, "text", None) or str(item)
            if key:
                text = self.t(f"recommendation.{key}", text, **_params_of(item))
            detail = getattr(item, "detail", None)
            action_uri = getattr(item, "action_uri", None)

            row = ctk.CTkFrame(body, fg_color=palette["row"], corner_radius=10)
            row.grid(row=index, column=0, pady=3, sticky="ew")
            row.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(
                row,
                text=self._severity_label(severity).upper(),
                text_color=self._severity_color(severity),
                font=ctk.CTkFont(size=10, weight="bold"),
                width=74,
                anchor="w",
            ).grid(row=0, column=0, rowspan=2, padx=(14, 10), pady=10, sticky="nw")
            ctk.CTkLabel(
                row,
                text=text,
                text_color=palette["text"],
                font=ctk.CTkFont(size=12),
                anchor="w",
                justify="left",
                wraplength=560,
            ).grid(row=0, column=1, padx=(0, 14), pady=(10, 0 if detail else 10), sticky="w")
            if detail:
                ctk.CTkLabel(
                    row,
                    text=str(detail),
                    text_color=palette["muted"],
                    font=ctk.CTkFont(size=11),
                    anchor="w",
                    justify="left",
                    wraplength=560,
                ).grid(row=1, column=1, padx=(0, 14), pady=(2, 10), sticky="w")

            if is_settings_uri(action_uri):
                actionable = True
                target = str(action_uri).strip()
                ctk.CTkButton(
                    row,
                    text=self.t("gui.button.open_setting", "Open setting"),
                    height=28,
                    width=132,
                    corner_radius=8,
                    fg_color="transparent",
                    border_width=1,
                    border_color=palette["border"],
                    hover_color=palette["hover"],
                    text_color=palette["text"],
                    font=ctk.CTkFont(size=11),
                    # Bound to this row's own URI, so a later row cannot change what it opens.
                    command=lambda uri=target: self.open_setting(uri),
                ).grid(row=0, column=2, rowspan=2, padx=(0, 14), pady=10, sticky="e")

        if actionable:
            # The promise the button rests on, spelled out where the button is.
            self._empty_label(
                body,
                self.t(
                    "gui.label.action_hint",
                    "Opens the matching Windows settings page. Nothing is changed for you.",
                ),
            ).grid(row=len(items), column=0, pady=(8, 0), sticky="w")

    # ------------------------------------------------------------ settings page

    def open_setting(self, uri: str) -> None:
        """
        Open one Windows settings page, and only ever because the user clicked the button.

        This is the single privileged call in the whole application. It shows a page; it
        cannot change a setting, and it is never reached from analysis or from rendering.
        The URI comes from our own advice table and is checked again anyway - see
        :func:`is_settings_uri`. Any failure becomes a message, never a traceback.
        """
        if not is_settings_uri(uri):
            # Names what was refused. It is our own string, and it is still flattened to one
            # line and truncated: the status line is a single line, and a refused value is
            # exactly the kind of value that has no business deciding how tall it is.
            self._setting_failed(_one_line(uri, 80))
            return
        # Windows only. Everywhere else the attribute is simply absent, and nothing runs.
        opener = getattr(os, "startfile", None)
        if not callable(opener):
            self._setting_failed(NA)
            return
        try:
            opener(uri.strip())
        except Exception as error:  # A missing page, a policy block, a broken association.
            self._setting_failed(str(error))
            return
        # Says what happened, and repeats what did not: the page is open, nothing changed.
        self._set_status_line(
            self.t(
                "gui.msg.setting_opened",
                "Windows opened the settings page. Nothing was changed.",
            )
        )

    def _setting_failed(self, reason: str) -> None:
        """Report a refused or failed open on the status line - never as a traceback."""
        self._set_status_line(
            self.t(
                "gui.msg.setting_failed",
                "The settings page could not be opened: {error}",
                error=reason or NA,
            )
        )

    def _render_processes(self) -> None:
        palette = self.palette
        self._clear(self.process_table)
        data = self.analysis
        if data is None or not data.top_processes:
            self._empty_label(
                self.process_table,
                self.t("gui.msg.no_processes", "No process information is available."),
            ).grid(row=0, column=0, sticky="w")
            return

        headers = (
            self.t("field.name", "Name"),
            self.t("field.pid", "PID"),
            self.t("field.memory", "Memory"),
            self.t("field.memory_percent", "Memory %"),
            self.t("field.cpu_percent", "CPU %"),
        )
        header = ctk.CTkFrame(self.process_table, fg_color="transparent")
        header.grid(row=0, column=0, pady=(0, 4), sticky="ew")
        self._process_row_widgets(header, headers, palette["faint"], bold=True)

        # The collector already ranks by memory; re-sorting here would only risk showing a
        # different order than the exported report for the same snapshot.
        for index, process in enumerate(data.top_processes, start=1):
            row = ctk.CTkFrame(
                self.process_table,
                fg_color=palette["row"] if index % 2 else palette["card_alt"],
                corner_radius=8,
            )
            row.grid(row=index, column=0, pady=2, sticky="ew")
            self._process_row_widgets(
                row,
                (
                    _display(process.name),
                    _display(process.pid),
                    format_bytes(process.memory_bytes),
                    _percent_text(process.memory_percent),
                    # CPU sampling can fail for a single process while the rest succeed, so
                    # this column is the one most likely to hold a None.
                    _percent_text(process.cpu_percent),
                ),
                palette["text"],
            )

    def _process_row_widgets(
        self, parent: Any, values: Sequence[str], color: str, *, bold: bool = False
    ) -> None:
        parent.grid_columnconfigure(0, weight=1)
        font = ctk.CTkFont(size=11, weight="bold" if bold else "normal")
        widths = (0, 70, 90, 90, 80)
        for column, value in enumerate(values):
            label = ctk.CTkLabel(
                parent,
                text=value,
                text_color=color,
                font=font,
                anchor="w" if column == 0 else "e",
            )
            if widths[column]:
                label.configure(width=widths[column])
            label.grid(
                row=0,
                column=column,
                padx=(12, 8) if column == 0 else (0, 12),
                pady=7,
                sticky="w" if column == 0 else "e",
            )

    def _render_storage(self) -> None:
        self._render_partitions()
        self._render_drive_health()
        self._render_folder_usage()

    def _render_partitions(self) -> None:
        palette = self.palette
        self._clear(self.storage_body)
        data = self.analysis
        partitions = list(data.partitions) if data is not None else []
        if data is not None and not partitions:
            partitions = [data.disk]
        if not partitions:
            self._empty_label(
                self.storage_body, self.t("gui.label.no_data", "No data yet")
            ).grid(row=0, column=0, sticky="w")
            return

        for index, partition in enumerate(partitions):
            row = ctk.CTkFrame(self.storage_body, fg_color=palette["card_alt"], corner_radius=12)
            row.grid(row=index, column=0, pady=5, sticky="ew")
            row.grid_columnconfigure(1, weight=1)

            title = _display(partition.drive)
            if partition.is_system:
                title = f"{title}  -  {self.t('gui.value.system_drive', 'System drive')}"
            ctk.CTkLabel(
                row,
                text=title,
                text_color=palette["text"],
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w",
            ).grid(row=0, column=0, padx=(16, 12), pady=(12, 2), sticky="w")
            meta = " | ".join(
                part
                for part in (
                    _display(partition.filesystem) if partition.filesystem else "",
                    _display(partition.media_type) if partition.media_type else "",
                )
                if part
            )
            ctk.CTkLabel(
                row,
                text=meta or NA,
                text_color=palette["muted"],
                font=ctk.CTkFont(size=11),
                anchor="w",
            ).grid(row=0, column=1, padx=(0, 16), pady=(12, 2), sticky="w")
            ctk.CTkLabel(
                row,
                text=format_percent(partition.usage_percent),
                text_color=self._usage_color(partition.usage_percent),
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="e",
            ).grid(row=0, column=2, padx=(0, 16), pady=(12, 2), sticky="e")

            bar = ctk.CTkProgressBar(
                row,
                height=9,
                corner_radius=6,
                fg_color=palette["track"],
                progress_color=self._usage_color(partition.usage_percent),
            )
            bar.grid(row=1, column=0, columnspan=3, padx=16, pady=(4, 4), sticky="ew")
            bar.set(_fraction(partition.usage_percent))
            ctk.CTkLabel(
                row,
                text=self.t(
                    "gui.storage.usage",
                    "{used} of {total} used, {free} free",
                    used=format_bytes(partition.used_bytes),
                    total=format_bytes(partition.total_bytes),
                    free=format_bytes(partition.free_bytes),
                ),
                text_color=palette["muted"],
                font=ctk.CTkFont(size=11),
                anchor="w",
            ).grid(row=2, column=0, columnspan=3, padx=16, pady=(0, 12), sticky="w")

    def _usage_color(self, usage_percent: float | None) -> str:
        palette = self.palette
        if usage_percent is None:
            return palette["muted"]
        if usage_percent >= 92:
            return palette["danger"]
        if usage_percent >= 80:
            return palette["warning"]
        return palette["accent"]

    def _life_color(self, life_left_percent: int | None) -> str:
        """
        Colour of a drive's remaining life.

        The thresholds mirror the wear tiers the score uses - a drive is "worn" long before
        it is "failing" - so the bar and the deduction cannot tell two different stories.
        An unknown figure is muted grey: a drive that reports no wear counter is not a
        drive in trouble.
        """
        palette = self.palette
        if life_left_percent is None:
            return palette["muted"]
        if life_left_percent <= 10:
            return palette["danger"]
        if life_left_percent <= 20:
            return palette["warning"]
        return palette["success"]

    def _render_drive_health(self) -> None:
        """Per-drive wear, showing only the figures the drive itself reported."""
        palette = self.palette
        self._clear(self.storage_health_body)
        data = self.analysis
        if data is None:
            self._empty_label(
                self.storage_health_body, self.t("gui.label.no_data", "No data yet")
            ).grid(row=0, column=0, sticky="w")
            return
        drives = [
            drive
            for drive in (getattr(data, "drive_health", ()) or ())
            if _drive_answered(drive)
        ]
        if not drives:
            # Most drives answer these queries only to the manufacturer's own tool, so an
            # empty table here is normal and is never held against the machine.
            self._empty_label(
                self.storage_health_body, self.t("report.none_detected", "None detected.")
            ).grid(row=0, column=0, sticky="w")
            return

        for index, drive in enumerate(drives):
            life_left = _as_int(getattr(drive, "life_left_percent", None))
            row = ctk.CTkFrame(
                self.storage_health_body, fg_color=palette["card_alt"], corner_radius=12
            )
            row.grid(row=index, column=0, pady=5, sticky="ew")
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(
                row,
                text=_display(getattr(drive, "drive", None)),
                text_color=palette["text"],
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="w",
            ).grid(row=0, column=0, padx=(16, 12), pady=(12, 2), sticky="w")
            meta = " | ".join(
                str(part).strip()
                for part in (
                    getattr(drive, "model", None),
                    getattr(drive, "bus_type", None),
                    getattr(drive, "media_type", None),
                    getattr(drive, "source", None),
                )
                if part
            )
            ctk.CTkLabel(
                row,
                text=meta or NA,
                text_color=palette["muted"],
                font=ctk.CTkFont(size=11),
                anchor="w",
                justify="left",
                wraplength=420,
            ).grid(row=0, column=1, padx=(0, 16), pady=(12, 2), sticky="w")
            ctk.CTkLabel(
                row,
                text=(
                    "{label}: {value}".format(
                        label=self.t("field.life_left", "Life Left"),
                        value=format_percent(life_left) if life_left is not None else NA,
                    )
                ),
                text_color=self._life_color(life_left),
                font=ctk.CTkFont(size=13, weight="bold"),
                anchor="e",
            ).grid(row=0, column=2, padx=(0, 16), pady=(12, 2), sticky="e")

            bar = ctk.CTkProgressBar(
                row,
                height=9,
                corner_radius=6,
                fg_color=palette["track"],
                # A drive that reports no wear counter shows an empty track, not a full bar:
                # a guessed 100% would be an invented measurement.
                progress_color=(
                    self._life_color(life_left) if life_left is not None else palette["track"]
                ),
            )
            bar.grid(row=1, column=0, columnspan=3, padx=16, pady=(4, 4), sticky="ew")
            bar.set(_fraction(life_left))

            figures = " | ".join(
                "{label}: {value}".format(label=label, value=value)
                for label, value in (
                    (
                        self.t("field.temperature", "Temperature"),
                        self._celsius(getattr(drive, "temperature_celsius", None)),
                    ),
                    (
                        self.t("field.power_on_hours", "Power-on Hours"),
                        self._hours(getattr(drive, "power_on_hours", None)),
                    ),
                    (
                        self.t("field.data_written", "Data Written"),
                        format_bytes(getattr(drive, "data_written_bytes", None)),
                    ),
                )
            )
            ctk.CTkLabel(
                row,
                text=figures,
                text_color=palette["muted"],
                font=ctk.CTkFont(size=11),
                anchor="w",
                justify="left",
                wraplength=740,
            ).grid(row=2, column=0, columnspan=3, padx=16, pady=(0, 12), sticky="w")

            if getattr(drive, "critical_warning", None):
                ctk.CTkLabel(
                    row,
                    text="{label}: {value}".format(
                        label=self.t("field.critical_warning", "Critical Warning"),
                        value=self.t("field.yes", "Yes"),
                    ),
                    text_color=palette["danger"],
                    font=ctk.CTkFont(size=11, weight="bold"),
                    anchor="w",
                    justify="left",
                    wraplength=740,
                ).grid(row=3, column=0, columnspan=3, padx=16, pady=(0, 12), sticky="w")

    def _render_folder_usage(self) -> None:
        """
        The measured folders, biggest first.

        Sorted here rather than trusted from the snapshot, and by exactly the rule the text
        report sorts by - an unmeasured folder sorts last, because "unknown" is not "small" -
        so the table on screen and the table in an exported report list the same snapshot in
        the same order.
        """
        palette = self.palette
        self._clear(self.storage_folders_body)
        data = self.analysis
        if data is None:
            self._empty_label(
                self.storage_folders_body, self.t("gui.label.no_data", "No data yet")
            ).grid(row=0, column=0, sticky="w")
            return
        folders = list(getattr(data, "folder_usage", ()) or ())
        folders.sort(key=lambda item: _size_key(getattr(item, "size_bytes", None)), reverse=True)
        if not folders:
            self._empty_label(
                self.storage_folders_body, self.t("report.none_detected", "None detected.")
            ).grid(row=0, column=0, sticky="w")
            return

        for index, folder in enumerate(folders):
            row = ctk.CTkFrame(
                self.storage_folders_body,
                fg_color=palette["row"] if index % 2 else palette["card_alt"],
                corner_radius=10,
            )
            row.grid(row=index, column=0, pady=3, sticky="ew")
            row.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                row,
                text=_display(getattr(folder, "label", None)),
                text_color=palette["text"],
                font=ctk.CTkFont(size=12, weight="bold"),
                anchor="w",
            ).grid(row=0, column=0, padx=(14, 10), pady=(10, 0), sticky="w")
            # A folder whose scan ran out of time reports a lower bound, and says so - the
            # same wording the text report uses, so the two can never read differently.
            size = format_bytes(getattr(folder, "size_bytes", None))
            if getattr(folder, "truncated", False):
                size = f"{size} ({self.t('report.partial_scan', 'partial scan')})"
            ctk.CTkLabel(
                row,
                text=size,
                text_color=palette["text"],
                font=ctk.CTkFont(size=12, weight="bold"),
                anchor="e",
            ).grid(row=0, column=1, padx=(0, 14), pady=(10, 0), sticky="e")
            ctk.CTkLabel(
                row,
                text="{path}  -  {files}: {count}".format(
                    path=_display(getattr(folder, "path", None)),
                    files=self.t("field.files", "Files"),
                    count=format_count(_as_int(getattr(folder, "file_count", None))),
                ),
                text_color=palette["muted"],
                font=ctk.CTkFont(size=11),
                anchor="w",
                justify="left",
                wraplength=700,
            ).grid(row=1, column=0, columnspan=2, padx=14, pady=(2, 10), sticky="w")

    def _security_row(
        self,
        parent: Any,
        index: int,
        label: str,
        value: str = "",
        state: str | None = None,
    ) -> None:
        """
        One protection line: what it is, what was read, and the verdict as a pill.

        ``state`` is None for a row that is a fact rather than a verdict - the date of the
        last scan is not good or bad news, and colouring it would invent an opinion the
        analyser does not hold.
        """
        palette = self.palette
        row = ctk.CTkFrame(parent, fg_color=palette["row"], corner_radius=10)
        row.grid(row=index, column=0, pady=3, sticky="ew")
        row.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            row,
            text=label,
            text_color=palette["muted"],
            font=ctk.CTkFont(size=12),
            width=170,
            anchor="w",
        ).grid(row=0, column=0, padx=(14, 10), pady=10, sticky="w")
        if value:
            ctk.CTkLabel(
                row,
                text=value,
                text_color=palette["muted"] if value == NA else palette["text"],
                font=ctk.CTkFont(size=12, weight="bold"),
                anchor="w",
                justify="left",
                wraplength=420,
            ).grid(row=0, column=1, padx=(0, 10), pady=10, sticky="w")
        if state is not None:
            ctk.CTkLabel(
                row,
                text=f"  {self._state_label(state)}  ",
                height=24,
                corner_radius=12,
                fg_color=self._state_pill_color(state),
                text_color=self._state_color(state),
                font=ctk.CTkFont(size=11, weight="bold"),
            ).grid(row=0, column=2, padx=(0, 14), pady=10, sticky="e")

    def _render_security(self) -> None:
        self._clear(self.security_rows)
        data = self.analysis
        security = getattr(data, "security", None) if data is not None else None
        assessment = self.assessment

        deductions = tuple(
            item
            for item in (assessment.deductions if assessment is not None else ())
            if str(getattr(item, "category", "")) == CATEGORY_SECURITY
        )

        if security is None:
            self._empty_label(
                self.security_rows, self.t("gui.label.no_data", "No data yet")
            ).grid(row=0, column=0, sticky="w")
        else:
            details = dict(_detail_pairs(getattr(security, "details", ())))
            yes = self.t("field.yes", "Yes")
            no = self.t("field.no", "No")

            reboot_pending = getattr(security, "reboot_pending", None)
            if reboot_pending is None:
                reboot_value, reboot_state = NA, STATE_UNKNOWN
            elif reboot_pending:
                # A pending restart is something to finish, not something broken.
                reboot_value, reboot_state = yes, STATE_WEAK
            else:
                reboot_value, reboot_state = no, STATE_GOOD
            # Which update asked for the restart is the part a reader can act on.
            reboot_source = details.get(SECURITY_DETAIL_REBOOT, "")
            if reboot_pending and reboot_source:
                reboot_value = f"{reboot_value}  -  {reboot_source}"

            signature_age = _as_int(getattr(security, "signature_age_days", None))
            if signature_age is None:
                signature_state = STATE_UNKNOWN
            elif any(getattr(item, "key", "") == "stale_signatures" for item in deductions):
                # The verdict comes from the rule that scored it, so the pill and the
                # deduction below it can never disagree about what counts as stale.
                signature_state = STATE_WEAK
            else:
                signature_state = STATE_GOOD

            self._security_row(
                self.security_rows,
                0,
                self.t("field.antivirus", "Antivirus"),
                # The product name needs COM/WMI and is often simply not readable; the pill
                # still carries the verdict, so an N/A here says only "name unknown".
                _display(getattr(security, "antivirus_name", None)),
                str(getattr(security, "antivirus", STATE_UNKNOWN)),
            )
            self._security_row(
                self.security_rows,
                1,
                self.t("field.firewall", "Firewall"),
                details.get(SECURITY_DETAIL_FIREWALL, ""),
                str(getattr(security, "firewall", STATE_UNKNOWN)),
            )
            self._security_row(
                self.security_rows,
                2,
                self.t("field.secure_boot", "Secure Boot"),
                "",
                str(getattr(security, "secure_boot", STATE_UNKNOWN)),
            )
            self._security_row(
                self.security_rows,
                3,
                self.t("field.reboot_pending", "Restart Pending"),
                reboot_value,
                reboot_state,
            )
            self._security_row(
                self.security_rows,
                4,
                self.t("field.signature_age", "Definitions Age"),
                self._days(signature_age),
                signature_state,
            )
            # The date of the last scan is a fact, not a verdict, so it carries no pill: this
            # app has no rule about how recent a scan should be, and inventing one here would
            # put an opinion on screen that the score does not hold.
            self._security_row(
                self.security_rows,
                5,
                self.t("field.last_scan", "Last Scan"),
                _datetime_text(getattr(security, "defender_last_scan", None)),
            )
            if SECURITY_DETAIL_CENTER in details:
                # Names the reason for the unknowns above: "nobody answered" and "the answer
                # was no" are not the same news, and only one of them is a problem.
                self._empty_label(
                    self.security_rows,
                    self.t(
                        "report.security_center_down",
                        "The Windows Security Center did not answer, so the antivirus and "
                        "firewall states are unknown rather than off.",
                    ),
                ).grid(row=6, column=0, pady=(8, 0), sticky="w")

        self._fill_deductions(
            self.security_deductions_body,
            deductions,
            self.t("gui.msg.no_deductions", "No points were deducted.")
            if assessment is not None
            else self.t("gui.label.no_data", "No data yet"),
        )
        self._fill_recommendations(
            self.security_recommendations_body,
            [
                item
                for item in self.recommendations
                if str(getattr(item, "category", "")) == CATEGORY_SECURITY
            ],
            self.t("gui.msg.no_recommendations", "No recommendations for this snapshot."),
        )

    def _render_system(self) -> None:
        palette = self.palette
        for body in (
            self.system_os_body,
            self.system_firmware_body,
            self.system_gpu_body,
            self.system_startup_body,
            self.system_warnings_body,
        ):
            self._clear(body)

        data = self.analysis
        if data is None:
            self._empty_label(
                self.system_os_body, self.t("gui.label.no_data", "No data yet")
            ).grid(row=0, column=0, sticky="w")
            return

        system = data.system
        os_rows = (
            (self.t("field.os", "System"), _display(system.os_name)),
            (self.t("field.edition", "Edition"), _display(system.edition)),
            (
                self.t("field.display_version", "Windows Version"),
                _display(system.display_version),
            ),
            (self.t("field.build", "Build"), _display(system.build)),
            (self.t("field.version", "Version"), _display(system.version)),
            (self.t("field.architecture", "Architecture"), _display(system.architecture)),
            (self.t("field.processor", "Processor"), _display(system.processor)),
            (
                self.t("field.max_frequency", "Max Frequency"),
                format_frequency(data.cpu.max_frequency_mhz),
            ),
            (
                self.t("field.install_date", "Windows Installed"),
                _datetime_text(system.install_date),
            ),
            (self.t("field.boot_time", "Last Boot"), _datetime_text(system.boot_time)),
        )
        for index, (label, value) in enumerate(os_rows):
            self._kv_row(self.system_os_body, index, label, value)

        firmware_rows = (
            (self.t("field.manufacturer", "Manufacturer"), _display(system.manufacturer)),
            (self.t("field.model", "Model"), _display(system.model)),
            (self.t("field.bios", "BIOS Version"), _display(system.bios_version)),
        )
        for index, (label, value) in enumerate(firmware_rows):
            self._kv_row(self.system_firmware_body, index, label, value)

        if not data.gpus:
            self._empty_label(
                self.system_gpu_body,
                self.t("gui.system.no_gpus", "No graphics adapters were reported."),
            ).grid(row=0, column=0, sticky="w")
        else:
            for index, gpu in enumerate(data.gpus):
                detail = " | ".join(
                    part
                    for part in (
                        _display(gpu.driver_version) if gpu.driver_version else "",
                        _display(gpu.driver_date) if gpu.driver_date else "",
                        format_bytes(gpu.memory_bytes) if gpu.memory_bytes else "",
                    )
                    if part
                )
                self._kv_row(self.system_gpu_body, index, _display(gpu.name), detail or NA)

        if not data.startup_items:
            self._empty_label(
                self.system_startup_body,
                self.t("gui.system.no_startup", "No startup items were found."),
            ).grid(row=0, column=0, sticky="w")
        else:
            for index, item in enumerate(data.startup_items):
                self._kv_row(
                    self.system_startup_body, index, _display(item.name), _display(item.source)
                )

        if not data.warnings:
            self._empty_label(
                self.system_warnings_body,
                self.t("gui.system.no_warnings", "No warnings. Every metric was collected."),
            ).grid(row=0, column=0, sticky="w")
        else:
            for index, warning in enumerate(data.warnings):
                ctk.CTkLabel(
                    self.system_warnings_body,
                    text=f"- {warning}",
                    text_color=palette["warning"],
                    font=ctk.CTkFont(size=12),
                    anchor="w",
                    justify="left",
                    wraplength=740,
                ).grid(row=index, column=0, pady=3, sticky="w")

    def _history_path_text(self) -> str:
        if _history is None:
            return self.t(
                "gui.history.unavailable",
                "The history module is not available in this installation.",
            )
        try:
            return str(_history.default_history_path())
        except Exception:
            return NA

    def _render_history(self) -> None:
        palette = self.palette
        self._clear(self.history_rows)
        self.history_path_label.configure(text=self._history_path_text())
        self.history_status_label.configure(
            text=self.history_note or "", text_color=palette["muted"]
        )

        if _history is None:
            self._set_chart_scores(())
            self._empty_label(
                self.history_rows,
                self.t(
                    "gui.history.unavailable",
                    "The history module is not available in this installation.",
                ),
            ).grid(row=0, column=0, sticky="w")
            return

        try:
            entries = list(_history.load_history())
        except Exception:  # load_history never raises, but a broken build must not crash the UI.
            entries = []

        # Oldest first, which is the order the store keeps and the order the chart draws.
        self._set_chart_scores(
            tuple(
                score
                for score in (_as_int(getattr(entry, "score", None)) for entry in entries)
                if score is not None
            )
        )

        if not entries:
            self._empty_label(
                self.history_rows,
                self.t("gui.msg.no_history", "No previous analysis is stored yet."),
            ).grid(row=0, column=0, sticky="w")
            return

        for position, index in enumerate(range(len(entries) - 1, -1, -1)):
            entry = entries[index]
            previous = entries[index - 1] if index > 0 else None
            row = ctk.CTkFrame(self.history_rows, fg_color=palette["row"], corner_radius=10)
            row.grid(row=position, column=0, pady=3, sticky="ew")
            row.grid_columnconfigure(1, weight=1)

            ctk.CTkLabel(
                row,
                text=_datetime_text(getattr(entry, "analyzed_at", None)),
                text_color=palette["muted"],
                font=ctk.CTkFont(size=11),
                width=130,
                anchor="w",
            ).grid(row=0, column=0, padx=(14, 10), pady=9, sticky="w")
            score = getattr(entry, "score", None)
            ctk.CTkLabel(
                row,
                text=self.t("gui.history.score", "Score {score}", score=_display(score)),
                text_color=self._score_color(score if isinstance(score, int) else None),
                font=ctk.CTkFont(size=12, weight="bold"),
                anchor="w",
            ).grid(row=0, column=1, padx=(0, 10), pady=9, sticky="w")

            if previous is None or not isinstance(score, int):
                delta_text = self.t("gui.history.first", "First saved run")
                delta_color = palette["faint"]
            else:
                delta = score - int(getattr(previous, "score", score))
                delta_text = self.t(
                    "gui.history.delta", "{delta} vs previous", delta=f"{delta:+d}"
                )
                if delta > 0:
                    delta_color = palette["success"]
                elif delta < 0:
                    delta_color = palette["danger"]
                else:
                    delta_color = palette["faint"]
            ctk.CTkLabel(
                row,
                text=delta_text,
                text_color=delta_color,
                font=ctk.CTkFont(size=11, weight="bold"),
                anchor="e",
            ).grid(row=0, column=2, padx=(0, 14), pady=9, sticky="e")

    # ----------------------------------------------------------- history chart

    def _set_chart_scores(self, scores: Sequence[int]) -> None:
        """Hand the chart its data and redraw it, on the Tk thread like every other render."""
        self._chart_scores = tuple(scores)
        self._draw_history_chart()

    def _on_chart_resize(self, event: Any = None) -> None:
        """
        Redraw after a resize, once, when the size really changed.

        Tk sends a ``<Configure>`` for every pixel of a window drag; coalescing them into one
        delayed redraw is what keeps dragging the window smooth.
        """
        size = (int(getattr(event, "width", 0) or 0), int(getattr(event, "height", 0) or 0))
        if size == self._chart_size:
            return
        self._chart_size = size
        self._cancel_job("_chart_job")
        try:
            self._chart_job = self.after(60, self._chart_redraw)
        except Exception:  # No interpreter to schedule on: draw now or not at all.
            self._draw_history_chart()

    def _chart_redraw(self) -> None:
        self._chart_job = None
        self._draw_history_chart()

    def _draw_history_chart(self) -> None:
        """
        Draw the score-over-time chart.

        Every item is created fresh after a ``delete("all")``, so repeated redraws - resize,
        theme switch, language switch - cannot pile items up on the canvas.
        """
        canvas = getattr(self, "history_canvas", None)
        if canvas is None:
            return
        try:
            if not canvas.winfo_exists():
                return
            canvas.delete("all")
            canvas.configure(background=self.palette["card_alt"])
            width = int(canvas.winfo_width())
            height = int(canvas.winfo_height())
        except Exception:  # A canvas mid-teardown is not worth an exception.
            return

        # Before the first layout pass Tk reports 1x1; the <Configure> binding redraws.
        if width <= 1:
            width = CHART_FALLBACK_WIDTH
        if height <= 1:
            height = CHART_HEIGHT

        palette = self.palette
        scores = [max(0, min(100, value)) for value in self._chart_scores]
        if not scores:
            canvas.create_text(
                width // 2,
                height // 2,
                text=self.t(
                    "gui.label.history_empty",
                    "Save a few analyses and the trend shows up here.",
                ),
                fill=palette["muted"],
                font=(CHART_FONT, 10),
            )
            return

        left, right, top, bottom = CHART_MARGINS
        plot_width = width - left - right
        plot_height = height - top - bottom
        if plot_width < 60 or plot_height < 40:
            return  # Too small to read; an unreadable chart is worse than none.

        def y_of(score: float) -> float:
            return top + plot_height * (1.0 - score / 100.0)

        def x_of(index: int) -> float:
            if len(scores) == 1:
                return left + plot_width / 2.0
            return left + plot_width * index / (len(scores) - 1)

        # The score bands, in the same muted fills the status pills use, so they read as a
        # background rather than competing with the line.
        for low, high, colour in (
            (75, 100, palette["pill_ok"]),
            (50, 75, palette["pill_warn"]),
            (0, 50, palette["pill_bad"]),
        ):
            canvas.create_rectangle(
                left, y_of(high), left + plot_width, y_of(low), fill=colour, outline=""
            )
        for score in (0, 50, 75, 100):
            y = y_of(score)
            canvas.create_line(left, y, left + plot_width, y, fill=palette["border"])
            canvas.create_text(
                left - 6,
                y,
                text=str(score),
                anchor="e",
                fill=palette["faint"],
                font=(CHART_FONT, 9),
            )

        points = [(x_of(index), y_of(score)) for index, score in enumerate(scores)]
        if len(points) > 1:
            flat: list[float] = [value for point in points for value in point]
            canvas.create_line(*flat, fill=palette["accent"], width=2)
        for x, y in points:
            canvas.create_oval(
                x - 3, y - 3, x + 3, y + 3, fill=palette["accent"], outline=palette["card_alt"]
            )

        self._draw_chart_run_labels(canvas, points, plot_width, top + plot_height)
        self._draw_chart_value_labels(canvas, scores, points, left, plot_width, top, plot_height)

    def _draw_chart_run_labels(
        self, canvas: Any, points: Sequence[tuple[float, float]], plot_width: float, baseline: float
    ) -> None:
        """Number the runs along the bottom, dropping labels rather than overlapping them."""
        palette = self.palette
        room = max(1, int(plot_width // CHART_LABEL_SPACING))
        step = max(1, -(-len(points) // room))  # ceil division: how many runs one label covers
        for index in range(0, len(points), step):
            canvas.create_text(
                points[index][0],
                baseline + 12,
                text=str(index + 1),
                fill=palette["faint"],
                font=(CHART_FONT, 9),
            )

    def _draw_chart_value_labels(
        self,
        canvas: Any,
        scores: Sequence[int],
        points: Sequence[tuple[float, float]],
        left: float,
        plot_width: float,
        top: float,
        plot_height: float,
    ) -> None:
        """
        Put the score on the newest, the highest and the lowest run.

        The number itself is the label: which point is which is already obvious from where it
        sits - newest on the right, highest at the top, lowest at the bottom - and a bare
        number reads the same in every language. The newest is claimed first, so when one
        point is two of the three (a single run, or a last run that is also the best) the
        label that matters survives and the other is dropped instead of drawn on top of it.
        """
        palette = self.palette
        last = len(scores) - 1
        highest = max(range(len(scores)), key=lambda index: scores[index])
        lowest = min(range(len(scores)), key=lambda index: scores[index])
        wanted = (
            (last, -1, palette["accent"]),
            (highest, -1, palette["muted"]),
            (lowest, 1, palette["muted"]),
        )

        taken: set[int] = set()
        for index, direction, colour in wanted:
            if index in taken:
                continue
            taken.add(index)
            x, y = points[index]
            offset = -11 if direction < 0 else 13
            y = max(top + 7, min(top + plot_height - 6, y + offset))
            if x < left + 20:
                anchor = "w"
            elif x > left + plot_width - 20:
                anchor = "e"
            else:
                anchor = "center"
            canvas.create_text(
                x,
                y,
                text=str(scores[index]),
                anchor=anchor,
                fill=colour,
                font=(CHART_FONT, 9, "bold"),
            )

    # ---------------------------------------------------------------- running

    def _set_pill(self, text: str, background: str, foreground: str) -> None:
        self.state_pill.configure(text=f"  {text}  ", fg_color=background, text_color=foreground)

    def _apply_run_state(self) -> None:
        palette = self.palette
        if self._running:
            self.analyze_button.configure(
                state="disabled", text=self.t("gui.button.analyzing", "Analyzing...")
            )
            self.export_button.configure(state="disabled")
            self.copy_button.configure(state="disabled")
            self._set_pill(
                self.t("gui.state.running", "Analysis in progress..."),
                palette["pill_warn"],
                palette["warning"],
            )
            return

        has_data = self.analysis is not None
        self.analyze_button.configure(
            state="normal",
            text=(
                self.t("gui.button.again", "Analyze again")
                if has_data
                else self.t("gui.button.analyze", "Analyze my PC")
            ),
        )
        state = "normal" if has_data else "disabled"
        self.export_button.configure(state=state)
        self.copy_button.configure(state=state)
        if has_data:
            self._set_pill(
                self.t("gui.state.complete", "Analysis complete"),
                palette["pill_ok"],
                palette["success"],
            )
        else:
            self._set_pill(
                self.t("gui.state.ready", "Ready"), palette["pill_ok"], palette["success"]
            )

    @staticmethod
    def _progress_step_default(step_key: str) -> str:
        """
        The English label the collector publishes for one step key.

        ``analyze_pc`` reports a stable key, not a sentence, so the wording can follow the
        chosen language. The table is read lazily: a collector without it, or a key from a
        newer collector than this window, still yields readable text instead of nothing.
        """
        labels = getattr(_analyzer, "PROGRESS_LABELS", None)
        if isinstance(labels, dict):
            return str(labels.get(step_key, step_key))
        return step_key

    def _progress_line(self) -> str:
        """The caption under the progress bar, translated on every render and rebuild."""
        if self._progress_key is None:
            return self.t("gui.state.ready", "Ready")
        key, default = self._progress_key
        return self.t(key, default)

    def _set_progress(self, key: str, default: str, fraction: float) -> None:
        """Show a progress caption by key, always on the Tk thread."""
        self._progress_key = (key, default)
        self._progress_value = fraction
        self.progress_bar.set(fraction)
        self.progress_label.configure(text=self._progress_line())

    def _set_progress_step(self, step_key: str, fraction: float) -> None:
        """Show one collector step; the worker only queued the key, the wording happens here."""
        self._set_progress(
            f"progress.{step_key}", self._progress_step_default(step_key), fraction
        )

    def start_analysis(self) -> None:
        if self._running:
            return
        self._running = True
        self.save_history = self._read_history_choice()
        self.history_note = None
        self._apply_run_state()
        self.subtitle_label.configure(
            text=self.t("gui.state.running", "Analysis in progress...")
        )
        self._set_progress("gui.progress.starting", "Starting analysis...", 0.02)

        save_history = self.save_history and _history is not None
        thread = threading.Thread(
            target=self._analysis_worker, args=(save_history,), daemon=True
        )
        thread.start()
        self._poll_job = self.after(80, self._poll_analysis)

    def _progress_bridge(self, step_key: str, fraction: float) -> None:
        """
        The ``analyze_pc`` progress callback: ``(step_key, fraction)``.

        Runs on the worker thread, so it may only queue the bare key - never touch a widget,
        and never translate, because the translator is only used from the Tk thread.
        """
        try:
            value = max(0.0, min(1.0, float(fraction)))
        except (TypeError, ValueError):
            value = 0.0
        self._result_queue.put(("progress", str(step_key), value))

    def _analysis_worker(self, save_history: bool) -> None:
        try:
            data = self._run_analysis(self._progress_bridge)
            assessment = calculate_health_details(data)
            recommendations = list(generate_recommendations(data))
        except Exception as error:  # Any collector failure is reported, never raised at Tk.
            self._result_queue.put(("error", str(error)))
            return

        note: str | None = None
        if save_history and _history is not None:
            try:
                saved_to = _history.append_snapshot(data, assessment)
                note = self.t("gui.history.saved", "Saved to {path}", path=str(saved_to))
            except Exception as error:
                note = self.t(
                    "gui.history.failed", "This run could not be saved: {error}", error=str(error)
                )
        self._result_queue.put(("success", data, assessment, recommendations, note))

    def _run_analysis(self, progress: Callable[[str, float], None]) -> AnalysisData:
        """
        Call ``analyze_pc`` with only the keywords this build of the collector accepts.

        ``progress`` is the collector's ``(step_key, fraction)`` callback and runs on this
        worker thread.
        """
        options: dict[str, Any] = {
            "cpu_interval": 1.0,
            "progress": progress,
            "scan_temp": True,
            "include_startup": True,
            "include_gpu": True,
            # v2.1 state collectors. Filtered out below on a collector that predates them,
            # which is why asking for all of them here is safe.
            "include_security": True,
            "include_drive_health": True,
            "scan_folders": True,
        }
        try:
            accepted = inspect.signature(analyze_pc).parameters
        except (TypeError, ValueError):
            accepted = {}
        if accepted:
            options = {name: value for name, value in options.items() if name in accepted}
        return analyze_pc(**options)

    def _poll_analysis(self) -> None:
        """Consume worker output on Tk's main thread; no widget is ever touched off-thread."""
        self._poll_job = None
        while True:
            try:
                result = self._result_queue.get_nowait()
            except Empty:
                break
            kind = result[0]
            if kind == "progress":
                self._set_progress_step(str(result[1]), float(result[2]))
                continue
            if kind == "error":
                self._analysis_failed(str(result[1]))
                return
            if kind == "success":
                self._display_analysis(result[1], result[2], list(result[3]), result[4])
                return
        if self._running:
            self._poll_job = self.after(80, self._poll_analysis)

    def destroy(self) -> None:
        """Drop our own pending callbacks first: a queued one outlives the widgets it uses."""
        self._running = False
        self._cancel_job("_poll_job")
        self._cancel_job("_copy_job")
        self._cancel_job("_chart_job")
        super().destroy()

    def _cancel_job(self, attribute: str) -> None:
        """Cancel one of our own ``after()`` jobs, if it is still scheduled."""
        job = getattr(self, attribute, None)
        setattr(self, attribute, None)
        if job is None:
            return
        try:
            self.after_cancel(job)
        except Exception:  # Tk may already be tearing the interpreter down.
            pass

    def _analysis_failed(self, error: str) -> None:
        palette = self.palette
        self._running = False
        self._apply_run_state()
        failed = self.t("gui.state.failed", "Analysis failed")
        self._set_pill(failed, palette["pill_bad"], palette["danger"])
        message = self.t(
            "gui.msg.analysis_failed", "The analysis could not finish: {error}", error=error
        )
        self.subtitle_label.configure(text=message)
        self._set_progress("gui.state.failed", "Analysis failed", 0.0)
        messagebox.showerror(failed, message, parent=self)

    def _display_analysis(
        self,
        data: AnalysisData,
        assessment: HealthAssessment,
        recommendations: list[Any],
        history_note: str | None,
    ) -> None:
        self.analysis = data
        self.assessment = assessment
        self.recommendations = recommendations
        self.history_note = history_note
        self._running = False

        self._set_progress("gui.state.complete", "Analysis complete", 1.0)
        self._render_all()
        self._apply_run_state()

    # ----------------------------------------------------------------- output

    def _output_options(self, redact: bool) -> dict[str, Any]:
        """
        Keyword arguments shared by every writer.

        ``redact`` is only passed when it is switched on, so a v1.0 module without the keyword
        still works with redaction off and fails loudly - instead of quietly writing the
        account name - when the user asked for it.
        """
        options: dict[str, Any] = {"translator": self.translator}
        if redact:
            options["redact"] = True
        return options

    def _redaction_unavailable(self) -> RuntimeError:
        """Error shown when a writer cannot honour redaction, so nothing leaks by accident."""
        return RuntimeError(
            self.t(
                "gui.msg.redact_unavailable",
                "This installation cannot mask personal data. Untick '{label}' to continue.",
                label=self.t("gui.label.redact", "Redact personal data"),
            )
        )

    def _text_report(self, *, redact: bool = False) -> str:
        """Build the plain-text report, tolerating the v1.0 three-argument signature."""
        try:
            return build_report(
                self.analysis,
                self.recommendations,
                self.assessment,
                **self._output_options(redact),
            )
        except TypeError as error:
            if redact:  # Falling back here would hand back an unredacted report.
                raise self._redaction_unavailable() from error
            return build_report(self.analysis, self.recommendations, self.assessment)

    def copy_report_to_clipboard(self) -> None:
        if self.analysis is None or self.assessment is None:
            return
        try:
            text = self._text_report(redact=self._read_redact_choice())
            self.clipboard_clear()
            self.clipboard_append(text)
            self.update_idletasks()
        except Exception as error:
            messagebox.showerror(
                self.t("gui.dialog.copy_failed", "Copy failed"), str(error), parent=self
            )
            return

        original = self.t("gui.button.copy", "Copy to clipboard")
        self.copy_button.configure(text=self.t("gui.button.copied", "Copied"))
        # The button has room for one word, so the sentence that says what actually happened
        # goes on the status line; the reset below hands that line back to the analysis.
        self._set_status_line(self.t("gui.msg.copied", "The report was copied to the clipboard."))
        # Replace any reset still in flight from a previous click, and keep the id so that
        # closing the window inside the 1.8 s window does not leave a callback behind.
        self._cancel_job("_copy_job")
        self._copy_job = self.after(1800, lambda: self._restore_copy_button(original))

    def _set_status_line(self, text: str) -> None:
        """Put a transient message on the subtitle line; ``_render_subtitle`` takes it back."""
        label = getattr(self, "subtitle_label", None)
        try:
            if label is not None and label.winfo_exists():
                label.configure(text=text)
        except Exception:  # A missing or rebuilt label must not break the copy itself.
            pass

    def _restore_copy_button(self, text: str) -> None:
        self._copy_job = None
        button = getattr(self, "copy_button", None)
        try:
            if button is not None and button.winfo_exists():
                button.configure(text=text)
        except Exception:  # The button may have been rebuilt by a theme or language switch.
            pass
        try:  # The confirmation was transient: the line belongs to the analysis summary.
            self._render_subtitle()
        except Exception:
            pass

    def _format_spec(self, fmt: str) -> tuple[str, str, str, str]:
        for spec in FORMAT_SPECS:
            if spec[0] == fmt:
                return spec
        return FORMAT_SPECS[0]

    def _suggested_filename(self, fmt: str, extension: str) -> str:
        if _exporters is not None:
            try:
                return str(_exporters.default_filename(fmt))
            except Exception:
                pass
        return f"apoliak_vitals_report_{datetime.now():%Y%m%d_%H%M%S}{extension}"

    def export_current_report(self) -> None:
        if self.analysis is None or self.assessment is None:
            messagebox.showinfo(
                self.t("gui.dialog.export_title", "Save the report"),
                self.t("gui.label.no_data", "No data yet"),
                parent=self,
            )
            return

        fmt, extension, _label, dialog_default = self._format_spec(self.export_format)
        if _exporters is None and fmt != "text":
            messagebox.showerror(
                self.t("gui.dialog.export_failed", "Export failed"),
                self.t(
                    "gui.dialog.format_unavailable",
                    "This export format is not available in this installation.",
                ),
                parent=self,
            )
            return

        if _exporters is not None:
            try:
                # extension_for() answers "txt"; every Tk argument below wants ".txt".
                suffix = str(_exporters.extension_for(fmt)).lstrip(".")
                extension = f".{suffix}" if suffix else extension
            except Exception:
                pass

        path = filedialog.asksaveasfilename(
            parent=self,
            title=self.t("gui.dialog.export_title", "Save the report"),
            initialfile=self._suggested_filename(fmt, extension),
            defaultextension=extension,
            filetypes=(
                (self.t(f"gui.filetype.{fmt}", dialog_default), f"*{extension}"),
                (self.t("gui.filetype.all", "All files"), "*.*"),
            ),
        )
        if not path:
            return

        redact = self._read_redact_choice()
        try:
            if _exporters is not None:
                destination = _exporters.export(
                    fmt,
                    self.analysis,
                    self.recommendations,
                    self.assessment,
                    Path(path),
                    **self._output_options(redact),
                )
            else:
                destination = export_report(
                    self.analysis,
                    self.recommendations,
                    self.assessment,
                    Path(path),
                    **self._output_options(redact),
                )
        except Exception as error:
            # A writer too old for the redact keyword raises TypeError. Nothing was written
            # in either case, so the account name cannot leak; only the wording improves.
            if redact and isinstance(error, TypeError):
                error = self._redaction_unavailable()
            messagebox.showerror(
                self.t("gui.dialog.export_failed", "Export failed"),
                self.t(
                    "gui.msg.export_failed",
                    "The report could not be saved: {error}",
                    error=str(error),
                ),
                parent=self,
            )
            return

        messagebox.showinfo(
            self.t("gui.dialog.exported", "Report exported"),
            self.t("gui.msg.export_ok", "Report saved to {path}", path=str(destination)),
            parent=self,
        )


def main() -> None:
    try:
        ctk.set_default_color_theme("blue")
    except Exception:  # A missing theme file must not stop the app from opening.
        pass
    app = ApoliakAnalyzerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
