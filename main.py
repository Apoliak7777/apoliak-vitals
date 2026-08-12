"""Console entry point for Apoliak Vitals."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

from src import __version__, exporters, history
from src.analyzer import PROGRESS_LABELS, MissingDependencyError, analyze_pc
from src.health_score import calculate_health_details
from src.i18n import Translator, available_languages, detect_language, get_translator
from src.models import HealthAssessment
from src.recommendations import generate_recommendations
from src.report import build_report
from src.utils import (
    DEFAULT_SCAN_SECONDS,
    Ansi,
    format_bytes,
    format_percent,
    redact_text,
    supports_color,
)

APP_VERSION = __version__

#: Marker left by a bare ``--export`` flag; the real filename is generated at export time.
AUTO_EXPORT = ""

COLOR_MODES = ("auto", "always", "never")

#: Answers accepted for the interactive export question, in English and Slovak.
_YES_ANSWERS = frozenset({"y", "yes", "a", "ano", "áno"})


def _requested_language(argv: Sequence[str] | None = None) -> str | None:
    """
    Language asked for on the command line, or None when it is absent or not shipped.

    argparse cannot answer this question: it prints the help text the parser was built with,
    so the language has to be known before the parser exists. The scan is deliberately
    forgiving - an unsupported value is ignored here and left to argparse, which rejects it
    with its own message and exit code 2.
    """
    values = [str(item) for item in (sys.argv[1:] if argv is None else argv)]
    chosen: str | None = None
    for index, item in enumerate(values):
        if item == "--lang" and index + 1 < len(values):
            candidate = values[index + 1]
        elif item.startswith("--lang="):
            candidate = item.partition("=")[2]
        else:
            continue
        code = candidate.strip().casefold()
        if code in available_languages():
            chosen = code  # A repeated flag keeps the last value, exactly like argparse.
    return chosen


def build_parser(language: str | None = None) -> argparse.ArgumentParser:
    """
    Build the console parser with every help line in the chosen language.

    Passing an English default to every lookup keeps a key the catalogue happens to lack from
    ever surfacing as a raw key in --help.
    """
    translator = get_translator(language or _requested_language())

    def t(key: str, english: str, **params: object) -> str:
        return translator.t(key, english, **params)

    parser = argparse.ArgumentParser(
        add_help=False,  # Replaced below so that -h is described in the chosen language too.
        description=t(
            "cli.description",
            "Safely analyze Windows PC health without changing any system setting.",
        ),
        epilog=t(
            "cli.epilog",
            "Exit codes: 0 success, 1 runtime failure, 2 invalid arguments, 3 score below "
            "--fail-under. The analyzer only reads. It never deletes, repairs, or "
            "reconfigures.",
        ),
    )
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help=t("cli.help.help", "show this help message and exit"),
    )

    analysis = parser.add_argument_group(t("cli.group.analysis", "analysis"))
    analysis.add_argument(
        "--cpu-sample-seconds",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help=t("cli.help.cpu_seconds", "CPU measurement interval from 0 to 5 seconds (default: 1)"),
    )
    analysis.add_argument(
        "--top",
        type=int,
        default=5,
        metavar="N",
        help=t("cli.help.top", "how many top processes to collect, 0 disables the list "
                              "(default: 5)"),
    )
    analysis.add_argument(
        "--no-temp-scan",
        action="store_true",
        help=t("cli.help.no_temp_scan", "skip the TEMP folder measurement entirely"),
    )
    analysis.add_argument(
        "--temp-scan-seconds",
        type=float,
        default=DEFAULT_SCAN_SECONDS,
        metavar="SECONDS",
        # The number is passed in so the help can never quote a stale default. It travels as
        # "seconds" because Translator.t() already owns the name "default".
        help=t(
            "cli.help.temp_seconds",
            "time budget for the TEMP folder scan in seconds (default: {seconds})",
            seconds=f"{DEFAULT_SCAN_SECONDS:g}",
        ),
    )
    analysis.add_argument(
        "--no-startup",
        action="store_true",
        help=t("cli.help.no_startup", "skip collection of startup items"),
    )
    analysis.add_argument(
        "--no-gpu",
        action="store_true",
        help=t("cli.help.no_gpu", "skip collection of GPU details"),
    )

    output = parser.add_argument_group(t("cli.group.output", "output"))
    output.add_argument(
        "--format",
        choices=exporters.FORMATS,
        default=None,
        help=t("cli.help.format", "output format (default: text, or taken from the export file "
                                 "extension)"),
    )
    output.add_argument(
        "--export",
        nargs="?",
        const=AUTO_EXPORT,
        metavar="PATH",
        help=t("cli.help.export", "export the result; without a path an auto-named file lands "
                                 "in this folder"),
    )
    output.add_argument(
        "--output",
        metavar="PATH",
        help=t("cli.help.output", "explicit export destination; implies --export and wins over it"),
    )
    output.add_argument(
        "--no-prompt",
        action="store_true",
        help=t("cli.help.no_prompt", "never ask anything interactively"),
    )
    output.add_argument(
        "--redact",
        action="store_true",
        help=t("cli.help.redact", "mask the Windows account name everywhere in the output"),
    )
    output.add_argument(
        "--lang",
        choices=available_languages(),
        default=detect_language(),
        help=t("cli.help.language", "report language (default: detected from APOLIAK_LANG or the "
                                   "system locale)"),
    )
    output.add_argument(
        "--color",
        choices=COLOR_MODES,
        default="auto",
        help=t("cli.help.color", "terminal colour; never reaches an exported file "
                                "(default: auto)"),
    )
    output.add_argument(
        "--quiet",
        action="store_true",
        help=t("cli.help.quiet", "print only the score line"),
    )
    output.add_argument(
        "--fail-under",
        type=int,
        default=None,
        metavar="N",
        help=t("cli.help.fail_under", "exit with code 3 when the health score is below N (0-100)"),
    )

    stored = parser.add_argument_group(
        t("cli.group.history", "history (opt-in, stored locally)")
    )
    stored.add_argument(
        "--save-history",
        action="store_true",
        help=t("cli.help.history", "append this run to the local history file"),
    )
    stored.add_argument(
        "--history-path",
        metavar="PATH",
        help=t(
            "cli.help.history_path",
            "custom history file (default: %%LOCALAPPDATA%%\\Apoliak\\Vitals)",
        ),
    )
    stored.add_argument(
        "--show-history",
        nargs="?",
        type=int,
        const=10,
        default=None,
        metavar="N",
        help=t("cli.help.show_history", "print the last N stored runs and exit "
                                       "(default: 10, 0 shows all)"),
    )
    stored.add_argument(
        "--compare",
        action="store_true",
        help=t("cli.help.compare", "show the change against the previous stored run"),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {APP_VERSION}",
        help=t("cli.help.version", "show the program version and exit"),
    )
    return parser


def run(args: argparse.Namespace) -> int:
    """Execute one console run and return the process exit code."""
    translator = get_translator(_get(args, "lang", None))
    problem = _validate(args, translator)
    if problem is not None:
        print(problem, file=sys.stderr)
        return 2

    quiet = bool(_get(args, "quiet", False))
    redact = bool(_get(args, "redact", False))

    if _get(args, "show_history", None) is not None:
        return _show_history(args, translator)

    requested_path = _get(args, "output", None)
    if requested_path is None:
        requested_path = _get(args, "export", None)
    export_requested = requested_path is not None

    fmt = _get(args, "format", None) or _format_from(requested_path) or "text"
    if fmt not in exporters.FORMATS:
        print(
            translator.t("cli.msg.invalid_format", "Error: unknown export format '{value}'.",
                         value=fmt),
            file=sys.stderr,
        )
        return 2

    colors = Ansi(_color_enabled(_get(args, "color", "auto")))
    progress = _ProgressLine(
        sys.stdout, translator, enabled=_isatty(sys.stdout) and not quiet
    )

    try:
        data = analyze_pc(
            cpu_interval=float(_get(args, "cpu_sample_seconds", 1.0)),
            top_process_limit=max(0, int(_get(args, "top", 5))),
            scan_temp=not bool(_get(args, "no_temp_scan", False)),
            temp_scan_seconds=float(_get(args, "temp_scan_seconds", DEFAULT_SCAN_SECONDS)),
            include_startup=not bool(_get(args, "no_startup", False)),
            include_gpu=not bool(_get(args, "no_gpu", False)),
            progress=progress.update,
        )
    except MissingDependencyError as error:
        print(translator.t("cli.msg.missing_dependency", "Error: {error}", error=error),
              file=sys.stderr)
        return 1
    except Exception as error:  # A failed analysis must still exit cleanly.
        print(_failed_text(translator, error), file=sys.stderr)
        return 1
    finally:
        progress.clear()

    try:
        assessment = calculate_health_details(data)
        recommendations = generate_recommendations(data)
    except Exception as error:
        print(_failed_text(translator, error), file=sys.stderr)
        return 1

    # Status lines must never end up inside piped machine-readable output.
    notes = _Notes(None if quiet else _note_stream(fmt, export_requested))
    history_path = _get(args, "history_path", None)

    # Read the delta before storing this run, so "previous" cannot become this very run.
    compare = bool(_get(args, "compare", False))
    delta = history.compare_to_previous(data, assessment, path=history_path) if compare else None

    # A renderer defect is still a failed run, never a traceback in the user's console.
    try:
        if quiet:
            print(_score_line(assessment, translator, colors))
        elif fmt == "text":
            print(
                build_report(
                    data, recommendations, assessment,
                    translator=translator, redact=redact, colors=colors,
                ),
                end="",
            )
        elif not export_requested:
            content = exporters.render(
                fmt, data, recommendations, assessment, translator=translator, redact=redact
            )
            sys.stdout.write(content if content.endswith("\n") else f"{content}\n")
    except Exception as error:
        print(_failed_text(translator, error), file=sys.stderr)
        return 1

    if compare:
        for line in _compare_lines(delta, translator):
            notes(line)

    destination = _destination(requested_path, fmt)
    if not export_requested and fmt == "text" and not quiet and _may_prompt(args):
        if _ask_to_export(translator):
            # Our own name, so it steps aside instead of replacing an earlier export.
            destination = exporters.unique_path(Path.cwd() / exporters.default_filename(fmt))
            export_requested = True

    if export_requested and destination is not None:
        try:
            saved = exporters.export(
                fmt, data, recommendations, assessment, destination,
                translator=translator, redact=redact,
            )
        except (OSError, ValueError) as error:
            print(
                translator.t("cli.msg.export_failed", "Could not export the report: {error}",
                             error=error),
                file=sys.stderr,
            )
            return 1
        except Exception as error:  # A renderer defect must not reach the user as a traceback.
            print(_failed_text(translator, error), file=sys.stderr)
            return 1
        notes(translator.t("cli.msg.saved", "Report saved to: {path}",
                           path=_display_path(saved, redact)))

    if bool(_get(args, "save_history", False)):
        try:
            stored = history.append_snapshot(data, assessment, path=history_path)
        except OSError as error:  # Opt-in bookkeeping never invalidates a good analysis.
            print(
                translator.t("cli.msg.history_failed",
                             "Could not update the history file: {error}", error=error),
                file=sys.stderr,
            )
        else:
            notes(translator.t("cli.msg.history_saved", "History updated: {path}",
                               path=_display_path(stored, redact)))

    threshold = _get(args, "fail_under", None)
    if threshold is not None and assessment.score < int(threshold):
        print(
            translator.t(
                "cli.msg.below_threshold",
                "Score {score} is below the required minimum {threshold}.",
                score=assessment.score,
                threshold=int(threshold),
            ),
            file=sys.stderr,
        )
        return 3
    return 0


def main() -> int:
    _harden_console()
    return run(build_parser().parse_args())


def _harden_console() -> None:
    """
    Let the console degrade a character instead of killing the run.

    A legacy code page cannot encode Slovak diacritics, and a redirected stream would raise
    UnicodeEncodeError halfway through a report. Replacement characters are a far better
    outcome than a traceback over an accent.

    A redirected stream is also a file the user opens later, and the JSON, HTML, and
    Markdown documents all declare UTF-8, so those bytes must really be UTF-8 - otherwise
    ``main.py --format json > report.json`` writes a file no JSON reader can decode. A real
    console keeps its own code page, where UTF-8 bytes would come out as mojibake.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            if _isatty(stream):
                reconfigure(errors="replace")
            else:
                reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def _get(args: argparse.Namespace, name: str, default: Any) -> Any:
    """Read one option, tolerating a Namespace built by an older caller or by a test."""
    value = getattr(args, name, default)
    return default if value is None and default is not None else value


def _validate(args: argparse.Namespace, translator: Translator) -> str | None:
    """Return the first argument problem as a ready-to-print message, or None when usable."""
    interval = translator.t(
        "cli.msg.invalid_interval", "Error: --cpu-sample-seconds must be between 0 and 5."
    )
    try:
        cpu_seconds = float(_get(args, "cpu_sample_seconds", 1.0))
    except (TypeError, ValueError):
        return interval
    if not 0 <= cpu_seconds <= 5:
        return interval

    try:
        top = int(_get(args, "top", 5))
    except (TypeError, ValueError):
        top = -1
    if top < 0:
        return translator.t("cli.msg.invalid_top", "Error: --top must be 0 or a whole number.")

    try:
        temp_seconds = float(_get(args, "temp_scan_seconds", DEFAULT_SCAN_SECONDS))
    except (TypeError, ValueError):
        temp_seconds = -1.0
    if temp_seconds < 0:
        return translator.t(
            "cli.msg.invalid_temp_seconds", "Error: --temp-scan-seconds must be 0 or greater."
        )

    threshold = _get(args, "fail_under", None)
    if threshold is not None:
        try:
            threshold = int(threshold)
        except (TypeError, ValueError):
            threshold = -1
        if not 0 <= threshold <= 100:
            return translator.t(
                "cli.msg.invalid_threshold", "Error: --fail-under must be between 0 and 100."
            )

    if _get(args, "color", "auto") not in COLOR_MODES:
        return translator.t(
            "cli.msg.invalid_color",
            "Error: --color must be one of: {values}.",
            values=", ".join(COLOR_MODES),
        )
    return None


def _failed_text(translator: Translator, error: BaseException) -> str:
    return translator.t("cli.msg.analysis_failed", "Analysis failed safely: {error}", error=error)


def _format_from(path: str | None) -> str | None:
    """Infer the format from an export path so --output report.html just works."""
    if not path:
        return None
    try:
        return exporters.format_from_path(path)
    except Exception:
        return None


def _destination(requested_path: str | None, fmt: str) -> Path | None:
    """
    Turn the requested export target into a path.

    A generated name is resolved to a free one, because two runs inside the same second would
    otherwise share a file name and the second would overwrite the first. A path the user
    typed is returned untouched: overwriting is what naming a file means.
    """
    if requested_path is None:
        return None
    if requested_path == AUTO_EXPORT:
        return exporters.unique_path(Path.cwd() / exporters.default_filename(fmt))
    return Path(requested_path)


def _note_stream(fmt: str, export_requested: bool) -> TextIO:
    if fmt == "text" or export_requested:
        return sys.stdout
    return sys.stderr


def _color_enabled(mode: str) -> bool:
    if mode == "always":
        return True
    if mode == "never":
        return False
    return supports_color(sys.stdout)


def _isatty(stream: TextIO | None) -> bool:
    try:
        return bool(stream is not None and stream.isatty())
    except Exception:
        return False


def _may_prompt(args: argparse.Namespace) -> bool:
    if bool(_get(args, "no_prompt", False)):
        return False
    return _isatty(sys.stdout) and _isatty(sys.stdin)


def _ask_to_export(translator: Translator) -> bool:
    question = translator.t("cli.prompt.export", "Export this report? [y/N]: ")
    try:
        answer = input(f"\n{question}").strip().casefold()
    except (EOFError, KeyboardInterrupt):
        print()
        print(translator.t("cli.msg.cancelled", "Cancelled."))
        return False
    return answer in _YES_ANSWERS


def _status_text(status: str, translator: Translator) -> str:
    key = f"status.{str(status).strip().casefold().replace(' ', '_')}"
    return translator.t(key, str(status))


def _score_line(assessment: HealthAssessment, translator: Translator, colors: Ansi) -> str:
    text = translator.t(
        "cli.msg.score_line",
        "Score: {score}/100 ({status})",
        score=assessment.score,
        status=_status_text(assessment.status, translator),
    )
    if assessment.score >= 75:
        return colors.paint(text, colors.BOLD, colors.GREEN)
    if assessment.score >= 50:
        return colors.paint(text, colors.BOLD, colors.YELLOW)
    return colors.paint(text, colors.BOLD, colors.RED)


def _compare_lines(delta: history.HistoryDelta | None, translator: Translator) -> list[str]:
    """Render the change against the previous stored run, one metric per line."""
    if delta is None:
        return [translator.t("cli.msg.no_history", "No previous analysis is stored yet.")]

    header = translator.t(
        "cli.msg.compare_header",
        "Compared with the previous analysis ({when}):",
        when=delta.previous.analyzed_at.strftime("%Y-%m-%d %H:%M"),
    )
    metrics = (
        ("cli.msg.compare_score", "Score: {value}", f"{delta.score_delta:+d}"),
        ("cli.msg.compare_cpu", "CPU usage: {value}", _signed_points(delta.cpu_delta)),
        ("cli.msg.compare_ram", "RAM usage: {value}", _signed_points(delta.ram_delta)),
        ("cli.msg.compare_disk", "Free disk space: {value}",
         _signed_bytes(delta.disk_free_delta)),
    )
    lines = [f"  {translator.t(key, default, value=value)}" for key, default, value in metrics]
    return [header, *lines]


def _signed_points(value: float | None) -> str:
    """Percentage-point difference. Unknown stays N/A instead of a made-up zero."""
    if value is None:
        return "N/A"
    return f"{value:+.1f} pp"


def _signed_bytes(value: int | None) -> str:
    if value is None:
        return "N/A"
    return f"{'+' if value >= 0 else '-'}{format_bytes(abs(value))}"


def _display_path(path: Any, redact: bool) -> str:
    text = str(path)
    return (redact_text(text) or text) if redact else text


def _show_history(args: argparse.Namespace, translator: Translator) -> int:
    """Print the stored runs and exit. This path never touches the operating system."""
    try:
        count = int(_get(args, "show_history", 10))
    except (TypeError, ValueError):
        count = 10

    location = _get(args, "history_path", None)
    redact = bool(_get(args, "redact", False))
    entries = history.load_history(path=location, limit=count if count > 0 else None)
    resolved = location if location is not None else history.default_history_path()
    print(
        translator.t(
            "cli.msg.history_file", "History file: {path}", path=_display_path(resolved, redact)
        )
    )

    if not entries:
        print(translator.t("cli.msg.no_history", "No previous analysis is stored yet."))
        return 0

    # Headers are translated, so their width follows the text instead of a fixed column size.
    # The table has its own keys instead of borrowing report.*/field.*: a column heading and
    # a report label are different jobs, and a language has to be free to shorten the one
    # without touching the other. The defaults repeat the shipped English wording.
    headers = [
        translator.t("cli.history.column.date", "Analysis Date"),
        translator.t("cli.history.column.score", "Score"),
        translator.t("cli.history.column.status", "Status"),
        translator.t("cli.history.column.cpu", "CPU"),
        translator.t("cli.history.column.ram", "RAM"),
        translator.t("cli.history.column.free_disk", "Free disk"),
    ]
    aligns = ("l", "r", "l", "r", "r", "r")
    rows = [
        [
            entry.analyzed_at.strftime("%Y-%m-%d %H:%M"),
            str(entry.score),
            _status_text(entry.status, translator),
            format_percent(entry.cpu_percent),
            format_percent(entry.ram_percent),
            format_bytes(entry.disk_free_bytes),
        ]
        for entry in entries
    ]
    widths = [
        max([len(headers[index])] + [len(row[index]) for row in rows])
        for index in range(len(headers))
    ]

    def line(cells: Sequence[str]) -> str:
        parts = [
            cell.rjust(widths[index]) if aligns[index] == "r" else cell.ljust(widths[index])
            for index, cell in enumerate(cells)
        ]
        return "  ".join(parts).rstrip()

    print()
    print(line(headers))
    print("-" * (sum(widths) + 2 * (len(widths) - 1)))
    for row in rows:
        print(line(row))
    return 0


class _Notes:
    """Writes short status lines to one stream, or swallows them in quiet mode."""

    def __init__(self, stream: TextIO | None) -> None:
        self._stream = stream

    def __call__(self, text: str) -> None:
        if self._stream is None:
            return
        print(text, file=self._stream)


class _ProgressLine:
    """
    Single-line progress indicator for interactive runs.

    Carriage-return updates keep the console tidy, and the line is erased once the run
    finishes. A console that rejects a write disables the indicator instead of failing the
    analysis, because progress output is never worth losing a result over.
    """

    def __init__(self, stream: TextIO, translator: Translator, *, enabled: bool) -> None:
        self._stream = stream
        self._translator = translator
        self._enabled = bool(enabled)
        self._width = 0

    def update(self, step_key: str, fraction: float) -> None:
        """
        Render one analysis step.

        ``step_key`` is a key from :data:`src.analyzer.PROGRESS_LABELS`, not a sentence, so
        the step is translated here - in the language this run was asked for - instead of
        arriving as English prose the console would have to print as it stands. A step the
        catalogue does not carry falls back to the analyzer's own English label.
        """
        if not self._enabled:
            return
        try:
            percent = max(0, min(100, int(round(float(fraction) * 100))))
            step = self._translator.t(
                f"progress.{step_key}", PROGRESS_LABELS.get(step_key, str(step_key))
            )
            # The passthrough key stays in the chain so a language can still decorate the
            # line (a prefix, a different spacing) without touching this module.
            label = self._translator.t("cli.msg.progress", "{message}", message=step)
            line = f"[{percent:3d}%] {str(label)[:60]}"
            self._width = max(self._width, len(line))
            self._stream.write(f"\r{line.ljust(self._width)}")
            self._stream.flush()
        except Exception:
            self._enabled = False

    def clear(self) -> None:
        if not self._enabled or not self._width:
            return
        try:
            self._stream.write(f"\r{' ' * self._width}\r")
            self._stream.flush()
        except Exception:
            pass
        self._width = 0


if __name__ == "__main__":
    raise SystemExit(main())
