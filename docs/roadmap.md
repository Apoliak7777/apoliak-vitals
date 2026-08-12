# Roadmap

## Completed — v1.0 analyzer (2026-07-16)

- Console analyzer
- Modern dark GUI
- System, CPU, RAM, disk, process, TEMP, and uptime data
- PC Health Score and visible deductions
- Safe recommendations
- Text report export
- Automated tests
- Standalone Windows build configuration

## Completed — v2.0 (2026-08-11)

The v1.1 list is now shipped, with two exceptions noted below.

- **Done — JSON export with a versioned schema.** `src/exporters.py`, `schema_version`
  `2.0`, stable key layout. HTML and Markdown shipped alongside it.
- **Done — historical report comparison stored only with user consent.**
  `src/history.py`, opt-in via `--save-history` or the GUI checkbox, newest 200 runs, and
  `--compare` for the delta against the previous run.
- **Done — localization layer.** `src/i18n.py`, English and Slovak across the report, the
  exports, the CLI, and the GUI, with `APOLIAK_LANG` and OS-locale detection.
- **Done — accessibility and high-contrast review on Windows.** A light theme was added
  beside the dark one, and both palettes were reworked for contrast. The remaining gaps
  are keyboard navigation and screen-reader labelling; they move to v2.1.
- **Not done — signed release workflow and checksums.** Carried forward.
- **Not done — optional PDF export.** Deferred indefinitely: every viable route adds a
  third-party dependency, and the self-contained HTML export prints to PDF from any
  browser.

Also delivered beyond the v1.1 list: registry-based Windows edition, firmware, GPU and
startup collection; SSD/HDD detection; per-partition listing; top-process ranking by memory
with real CPU figures; page file, battery, and network metrics; the graded score of 36 rule
rows with per-area sub-scores; redaction in both interfaces; and the console exit-code
contract.

### Hardening pass, same release

A review before release found eleven defects worth fixing rather than documenting. All are
in: `data.disk` is the single authority on which drive is being scored and advised on;
`src/i18n.py` is the single source of the rendered wording, so the four export formats of
one run cannot disagree; a truncated TEMP scan marks the snapshot incomplete and is quoted
as a lower bound; the top-process CPU column holds real, per-core-normalised numbers;
`required_values_present()` is the one definition of "complete"; Slovak counts with three
plural forms; the console `--help` and history table follow `--lang`; the HTML and Markdown
renderers cannot crash a run; automatically named exports never overwrite each other; TEMP
is resolved from the environment so no probe file is written; and the GUI has the redaction
checkbox the CLI always had.

### Adversarial review rounds, same release

Two further review rounds found six more defects, all reproduced with evidence before they
were fixed. All are in:

1. **No deduction without advice.** The mild tiers of CPU, RAM, and page-file usage deducted
   points while the advice engine stayed silent. `medium_cpu`, `medium_ram`, and
   `medium_swap` close the gap, and the invariant is now absolute: no deduction key is ever
   emitted without a recommendation covering the same condition, and `all_good` is only ever
   emitted alone.
2. **The lower bound is not English.** The "at least X" qualifier was baked into the
   deduction's `value` parameter, so a Slovak report read "(at least 12.0 GB)". Producers
   now attach a language-neutral `bound` parameter and the shared renderer words it through
   `report.at_least`; the truncated-TEMP recommendations stopped quoting the same size as
   exact.
3. **A missing TEMP folder is unknown, not empty.** A path that is not an accessible
   directory yields `size_bytes=None` and a warning instead of 0 bytes — the last place the
   application invented a measurement.
4. **Progress steps speak the chosen language.** `analyze_pc` passes a step key plus a
   fraction and publishes `PROGRESS_LABELS`; the console and the GUI translate it.
5. **No orphaned catalogue keys.** Of 29 keys with no call site, ten were wired to where
   they belong and 19 removed from both tables.
6. **JSON gets the same net as the other formats.** `snapshot_to_dict()` builds every branch
   behind a guard and reports failures in `export_errors`, while `render()` still raises
   `ValueError`, and only `ValueError`, for an unknown format.

The test suite grew to 548 tests across ten modules.

## Completed — v2.1 (2026-08-12)

v2.0 measured **load**: how busy the PC is right now. v2.1 closes the obvious gap by adding
**state**: what is durably wrong, whether or not the machine happens to be busy.

- **Done — Windows protection status.** `src/win_security.py`: antivirus and firewall through
  the Security Center API (which also covers third-party antivirus), Secure Boot, a pending
  restart and why one is owed, Defender's last scan and signature age. A new `security` score
  category, a new GUI view, and a new section in all four export formats.
- **Done — drive wear.** `src/win_storage.py`: model, bus type, media type, life remaining,
  temperature, power-on hours, data written and the drive's own critical warning, from the
  NVMe SMART health log page. Query-only IOCTLs on handles opened with `dwDesiredAccess = 0`;
  no administrator rights; the serial number deliberately never read.
- **Done — battery wear.** `src/win_battery.py`: design against full-charge capacity, cycle
  count and chemistry, straight from the ACPI battery driver. Unelevated, verified from a
  standard account.
- **Done — the biggest-folders scan.** `src/folder_usage.py`: eight known folders resolved
  with `SHGetKnownFolderPath` and measured with the same defensive walker TEMP uses, sharing
  one wall-clock budget with it so a run cannot get longer.
- **Done — actionable advice.** Eleven recommendations carry an `ms-settings:` page, and the
  GUI shows an **Open setting** button for them. The app opens the page; the user makes the
  change; the app itself still changes nothing.
- **Done — a trend view in the GUI.** The History view draws a score-over-time chart from
  `history.load_history()`, exactly as this list proposed: a pure read, opt-in, no new file.
- **Done — keep `app.manifest` at `asInvoker`.** Unchanged, and every new collector was built
  to work without elevation rather than to ask for it.
- **Not done — signed release workflow and published checksums.** Still the oldest open item
  and the one that matters most for a tool users download. Carried into v2.2.
- **Not done — reproducible build documentation.** Carried forward.
- **Not done — the scheduled-snapshot workflow, the benchmark module, keyboard navigation and
  screen-reader labelling, `--watch`, and additional languages.** All carried into v2.2 below,
  unchanged.

### The honesty rules the new collectors are built on

Every v2.1 collector was written to the same three constraints, and they are worth keeping
for anything added later:

1. **Unknown is a first-class answer.** A refused registry key, a `wscapi.dll` that will not
   load, a SATA drive that rejects the SMART query and a firmware that publishes no capacity
   all produce `None` or `STATE_UNKNOWN` — never `bad`, never an estimate, never a
   comfortable zero. An unknown is never penalised by the score.
2. **A wrong number is worse than no number.** Every decoder has plausibility limits, and a
   figure outside them is dropped rather than reported.
3. **Report, do not judge, where the project has no rule.** Secure Boot is reported and
   advised on but costs no points, because it is off for many legitimate reasons; Defender's
   last scan date is shown without a verdict pill, because this application has no rule about
   how recent a scan should be and inventing one on screen would put an opinion in front of
   the user that the score does not hold.

### The read-only promise became a test

v2.1 is the first release in which the application may launch anything at all — one
`os.startfile` on an `ms-settings:` page, only from a click. That made a written promise
insufficient, so `tests/test_readonly.py` now proves it:

- an audit hook (`sys.addaudithook`) in a child interpreter watches `analyze_pc` (defaults,
  every collector on, every collector off) and all four renderers in both languages, plain and
  redacted, and asserts **zero** write-opens, file mutations, process launches, `os.startfile`
  calls, sockets and registry writes — including from inside `psutil` and `ctypes`, where a
  source-level grep sees nothing;
- the probe carries its own negative control, so an empty finding list cannot mean a broken
  hook;
- an `ast` pass asserts `open_setting` is the only function in `gui.py` that can reach
  `os.startfile`, and the fence itself is tested against 7 accepted and 26 refused values.

The test suite grew to **948 tests across sixteen modules**, up from 548 across ten.

## Proposed v2.2

**Release engineering**

- Signed release workflow and published SHA-256 checksums for the executable. This is the
  oldest open item and the one that matters most for a tool users download.
- Reproducible build documentation: pinned dependency versions and a recorded PyInstaller
  version per release.
- Keep `app.manifest` at `asInvoker`. An elevation request would break the central promise
  and must never be added — and every collector shipped so far was designed around that,
  including the two that read hardware wear.

**Scheduled snapshots**

- An opt-in scheduled run that appends to the existing history store: `main.py --quiet
  --no-prompt --save-history` is already the whole payload.
- Registration via Windows Task Scheduler must be a documented command the user runs
  themselves, or an action behind an explicit confirmation that shows the exact task it
  would create. The analyzer itself must not silently register anything — creating a
  scheduled task is a write to the system, and it belongs on the far side of the boundary
  described below. The v2.1 settings button is **not** a precedent for it: opening a page
  changes nothing, and registering a task changes something.
- The GUI trend view shipped in v2.1; extending it to CPU, RAM and free space over time is a
  pure read of the same store.

**Benchmark module**

- A read-only, self-contained CPU and memory micro-benchmark, run only when the user asks
  for it, with the sample duration shown before it starts.
- Results are a separate model and a separate score input; they must never silently change
  the health score, and a machine that never ran a benchmark must not be penalised for it.
- Storage benchmarking is explicitly out of scope while the tool is read-only: a
  representative disk benchmark writes.
- No result may be phrased as a promise. No FPS figures, no "your PC will be X% faster".

**More state, on the same terms**

- SATA/ATA SMART attributes for drives that reject the NVMe log page, if and only if a
  route exists that keeps `dwDesiredAccess = 0` and needs no elevation. If the only route is
  an elevated one, the answer stays "unknown" — that is the trade this project makes.
- Windows Update history and driver age, read-only, with the same "report, do not judge"
  rule: no deduction without a threshold the project is willing to publish and defend.

**Interface and coverage**

- Full keyboard navigation and screen-reader labelling in the GUI. Carried from v2.0 and
  still open; the six-view sidebar makes it more valuable, not less.
- Optional `--watch` mode on the console: re-sample at an interval and print only the score
  line, for a support session.
- Console flags for the v2.1 collectors (`--no-security`, `--no-drive-health`,
  `--no-folder-scan`). `analyze_pc` already accepts the arguments; only `main.py` would
  change.
- Additional languages. The i18n layer already reports missing keys through
  `Translator.missing_keys()`, so a partial table degrades to English safely.

## Rules for any future write-capable optimizer module

These are unchanged from v1.0 and are not negotiable by convenience.

- **Keep the analyzer strictly read-only.** No write operation may be added inside
  `src/analyzer.py`, `src/win_registry.py`, `src/win_security.py`, `src/win_storage.py`,
  `src/win_battery.py`, `src/folder_usage.py`, `src/processes.py`, `src/health_score.py`, or
  `src/recommendations.py`. Registry access stays `KEY_READ`; device handles stay query
  handles.
- **Put every write-capable action behind a separate service boundary** with its own
  models, its own tests, and its own entry point. It may consume `AnalysisData`; the
  analyzer must never depend on it.
- **Preview the exact change before confirmation.** Name the file, the key, the service, or
  the setting — never "optimize system".
- **Create and verify a restore path** where Windows supports one, and say so plainly where
  it does not.
- **Record a reversible action log** of what was changed, when, and how to undo it.
- **Offer safe mode and advanced mode without hiding risk.** Advanced mode may unlock more
  actions; it may not make the warnings quieter.
- **Benchmark before and after, and never promise a fixed improvement.**
- **Require confirmation per action, not per session.** One approval may not authorise a
  later, different write.
- **Keep the audit-hook test green.** `tests/test_readonly.py` asserts that analysis and
  export perform zero writes, zero launches and zero network calls. A write-capable module
  must live outside those code paths, which means the existing test keeps passing unchanged —
  if it needs relaxing, the boundary has been drawn in the wrong place.

Potential modules include a confirmed TEMP cleaner, a startup-app manager, a power-plan
selector, a benchmark tool, and game profiles. None of them belongs in the analyzer's
collection layer.
