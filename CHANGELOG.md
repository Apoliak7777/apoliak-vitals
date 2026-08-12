# Changelog

All notable project changes are documented here.

## 2.1.0 — 2026-08-12

v2.0 measured how busy the PC is. v2.1 adds what is durably wrong: the Windows protection
state, drive and battery wear, and where the disk space actually went — plus advice that
points at the page where something can be done about it.

### Added

- **`src/win_security.py` — the Windows protection state.** `read_security_state()` returns a
  `SecurityInfo` describing antivirus and firewall (through `WscGetSecurityProviderHealth` in
  `wscapi.dll`, which also covers third-party antivirus), Secure Boot, whether a restart is
  owed and why, Defender's last scan time, and the age of its signatures. Everything else is
  `KEY_READ` registry reads. Never raises; every field comes back `unknown` on a non-Windows
  host, on a locked-down machine, or when `wscapi.dll` will not load. `antivirus_name` is
  always `None` — the product name needs COM/WMI, which this project does not use, and
  guessing it would be an invention.
- **`src/win_storage.py` — drive wear.** `read_drive_health(drives=None)` returns one
  `DriveHealth` per physical disk: model, bus type, media type, percentage used (and the
  derived `life_left_percent`), temperature, power-on hours, total data written, and the
  drive's own critical-warning flag, decoded from the NVMe SMART / Health Information log
  page. Three query IOCTLs on handles opened with `dwDesiredAccess = 0` — no read access, no
  write access, **no administrator rights**. One physical disk answers once however many
  volumes it carries, and a disk that reports nothing is omitted rather than padded with
  `N/A`. **The serial number in `STORAGE_DEVICE_DESCRIPTOR` is deliberately never read.**
- **`src/win_battery.py` — battery wear.** `read_battery_health()` enumerates the present
  battery interfaces with `setupapi` and issues `IOCTL_BATTERY_QUERY_TAG` and
  `IOCTL_BATTERY_QUERY_INFORMATION`, returning design capacity, full-charge capacity, cycle
  count and chemistry. Returns an empty dict on a desktop or when nothing is readable.
  `BATTERY_CAPACITY_RELATIVE` packs are dropped rather than reported in a unit the firmware
  never published.
- **`src/folder_usage.py` — the biggest folders.** `read_folder_usage()` measures Downloads,
  Desktop, Documents, Pictures, Videos, Music, Local app data and Store app data with
  `utils.scan_folder`, biggest first, sharing one wall-clock budget. Paths come from
  `SHGetKnownFolderPath` with `KF_FLAG_DEFAULT` — never `KF_FLAG_CREATE` — because Documents
  and Desktop are routinely redirected into OneDrive and a `%USERPROFILE%` join would measure
  an empty leftover and report a reassuring, wrong number. A folder that cannot be listed
  reports `size_bytes=None`; a folder that does not exist is left out entirely.
- New models: `DriveHealth` (with `life_left_percent`), `SecurityInfo`, `FolderUsage`; the
  `STATE_GOOD` / `STATE_WEAK` / `STATE_BAD` / `STATE_UNKNOWN` verdict constants and
  `CATEGORY_SECURITY`. `BatteryInfo` gained `design_capacity_mwh`, `full_charge_capacity_mwh`,
  `cycle_count`, `chemistry` and the derived `health_percent`. `AnalysisData` gained
  `security`, `drive_health` and `folder_usage`. `Recommendation` gained `action_uri`.
- `analyzer.get_security()`, `analyzer.get_drive_health()` and `analyzer.get_folder_usage()`,
  plus the `include_security`, `include_drive_health`, `scan_folders` and
  `folder_scan_seconds` arguments of `analyze_pc` — every new step can be switched off, and a
  step that did not run leaves its field empty instead of guessing at it.
- Three new progress steps — `drive_health`, `folders`, `security` — in `PROGRESS_LABELS` and
  in both language tables, taking the analysis to thirteen named steps.
- **The `security` score category** and fourteen new rule rows across seven keys:
  `antivirus_off` (30 / 40), `firewall_off` (12 / 18), `stale_signatures` (8 / 14),
  `reboot_pending` (3), `drive_failing` (25), `drive_worn` (4 / 10 / 18) and `battery_worn`
  (3 / 6 / 10). `SCORE_RULES` now holds 50 rows over 17 measurements, still printable through
  `score_rules()`.
- Nine new recommendation keys — `antivirus_off`, `firewall_off`, `stale_signatures`,
  `secure_boot_off`, `reboot_pending`, `drive_worn`, `drive_failing`, `battery_worn` and
  `large_folder` — taking the catalogue to 32. `large_folder` fires when the biggest measured
  folder is over 20 GiB **or** over 10% of its drive; TEMP is excluded from that pick because
  it already has its own finding.
- **`Recommendation.action_uri` and the `RECOMMENDATION_ACTIONS` table.** Eleven keys now
  name the Windows settings page their advice is about:
  `ms-settings:windowsdefender`, `ms-settings:windowsupdate`, `ms-settings:storagesense`,
  `ms-settings:batterysaver` and `ms-settings:startupapps`.
- **The GUI's "Open setting" button** — the first and only thing this application asks the
  operating system to do. It calls `os.startfile` on an `ms-settings:` URI, **only from a
  deliberate click**, and opening a settings page never changes the setting behind it. It is
  fenced by `gui.is_settings_uri()`, which requires the exact lower-case scheme and a strict
  character pattern and refuses — rather than repairs — anything else, and by
  `gui.ApoliakAnalyzerApp.open_setting()`, the single call site. Elevation is never
  requested; the console has no equivalent.
- **A new Security view in the GUI**, taking it to six views: antivirus, firewall, Secure
  Boot, restart pending, definitions age and last scan as good / needs-attention / unknown
  pills, plus the security deductions and the security advice. When the Security Center did
  not answer, the view says the states are "unknown rather than off".
- The Storage view gained a **Drive health** card and a **Biggest folders** card.
- **A score-over-time chart** in the History view, drawn on a canvas from the opt-in local
  history and redrawn at the real width after every resize. This closes the "trend view in
  the GUI" item from the v2.1 roadmap.
- **`tests/test_readonly.py`** — the read-only promise asserted by the interpreter instead of
  by review. An audit hook (`sys.addaudithook`) in a child interpreter watches `analyze_pc`
  (defaults, all collectors on, all collectors off) and all four renderers in both languages,
  plain and redacted, and asserts **zero** write-opens, file mutations, process launches,
  `os.startfile` calls, sockets and registry writes. It starts with its own negative control —
  it writes a real file and launches a real process while armed and asserts the hook noticed
  both — so an empty finding list cannot mean a broken hook. A separate `ast` pass asserts
  that `open_setting` is the only function in `gui.py` that can reach `os.startfile`.
- New test modules `test_win_security.py`, `test_win_storage.py`, `test_win_battery.py`,
  `test_folder_usage.py`, `test_models.py` and `test_readonly.py`. The suite grew from 548
  tests in ten modules to **948 in sixteen**, still on the standard-library runner. Each new
  collector is asserted to return a safe empty value with `platform.system()` monkeypatched
  to `"Linux"`.

### Changed

- **`SCHEMA_VERSION` raised to `2.1`.** Nothing was removed or renamed, so an existing reader
  keeps working. The JSON payload gained three top-level keys — `drive_health` (after
  `partitions`), `folder_usage` (after `temp`) and `security` (after `startup_items`) — while
  `battery` gained the four wear fields plus `health_percent`, and every entry of
  `recommendations` gained `action_uri`. `drive_health` writes out the derived
  `life_left_percent` so a reader does not have to know the formula, and `security.details`
  is a list of `{key, value}` pairs (`firewall_profiles_off`, `reboot_sources`,
  `security_center`).
- **The two folder scans share one budget.** `analyzer.TOTAL_SCAN_SECONDS` (8 s) covers TEMP
  and the user folders together: TEMP runs first with half of it and hands whatever it did
  not need to the folder scan, which is floored at one second. Measuring the user's folders
  as well as TEMP therefore cannot double the length of a run. The console's
  `--temp-scan-seconds` (12 s by default) still overrides the TEMP half.
- The report, all four exports and both interfaces gained the new sections: `DRIVE HEALTH`,
  `BIGGEST FOLDERS` and `SECURITY`, each wired to `section.*` keys in both languages.
- The catalogue grew from 356 to **418 keys per language**, still with identical placeholders
  per key and still with a call site for every one.
- `most_worn_drive()` and `failing_drive()` are public in `health_score` and imported by
  `recommendations`, so the score and the advice can never name a different drive. Drive wear
  costs **one** deduction per snapshot, not one per disk: a PC with two worn drives has one
  problem to act on, and charging twice for it would make the score depend on how many disks
  are fitted.
- The drive self-assessment metric stays unknown until at least one disk actually answered,
  because "no drive told us" and "every drive said it is fine" are different facts and only
  the second may report Storage as measured.
- Version raised to 2.1.0 in `pyproject.toml`, `version_info.txt` and `gui.py`.

### Fixed

- **A machine with no antivirus, no firewall or a failing drive scored as if nothing were
  wrong.** v2.0 measured only load, so a PC that was busy doing nothing scored 100 while its
  protection was off and its SSD was at 5% of its rated life. Those are now scored, and they
  are the heaviest rules in the table.
- **Battery health was reported as "100%" on a worn pack.** psutil answers what the battery
  is *doing*; it cannot answer what the pack has *become*. A battery holding 75 Wh against a
  design of 80 Wh still reads 100% charged, and that was the only number the app had.
  `BatteryInfo.health_percent` now reports the wear, and stays `None` — never an estimate —
  whenever either capacity is missing.
- **"You have 588 GB free" was advice nobody could act on.** The biggest-folders scan names
  the folder instead, and `large_folder` quotes it with a settings page to look inside it
  first.
- **A truncated folder scan is a floor, exactly like a truncated TEMP scan.** `large_folder`
  carries the same language-neutral `bound` parameter, so a Slovak report reads "aspoň …" and
  no format invents its own phrasing.
- Plausibility limits were added to every new decoder, because a wrong number is worse than
  no number: a drive temperature outside 233–398 K, over 1 000 000 power-on hours, over 1 EB
  written, a battery above 1 000 000 mWh or 100 000 cycles are all treated as a bad answer and
  dropped.
- A refused or failed settings-page open is reported on the GUI status line — flattened to one
  line and truncated, so a refused value cannot decide how tall the status line is — instead
  of raising. A machine with no `os.startfile` at all (any non-Windows host) says so rather
  than exploding.

### Deliberately not done

- **No deduction for Secure Boot.** It is collected, reported and answered with one line of
  advice, and it costs nothing. Secure Boot is off for many legitimate reasons — dual boot,
  older firmware — and taking points away for that would be dishonest.
- **No settings page for `secure_boot_off`, `drive_worn` or `drive_failing`.** The first lives
  in firmware, and no Windows setting undoes physical wear. A wrong page is worse than none.
- **No console flags for the new collectors.** `analyze_pc` can switch each of them off, but
  `main.py` gained no `--no-security`, `--no-drive-health` or `--no-folder-scan`; a console
  run collects all three, exactly as the defaults say.
- **Nothing new in the history file.** It still stores nine numeric fields and no wear,
  folder or protection data.

## 2.0.0 — 2026-08-11

### Added

- Registry-based Windows identity: edition, display version (`24H2`), full build with the
  update revision (`26100.8875`), and the install date, read with `KEY_READ` only.
- Firmware identity: board manufacturer, model, and BIOS version. OEM placeholder strings
  such as `Default string` are reported as unknown instead of repeated.
- Graphics adapters (up to 4) with driver version, normalised driver date, and adapter
  memory, read from the display-adapter driver class key.
- Startup entries (up to 60) from the four `Run`/`RunOnce` keys and from both Startup
  folders. Listed for information only; nothing can be disabled from the app.
- SSD/HDD detection for every drive, via two query-only IOCTLs on a volume handle opened
  with `dwDesiredAccess = 0`. No administrator rights, no subprocess.
- Per-partition listing (up to 12 fixed drives) with filesystem and media type.
- Top-process ranking by memory or CPU, with PID, RSS, memory share, and a real CPU
  percentage (`src/processes.py`). A memory-sorted list samples the CPU of the ranked
  processes only, in one shared 0.15 s window, and divides by the logical core count so the
  figures match Task Manager. Read-only: nothing is suspended or terminated.
- Page-file (swap) total, used, and percentage.
- Per-core CPU load and current/maximum clock frequency.
- Battery percentage, charging state, and remaining time.
- Network traffic counters and per-interface link state and speed. IP and MAC addresses are
  deliberately not read.
- A second temp location: the machine-wide `%SystemRoot%\Temp` when the account can list
  it, each location carrying its size, file count, and a truncation flag.
- Graded health score: 36 rule rows over 10 measurements, up to four severity tiers each
  instead of a single on/off threshold, exposed as a documentable table through
  `score_rules()`.
- `health_score.required_values_present(data)`: the single public definition of a complete
  snapshot. `HealthAssessment.data_complete` is computed from it and
  `src/recommendations.py` imports it, so "incomplete" means one thing project-wide.
- `AnalysisData.temp_truncated`: set when the primary user-TEMP scan hit its time budget.
  Every export surfaces it, `data_complete` goes false, and the `large_temp` deduction is
  reworded as a lower bound ("at least 5.0 GB") instead of quoting a total that was never
  finished.
- `analyzer.PROGRESS_LABELS`: the public step-key → English-label map behind the
  `analyze_pc` progress callback, which now reports `(step_key, fraction)`. Consumers render
  `translator.t(f"progress.{key}", PROGRESS_LABELS[key])`, so the console progress line and
  the GUI both follow the chosen language.
- Recommendation keys `medium_cpu`, `medium_ram`, and `medium_swap`, wired to exactly the
  mild tiers of `high_cpu` (55%), `high_ram` (70%), and `high_swap` (50%). They close the
  last gap where the score deducted points and the advice engine said nothing.
- Ten `progress.*` catalogue keys per language for the analysis steps.
- Plural support in `src/i18n.py` — `Translator.t_plural()` and `plural_form()`, with the
  `.one` / `.few` / `.many` key suffixes — used by every renderer.
- Per-area sub-scores for CPU, Memory, Storage, Maintenance, and Power. A category nobody
  could measure is flagged unavailable rather than reported as a clean 100.
- `src/i18n.py`: full English and Slovak translation tables for the report, the exporters,
  the CLI, and the GUI, with `APOLIAK_LANG` and OS-locale detection.
- `src/exporters.py`: JSON, HTML, and Markdown export beside the existing text report. The
  HTML document is a single self-contained file — inline CSS, no scripts, no external
  requests.
- `src/history.py`: opt-in local history in `%LOCALAPPDATA%\Apoliak\Vitals\history.jsonl`,
  JSON Lines, newest 200 runs, numbers only, written through an atomic replace.
- Console options `--top`, `--no-temp-scan`, `--temp-scan-seconds`, `--no-startup`,
  `--no-gpu`, `--format`, `--output`, `--no-prompt`, `--redact`, `--lang`, `--color`,
  `--quiet`, `--fail-under`, `--save-history`, `--history-path`, `--show-history`,
  `--compare`, and `--version`.
- Documented console exit codes: 0 success, 1 runtime failure — including a rendering or
  export defect — 2 invalid arguments, 3 score below `--fail-under`. `exporters.render()`
  raises `ValueError`, and only `ValueError`, for an unknown format name.
- Single-line console progress indicator for interactive runs, driven by the new optional
  `progress` callback of `analyze_pc`.
- GUI: five views (Overview, Processes, Storage, System, History), a light theme beside the
  dark one, a live language switch, export-format selection, and copy-to-clipboard.
- `--redact` / redaction support across the report, the exports, and the displayed paths.
- GUI **Redact personal data** checkbox, off by default, applied to every export format and
  to the clipboard copy — the interface parity `--redact` was missing.
- Test suite grown to 548 tests across ten modules, including `tests/test_gui.py`, which
  exercises the window's pure helpers without opening one. Two tests skip themselves when
  the account may not create symbolic links.

### Changed

- `SCHEMA_VERSION` raised to `2.0`. Every field added since v1.0 carries a default, so an
  older snapshot still constructs cleanly.
- The six v1.0 thresholds survive unchanged as the `standard` tier of their rule — CPU 70%,
  RAM 80%, 20 GB free, 180 processes, 3 GB of TEMP, 48 hours of uptime — so the published
  v1.0 score table stays literally true, and milder and harsher tiers surround each anchor.
- Recommendation thresholds are now read out of the score table instead of being written
  twice, so the report can no longer deduct points for something it fails to mention. The
  invariant is enforced end to end: no deduction key may be emitted without a
  recommendation covering the same condition, and `all_good` is only ever emitted alone.
  The catalogue ships 23 recommendation keys.
- A measurement a producer could only put a floor under now travels as a language-neutral
  `bound` parameter beside the plain formatted `value`; the shared renderer resolves it
  through `report.at_least` before substituting it into the sentence. Text, JSON, HTML, and
  Markdown therefore agree in both languages, and the same rule applies to the `large_temp`
  and `medium_temp` recommendations, which used to quote a truncated size as exact.
- `exporters.snapshot_to_dict()` gained the per-section net the text, HTML, and Markdown
  builders already had. A branch that cannot be built — or cannot be serialised — becomes
  `null` and names itself in the new `export_errors` list instead of taking the whole export
  down. `render()` still raises `ValueError`, and only `ValueError`, for an unknown format.
- Every catalogue key now has a call site. `report.at_least` and `report.temp_truncated`
  are used by the bound renderer and the TEMP section, the six `cli.history.column.*` keys
  by the `--show-history` table, `gui.msg.copied` by the clipboard button, and `gui.title`
  by the window title; the 19 remaining keys that no code referenced were deleted from both
  tables. A shipped key with no call site is a promise the product does not keep.
- CPU load is measured with one per-core sampling pass; the overall figure is its mean, so
  the sampling interval is paid only once.
- The TEMP measurement runs against a wall-clock budget (12 s by default), split evenly
  between the folders it will measure, and reports a truncated result instead of a size that
  is too small.
- Deductions and recommendations now carry a stable `key`, a `category`, a `severity`, and
  the parameters their sentence uses, so translations reuse the numbers instead of
  re-deriving them.
- `build_report` and `export_report` gained keyword-only `translator` and `redact`
  arguments; the v1.0 three-positional-argument call still works.
- `src/i18n.py` is now the single source of the rendered wording. `report.build_report()`,
  `exporters.render()`, and `exporters.snapshot_to_dict()` resolve `translator=None` to the
  catalogue's English instead of printing the producing module's own sentence, so the JSON,
  text, HTML, and Markdown of one run can no longer disagree. The `text` / `reason` strings
  on `Recommendation` and `ScoreDeduction` remain as a last-resort fallback for a key the
  catalogue genuinely lacks.
- The console speaks the chosen language throughout: `--lang` is resolved before the
  argparse parser is built, so `--help` — description, group headings, every option, and the
  exit-code footer — the `--show-history` table header, and the progress line are all
  translated. All 56 `cli.*` keys are wired to a call site.
- The TEMP folder is resolved from `TMP` / `TEMP` / `TMPDIR` and falls through to
  `tempfile.gettempdir()` only when none is set, because `gettempdir()` creates, writes, and
  deletes a probe file on first use — a write this application promises not to make.
- Automatically named exports resolve to a free file name (`…_2`, `…_3`, …) through the new
  `exporters.unique_path()`. A path the user typed or picked still overwrites, as expected.
- Every `--help` line now comes from the catalogue rather than from a literal in
  `main.py`, and several were corrected to describe what the flag actually does — `--quiet`
  suppresses the progress line and the status notes but not a requested export, `--format`
  names the four formats, `--history-path` names the local application-data folder.
- The console reconfigures stdout/stderr: a real console degrades an unencodable character
  instead of dying, and a redirected stream is forced to UTF-8 so a piped JSON or HTML file
  is actually decodable.
- Version raised to 2.0.0 in `pyproject.toml`, `version_info.txt`, `main.py`, `gui.py`, and
  `src/report.py`.

### Fixed

- Windows 11 was reported as Windows 10, because `ProductName` still reads "Windows 10" on
  11. The marketing number is now derived from the build and only the edition suffix comes
  from the registry.
- Free disk space and percent-full could both be charged for the same drive. Only the
  free-bytes rule fires now; the percentage rule covers only what it misses.
- A small or disabled page file reported extreme usage percentages that said nothing about
  memory pressure. Swap below 1 GiB is no longer scored or advised on.
- A plugged-in laptop at low charge was treated as a finding. Battery charge is scored only
  while the PC is actually discharging.
- `NaN` and infinity arriving from a collector are treated as unknown instead of silently
  losing every comparison or breaking the integer formatters.
- The TEMP walker no longer follows Windows junctions and reparse points, so a scan cannot
  wander off the local folder. Its deadline is also checked per directory, not only every
  128 entries, so a folder on a stalled network share can no longer outlast the budget.
- Recommendations picked the system drive themselves instead of reading `data.disk`. With
  `analyze_pc(drive=…)` pointed elsewhere, one report could deduct 32 points for a full disk
  and then say nothing was wrong. `_system_partition` is gone; advice and score now read the
  same record, and every drive-related deduction and recommendation carries the drive and
  the measurement in its `params`.
- The CPU column of the top-process table was always `N/A` in a real report, because
  `analyze_pc` collected the list without CPU sampling — which also meant the
  `top_cpu_process` advice could never fire.
- A truncated TEMP scan was reported as if it were a completed measurement. It now marks the
  snapshot incomplete and its deduction reads as a lower bound.
- A missing, non-directory, or unlistable TEMP folder was reported as 0 bytes and scored as
  a spotlessly clean TEMP — the one place the application still invented a measurement.
  `get_temp_locations` now checks that a candidate is an accessible directory before
  scanning it and otherwise records `size_bytes = None` plus a warning naming the folder, so
  a broken `TMP` costs no points and turns `data_complete` false.
- The mild tiers of `high_cpu` (>55%), `high_ram` (>70%), and `high_swap` (>50%) deducted
  points while the advice engine stayed silent, so a real report could print
  "- 8 points: RAM usage is high (72%)." immediately above "No urgent issues were detected."
  `medium_cpu`, `medium_ram`, and `medium_swap` close the gap.
- The lower-bound qualifier was baked into the deduction's `value` parameter as the English
  literal "at least {value}", so a Slovak report read "Priečinok TEMP obsahuje veľa údajov
  (at least 12.0 GB)." The qualifier is now a translated sentence, and `report.at_least` and
  `report.temp_truncated` — both shipped and both dead — are wired up.
- `exporters.snapshot_to_dict()` had no per-section guard, so a hostile value or an
  unserialisable type escaped the JSON exporter while the other three formats degraded
  gracefully.
- The progress callback of `analyze_pc` forwarded hard-coded English literals, so both the
  console (`[ 35%] Reading memory usage`) and the GUI showed English under `--lang sk`. The
  callback now carries a step key and the consumer translates it.
- 29 catalogue keys had no call site. Ten were wired to where they belong and 19 deleted
  from both language tables.
- Two automatically named exports started in the same second overwrote each other; the
  second one now becomes `…_2`.
- The Slovak report printed "- 3 bodov", which is wrong: Slovak takes `bod` for 1, `body`
  for 2–4, and `bodov` for 0 and 5 upwards.
- `--lang sk` still printed an English `--help` and an English history-table header.
- An exception inside the HTML or Markdown renderer escaped as a traceback. Both now carry
  the per-section net the text renderer already had, and `main.py` turns any remaining
  render or export failure into the standard "Analysis failed safely" line and exit code 1.
- Resolving the TEMP folder went through `tempfile.gettempdir()`, which writes a probe file
  into TEMP on first use — the one place where the application contradicted its own
  read-only promise.
- `utils.redact_text` only matched a profile path at the start of a string and only with
  backslashes, so `C:/Users/<name>` and a path quoted inside a startup command survived
  redaction.
- `utils._enable_vt_mode` left the console's virtual-terminal flag switched on after exit;
  the previous mode is now restored through `atexit`.
- A drive that refuses to answer is left out of the partition list instead of being
  reported as empty.

## 1.0.0 — 2026-07-16

- Added the full read-only PC analysis engine.
- Added Windows system, CPU, RAM, disk, process, TEMP, and uptime collection.
- Added a transparent 0–100 health score and deduction breakdown.
- Added safe rule-based recommendations.
- Added console and modern CustomTkinter interfaces.
- Added UTF-8 text report export.
- Added graceful component-level error handling and incomplete-data disclosure.
- Added local Windows setup, run, and PyInstaller build scripts.
- Added automated unit tests and project documentation.
