# Apoliak Vitals

Apoliak Vitals is a lightweight Windows PC analysis tool. It reads the state of the
machine — Windows edition and firmware, CPU, RAM and page file, drives and their wear, the
Windows protection settings, processes, temporary files, the biggest user folders, uptime,
battery charge and battery wear, network and graphics adapters, and startup entries — turns
that into a transparent 0–100 health score, and offers plain, non-destructive advice.

This project is the first module of **Apoliak Optimizer**.

## What v2.1 adds

v2.0 measured **load**: how busy the PC is right now. v2.1 adds **state**: what is durably
wrong, and what you can do about it.

- **Windows protection status** — antivirus and firewall through the Security Center API,
  Secure Boot, a pending restart, and how old the Defender signatures are. A new **Security**
  score category, and a new GUI view.
- **Drive wear** from the NVMe SMART health log: life remaining, temperature, power-on hours,
  total data written, and the drive's own critical warning.
- **Battery wear** from the battery IOCTLs: design capacity against today's full-charge
  capacity, cycle count, and cell chemistry.
- **The biggest folders** — Downloads, Desktop, Documents, Pictures, Videos, Music, Local app
  data, and Store app data, measured with the same defensive walker TEMP uses.
- **Actionable advice.** Some recommendations now carry a Windows settings page, and the GUI
  shows an **Open setting** button beside them.
- **A history chart** in the GUI: the score over time, drawn from the opt-in local history.

Both wear readings work **without administrator rights** and report **unknown** rather than
guessing. A SATA drive that will not answer the SMART query still reports its model and bus
type, with every wear field blank; a battery whose firmware publishes no capacity produces no
health figure at all.

### About that settings button

**The app opens the page. You make the change. The app itself still changes nothing.**

Opening a Windows Settings page does not change a setting. There is no code in this project
that toggles a switch, fills a field, or clicks a button inside Settings — the button is a
shortcut to the place where *you* could make a change by hand.

It is fenced in tightly:

- it runs only from a deliberate click, never during analysis, scoring or rendering;
- it accepts only an `ms-settings:` URI, matched against a strict pattern; anything else —
  a file, a program, a web address, a different capitalisation — is refused, not repaired;
- the five pages it can ever open are `ms-settings:windowsdefender`, `ms-settings:windowsupdate`,
  `ms-settings:storagesense`, `ms-settings:batterysaver` and `ms-settings:startupapps`;
- it never asks for elevation;
- the console has no equivalent at all.

`tests/test_readonly.py` proves the fence rather than describing it: an audit hook watches
`analyze_pc` and all four renderers and asserts **zero** write-opens, **zero** subprocess or
`os.startfile` events, **zero** sockets and **zero** registry writes, and an `ast` pass
asserts that `open_setting` is the only function in `gui.py` that can reach `os.startfile`.
Details in [SECURITY.md](SECURITY.md).

## The read-only guarantee

The application observes the machine. It does not delete files, write to the registry, stop
or start services, disable startup entries, change power plans, install drivers, or request
administrator rights. The packaged executable ships an `asInvoker` manifest, so Windows never
shows an elevation prompt.

The only files it ever writes are:

1. a report you explicitly asked to export, and
2. the local history file — and only after you switch history on yourself.

Registry access goes through `winreg` with `KEY_READ` only, and every handle is closed in a
`finally`. Every storage IOCTL opens its volume or device with `dwDesiredAccess = 0`
(metadata queries, no read or write access, no elevation). The battery IOCTLs are the one
documented exception: they are `FILE_READ_ACCESS` control codes that reject a zero-access
handle, so `win_battery.py` tries zero access first and falls back to `GENERIC_READ` — still
unelevated, verified from a standard account, and `GENERIC_WRITE` is never requested.

There is no WMI, no COM, no PowerShell, no `wmic`, and no subprocess anywhere in collection,
scoring or rendering: every collector is plain Python over `winreg`, `ctypes`, `psutil`, `os`
and `platform`. The single call that reaches outside the process is the settings button
described above, and it happens only on a click.

The guarantee is taken literally down to the standard library. The TEMP folder is resolved
from the `TMP`, `TEMP` and `TMPDIR` environment variables rather than through
`tempfile.gettempdir()`, because that function proves a folder is usable by creating,
writing and deleting a probe file in it — a real write, and one this application does not
make. Known folders are resolved with `KF_FLAG_DEFAULT`, never `KF_FLAG_CREATE`, so the app
does not create a folder Windows would happily create for it.

Two more rules hold everywhere in the code:

- **A collector never raises.** A platform or permission failure becomes a missing value
  plus a readable warning. Partial data beats a crash.
- **A measurement is never invented.** Unknown stays unknown, renders as `N/A`, and costs
  no score points. That includes a TEMP folder the app cannot look into, a drive that
  refuses the SMART query, and a Security Center that does not answer: each reports an
  unknown, never a comfortable zero and never "you are unprotected".

## Features in v2.1

**Collection**

- Windows edition, display version (for example `24H2`), full build (`26100.9168`) and
  install date, read from the registry
- Board manufacturer, model and BIOS version; OEM placeholder strings such as
  `Default string` are reported as unknown rather than repeated
- Processor marketing name, physical and logical core counts, current and maximum clock
- CPU load overall and per logical core, from a single sampling pass
- RAM total, used, available, plus the Windows page file
- System-drive capacity, usage, filesystem and SSD/HDD media type
- Every fixed partition (up to 12), optical drives and unreadable mounts skipped
- **Drive health per physical disk** (new): model, bus type, media type, life remaining,
  temperature, power-on hours, total data written, and the drive's own critical-warning flag,
  read from the NVMe SMART / Health Information log page. One physical disk answers once,
  however many volumes it carries; a disk that reports nothing is left out rather than
  padding the table with a row of `N/A`. **The drive serial number is deliberately not read.**
- Running process count and the top processes by memory, with PID, RSS, memory share and a
  real CPU percentage — sampled for the listed processes only, one shared 0.15 s pause for
  the whole list, and divided by the logical core count so it matches Task Manager
- User TEMP and, where readable, the machine-wide `%SystemRoot%\Temp`, each with size,
  file count and a "measurement was truncated" flag. The TEMP path is resolved from `TMP`,
  `TEMP` or `TMPDIR`, never through `tempfile.gettempdir()`, which would write a probe
  file. A folder that is missing or that this account may not list reports an **unknown**
  size, not 0 bytes
- **The biggest user folders** (new): Downloads, Desktop, Documents, Pictures, Videos, Music,
  Local app data and Store app data, biggest first, each with size, file count and its own
  truncation flag. Paths come from `SHGetKnownFolderPath`, not from `%USERPROFILE%` joins,
  because Documents and Desktop are routinely redirected into OneDrive and a joined path
  would measure an empty leftover and report a reassuring, wrong number
- Uptime and last boot time
- Battery percentage, charging state and remaining time, plus **battery wear** (new): design
  capacity, full-charge capacity, cycle count and chemistry, with `health_percent` derived
  from the first two and `None` whenever either is missing
- **Windows protection state** (new): antivirus and firewall verdicts from
  `WscGetSecurityProviderHealth`, the firewall profiles that are switched off, Secure Boot,
  a pending restart and why one is owed, Defender's last scan and signature age
- Network traffic counters and link state per interface (up to 8) — **no IP and no MAC
  addresses**
- Graphics adapters (up to 4) with driver version, driver date and adapter memory
- Startup entries (up to 60) from the four `Run`/`RunOnce` keys and both Startup folders

**Analysis**

- Graded health score: **50 rule rows over 17 measurements**, up to four severity tiers per
  measurement instead of one on/off threshold
- Per-area sub-scores for **CPU, Memory, Storage, Maintenance, Power and Security**
- Every deduction states the number it was based on, and a measurement that was cut short
  is quoted as a lower bound ("at least 4.0 GB" / "aspoň 12,0 GB"), never as an exact
  figure. The qualifier is a translated sentence, not text baked into the number
- A category nobody could measure is reported as unavailable, not as a clean 100
- One definition of "complete data", shared by the score, the report and the advice
- **32 rule-based recommendations** whose thresholds and drive are read from the same place
  the score reads them, so advice and score can never contradict each other
- **Every deduction is always accompanied by advice** — including the mild tiers, which are
  covered by `medium_cpu`, `medium_ram`, `medium_swap`, `medium_disk`, `medium_disk_full`,
  `some_processes`, `medium_temp` and `medium_uptime`. No report can take points away and
  then print "No urgent issues were detected"
- **Eleven recommendations carry a Windows settings page** (`action_uri`), which the GUI
  turns into an **Open setting** button. Three deliberately do not: `secure_boot_off` points
  at a firmware switch, and `drive_worn` / `drive_failing` describe physical wear no setting
  can undo. A wrong page is worse than no page

**Interfaces and output**

- Modern CustomTkinter GUI with **six views**, a dark and a light theme, and a score-over-time
  chart in the History view
- Full console interface with progress line, colour, quiet mode and exit codes for scripts
- Four export formats: text, JSON, HTML and Markdown, all worded from the same catalogue
- English and Slovak throughout — the report, every export, the GUI, the console `--help`
  text, the `--show-history` table, and the progress steps of a running analysis. The
  interface is fully bilingual, not bilingual in places
- Opt-in local history with a comparison against the previous run
- Redaction of the Windows account name: `--redact` on the console, a checkbox in the GUI

## Quick start

**Double-click `dist\Apoliak-Vitals.exe`.** That is the whole application: **one file**,
no installer, no Python, no dependency folder. Copy it to a USB stick or another PC and it
works there too. Administrator access is neither required nor requested. It is built by
`build_exe.bat` (see [Rebuilding the executable](#rebuilding-the-executable)).

Windows 10 or 11, 64-bit. Nothing else is needed to *run* the app.

### Running from source instead

Only needed if you want to change the code. Requires Python 3.10 or newer from
[python.org](https://www.python.org/downloads/windows/) (enable **Add Python to PATH**),
plus `psutil` and `customtkinter` — the project's only two dependencies. Everything added in
v2.1 is pure `ctypes`, `winreg` and the standard library; no new dependency was introduced.

```powershell
py -3 -m pip install -r requirements.txt
```

Start the GUI:

```powershell
py -3 gui.py
```

Start the console version:

```powershell
py -3 main.py
```

Export an HTML report without any interactive question:

```powershell
py -3 main.py --output report.html --no-prompt
```

## Console reference

```powershell
.venv\Scripts\python.exe main.py --help
```

The help text itself is translated: `--lang sk --help` prints the whole parser — the
description, every group heading, every option and the exit-code footer — in Slovak. The
language is resolved before argparse is built, so `--lang` is honoured even by `--help`.

So is everything the run prints on the way. `analyze_pc` hands its progress callback a
stable step key rather than an English sentence, and the consumer renders `progress.<key>`
from the catalogue, falling back to `analyzer.PROGRESS_LABELS[key]`. The thirteen steps are
`system`, `cpu`, `ram`, `disk`, `partitions`, `drive_health`, `processes`, `top_processes`,
`temp`, `folders`, `security`, `extras` and `done`. Under `--lang sk` the progress line reads
`[ 35%] Načítavam využitie pamäte`, not `[ 35%] Reading memory usage`; the GUI reads the same
keys.

The v2.1 collectors have **no console flags of their own**: security, drive health and the
folder scan are always on for a console run, exactly as `analyze_pc` defaults them. The
option set below is unchanged from v2.0 and matches `main.py --help` exactly.

### Analysis options

| Option | Default | Effect |
|---|---|---|
| `--cpu-sample-seconds SECONDS` | `1` | CPU sampling interval, 0 to 5 seconds. Outside that range the run stops with exit code 2. One `percpu` pass serves both the overall figure and the per-core list, so the interval is paid once. |
| `--top N` | `5` | How many top processes to collect. `0` disables the list and skips the CPU sampling with it. Any other value adds one shared 0.15 s pause. |
| `--no-temp-scan` | off | Skip the TEMP measurement entirely. TEMP size then reads `N/A` and costs no points. |
| `--temp-scan-seconds SECONDS` | `12` | Wall-clock budget for the TEMP folders, split evenly between the ones that will be measured. A scan that runs out is reported as truncated, never as a smaller number. |
| `--no-startup` | off | Skip startup-entry collection. |
| `--no-gpu` | off | Skip graphics-adapter collection. |

### Output options

| Option | Default | Effect |
|---|---|---|
| `--format {text,json,html,markdown}` | `text`, or inferred from the export path | Output format. |
| `--export [PATH]` | off | Export the result. Without a path an auto-named `apoliak_vitals_report_YYYYMMDD_HHMMSS.<ext>` file lands in the current folder; if that name is taken, `_2`, `_3`, … is appended rather than overwriting. |
| `--output PATH` | none | Explicit destination. Implies `--export` and wins over it. The path you name is written as given — overwriting is what naming a file means. A directory is accepted and gets a generated, collision-free name. |
| `--no-prompt` | off | Never ask anything interactively. |
| `--redact` | off | Mask the Windows account name everywhere in the output, including paths. |
| `--lang {en,sk}` | detected | Language of the report, the messages and `--help`. Detection order: `APOLIAK_LANG`, then the OS locale, then English. |
| `--color {auto,always,never}` | `auto` | Terminal colour. Escape codes never reach an exported file. `NO_COLOR` and `FORCE_COLOR` are honoured in `auto` mode. |
| `--quiet` | off | Print only the score line. The progress indicator and the status notes ("Report saved to …") are suppressed with it; a requested export still happens. |
| `--fail-under N` | none | Exit with code 3 when the score is below N (0–100). |
| `--version` | — | Print the version and exit. |

### History options (opt-in)

| Option | Default | Effect |
|---|---|---|
| `--save-history` | off | Append this run to the local history file. Nothing is written without it. |
| `--history-path PATH` | `%LOCALAPPDATA%\Apoliak\Vitals\history.jsonl` | Use a different history file. |
| `--show-history [N]` | off, `10` when bare | Print the last N stored runs and exit. `0` shows all. The table header follows `--lang`. This path touches no system API at all. |
| `--compare` | off | Show the change against the previous stored run. Read before this run is stored, so "previous" can never be this same run. |

### Exit codes

| Code | Meaning |
|---:|---|
| 0 | Success |
| 1 | Runtime failure (analysis, scoring, rendering, export, or a missing `psutil`) |
| 2 | Invalid arguments |
| 3 | Score below `--fail-under` |

Exit code 1 covers a renderer or exporter defect too: the console prints the ordinary
"Analysis failed safely: …" line on stderr instead of a traceback. The same table is
printed at the bottom of `--help`, in the chosen language.

Examples:

```powershell
# machine-readable output on stdout, status lines kept off it
.venv\Scripts\python.exe main.py --format json --no-prompt > snapshot.json

# one line, suitable for a scheduled check
.venv\Scripts\python.exe main.py --quiet --no-prompt --fail-under 60

# shareable HTML with the account name masked
.venv\Scripts\python.exe main.py --output report.html --redact --no-prompt

# store this run and print how it moved since last time
.venv\Scripts\python.exe main.py --save-history --compare --no-prompt
```

## The GUI

The window has a sidebar (analyze, export format, export, copy to clipboard, **Redact
personal data**, language, theme) and **six views**. The analysis runs on a daemon worker
thread and reports back through a queue; only the Tk main thread ever touches a widget, so
the window stays responsive and shows a progress line — named step by step, in the language
selected in the sidebar. Nothing in the interface can change the machine — the process view
deliberately has no "end task" button, and the Security view reports the protection state
without offering to alter it.

**Redact personal data** is the GUI equivalent of `--redact`. It is off by default and sits
with the export controls, because that is the only moment it matters: the snapshot on
screen never leaves the PC, an exported or copied report does. When it is ticked, every
export format *and* the clipboard copy carry `<user>` instead of the account name. If a
writer is ever too old to honour redaction, the export is refused rather than written
unmasked.

| View | Contents |
|---|---|
| **Overview** | Health score with its progress bar, the **six** category sub-scores, nine metric cards (System, Processor, Memory, System Drive, Activity, Temporary Files, Battery, Network, Graphics), the score deductions, and the recommendations. |
| **Processes** | The top processes sorted by memory use — name, PID, memory, memory share and CPU %. Read-only list. |
| **Storage** | Three cards: every fixed drive and partition with capacity, used and free space, usage, filesystem and SSD/HDD type; **drive health** (model, bus, life left, temperature, power-on hours, data written, critical warning); and the **biggest folders** with size, file count and path. |
| **Security** | New in v2.1. Antivirus, Firewall, Secure Boot, Restart Pending, Definitions Age and Last Scan, each with a good / needs-attention / unknown pill, plus the security deductions and the security advice. When the Security Center did not answer, the view says so — "unknown rather than off". The read-only promise is repeated here, where a reader is most likely to doubt it. |
| **System** | Operating system, firmware, graphics adapters, startup entries, and the analysis warnings from this run. |
| **History** | The opt-in checkbox, the history file path, a **score-over-time chart** drawn on a canvas from the stored runs, and the runs themselves newest first. While the box is unchecked nothing is written to disk. |

Every recommendation that carries a Windows settings page gets an **Open setting** button on
its row, in the Overview and in the Security view. A caption under the list states the
boundary: *"Opens the matching Windows settings page. Nothing is changed for you."* A
successful open reports *"Windows opened the settings page. Nothing was changed."*

Language and theme switch live from the sidebar; the whole window re-renders in place, and
the chart redraws at the real canvas width after every resize.

## Export formats

| Format | Extension | Notes |
|---|---|---|
| `text` | `.txt` | The same renderer the console uses, without colour. UTF-8. |
| `json` | `.json` | The full versioned snapshot (`schema_version` `2.1`), indented, `ensure_ascii=False`. Stable key layout so an old export still reads in a later version. Deduction and recommendation sentences are resolved through the same catalogue the other three use. Carries an `export_errors` list — empty on a healthy export. |
| `html` | `.html` | A single self-contained document: inline CSS, no fonts, no images, no scripts, no external requests. Safe to e-mail. |
| `markdown` | `.md` | Tables and sections, for pasting into a ticket or a wiki. |

The format is taken from `--format`, otherwise inferred from the export file extension
(`.txt`, `.text`, `.json`, `.html`, `.htm`, `.md`, `.markdown`), otherwise `text`. An
unknown format name is the one thing the renderer raises for, and it raises `ValueError`.

Two guarantees hold across all four:

- **One wording.** `src/i18n.py` is the single source of the rendered text. A renderer
  called without a language falls back to the catalogue's English, not to the sentence its
  producer happened to build, so the JSON, text, HTML and Markdown of one run always
  describe a finding with the same words and the same numbers.
- **A renderer never crashes the run.** All four documents — JSON included — are assembled
  section by section behind their own guard; one damaged measurement costs that section a
  one-line apology, not the export. In JSON that section is written as `null` and names
  itself in `export_errors`, so a reader can tell "nobody measured this" from "nobody could
  write this"; every branch is also proved serialisable before it is returned, so a hostile
  *type* is caught in the same net as a hostile value. If the whole render fails anyway, the
  console reports it as a failed run with exit code 1.

### What changed in the JSON shape

`schema_version` is now `"2.1"`. Nothing was removed or renamed — an existing reader keeps
working — and three top-level keys were added, in this document order:

```text
schema_version, generated_by, analyzed_at, system, cpu, ram, disk, partitions,
drive_health, processes, temp, folder_usage, uptime_seconds, battery, network,
gpus, startup_items, security, health, recommendations, warnings, export_errors
```

- **`drive_health`** — a list, one entry per physical disk that answered:
  `drive, model, bus_type, media_type, percentage_used, life_left_percent,
  temperature_celsius, power_on_hours, data_written_bytes, critical_warning, source`.
  `life_left_percent` is the derived `100 − percentage_used`, written out so a reader does
  not have to know the formula. Empty when nothing could be read. **No serial number.**
- **`folder_usage`** — a list, biggest first: `key, label, path, size_bytes, file_count,
  truncated`. `size_bytes: null` means the folder could not be measured, which is not the
  same as `0`.
- **`security`** — an object: `antivirus, antivirus_name, firewall, secure_boot,
  reboot_pending, defender_last_scan, signature_age_days, details`. The three verdict fields
  carry `"good"`, `"weak"`, `"bad"` or `"unknown"`. `details` is a list of `{key, value}`
  pairs — currently `firewall_profiles_off`, `reboot_sources` and `security_center`.
  `antivirus_name` is always `null`: the product name needs COM/WMI, which this project does
  not use, and guessing it would be an invention.

Two existing objects gained fields, both optional and both `null` when unknown:

- **`battery`** gained `design_capacity_mwh`, `full_charge_capacity_mwh`, `cycle_count`,
  `chemistry` and the derived `health_percent`.
- each entry of **`recommendations`** gained `action_uri` — the `ms-settings:` page this
  advice is about, or `null`. It is data for a reader to look at; no exporter follows it.

## Health score

The score starts at 100 and only ever loses points to a rule in the table below. All **50
rows** are a public statement of "this measurement, past this threshold, costs this many
points", and every deduction printed in the report quotes the number it was based on.

Three properties are load-bearing:

- **An unknown measurement never costs points.** Its rule stays unevaluated and its
  category is reported as unavailable, so no interface reports a clean bill of health it
  never earned.
- **Only one tier of a rule can fire** — the worst one crossed. Tiers are alternatives,
  never cumulative.
- **The six v1.0 thresholds are preserved as anchors.** CPU above 70% (15 points), RAM
  above 80% (20), free space below 20 GB (20), more than 180 processes (10), TEMP above
  3 GB (10) and uptime past 48 hours (5) are exactly what v1.0 published, and they are the
  `standard` tier of their rule. v2.0 surrounded each anchor with milder and harsher tiers,
  and v2.1 added new rules beside them without touching one.

| Measurement | Condition | Tier | Points | Severity |
|---|---|---|---:|---|
| CPU usage | above 55% | mild | 6 | info |
| | above 70% | standard | 15 | warning |
| | above 85% | high | 22 | warning |
| | above 95% | severe | 28 | critical |
| RAM usage | above 70% | mild | 8 | info |
| | above 80% | standard | 20 | warning |
| | above 90% | high | 28 | critical |
| | above 95% | severe | 34 | critical |
| Page file usage | above 50% | mild | 4 | info |
| | above 75% | standard | 10 | warning |
| | above 90% | severe | 16 | critical |
| Free system-drive space | below 50.0 GB | mild | 8 | info |
| | below 20.0 GB | standard | 20 | warning |
| | below 10.0 GB | high | 26 | critical |
| | below 5.0 GB | severe | 32 | critical |
| System-drive usage | above 85% | mild | 5 | info |
| | above 92% | standard | 12 | warning |
| | above 97% | severe | 18 | critical |
| Running processes | above 150 | mild | 4 | info |
| | above 180 | standard | 10 | warning |
| | above 250 | high | 14 | warning |
| | above 350 | severe | 18 | warning |
| TEMP folder size | above 1.0 GB | mild | 4 | info |
| | above 3.0 GB | standard | 10 | warning |
| | above 10.0 GB | high | 14 | warning |
| | above 25.0 GB | severe | 18 | warning |
| System uptime | above 1 day | mild | 2 | info |
| | above 2 days | standard | 5 | warning |
| | above 7 days | high | 8 | warning |
| | above 14 days | severe | 10 | warning |
| Startup entries | above 12 | mild | 3 | info |
| | above 20 | standard | 6 | warning |
| | above 30 | severe | 10 | warning |
| Battery charge on battery | below 25% | mild | 2 | info |
| | below 15% | standard | 4 | warning |
| | below 7% | severe | 6 | critical |
| **Antivirus protection** | at risk or worse | standard | 30 | critical |
| | off | severe | 40 | critical |
| **Firewall protection** | at risk or worse | standard | 12 | warning |
| | off | severe | 18 | warning |
| **Antivirus signature age** | above 7 days | standard | 8 | warning |
| | above 30 days | severe | 14 | warning |
| **Pending Windows restart** | is pending | standard | 3 | info |
| **Drive self-assessment** | is failing | standard | 25 | critical |
| **Drive life remaining** | below 30% | mild | 4 | info |
| | below 20% | standard | 10 | warning |
| | below 10% | severe | 18 | critical |
| **Battery capacity remaining** | below 70% | mild | 3 | info |
| | below 60% | standard | 6 | warning |
| | below 50% | severe | 10 | warning |

Sizes are binary: `20.0 GB` means 20 GiB, the number Windows shows.

The protection verdicts sit on a ladder — `good` = 0, `weak` = 1, `bad` = 2 — and the two
security thresholds (0.5 and 1.5) mean "at risk or worse" and "off". `unknown` is not on the
ladder at all, so it can never fire a rule.

The table is generated from a single source and can be printed at any time:

```powershell
.venv\Scripts\python.exe -c "from src.health_score import score_rules
for r in score_rules(): print(r.key, r.tier, r.points, r.condition)"
```

### Secure Boot costs nothing, on purpose

Secure Boot is collected, reported, and — when it is off — answered with one line of advice.
There is deliberately **no deduction row for it**. It is switched off for many legitimate
reasons, a dual-boot machine and older firmware among them, and taking points away for that
would be dishonest. The advice says so in as many words.

### The score guards

- **Free space and percent-full are not charged twice.** They describe the same drive from
  two angles, so when the free-bytes rule fires, the percentage rule is dropped. The
  percentage rule therefore only covers what the byte rule misses: a large drive that is
  nearly full yet still has more than 20 GB free.
- **A page file smaller than 1 GiB is not scored at all.** A 256 MB page file sits at 95%
  on a perfectly healthy PC, so its percentage says nothing.
- **Battery charge is only a finding while the PC is actually discharging.** A plugged-in
  laptop at 20% is charging, not in trouble.
- **One deduction per snapshot for drive wear, not one per disk.** A PC with two worn drives
  has one problem to act on, and charging twice for it would make the score depend on how
  many disks are fitted. `most_worn_drive()` picks the worst one and the advice imports the
  same selector, so both name the same drive.
- **"No drive told us" is not "every drive is fine".** The drive self-assessment metric stays
  unknown until at least one disk actually answered the question, so Storage is only reported
  as measured when something really was measured.

### No deduction without advice

`src/recommendations.py` reads its thresholds out of `SCORE_RULES` itself, and it covers
every tier that costs points, mild tiers included. The invariant is absolute:

- **no deduction key is ever emitted without a recommendation covering the same
  condition** — a RAM reading of 72% loses 8 points *and* prints `medium_ram`, and every new
  v2.1 rule (`antivirus_off`, `firewall_off`, `stale_signatures`, `reboot_pending`,
  `drive_worn`, `drive_failing`, `battery_worn`) has its own recommendation key too;
- **`all_good` is only ever emitted alone.** It cannot appear next to a deduction, because
  it is only added when nothing else was found;
- the mild tiers are served by `medium_cpu` (above 55%), `medium_ram` (above 70%),
  `medium_swap` (above 50%), `medium_disk` (below 50 GB free), `medium_disk_full` (above
  85%), `some_processes` (above 150), `medium_temp` (above 1 GB) and `medium_uptime`
  (above 1 day), all at severity `info`;
- advice for the drive follows the score's own suppression rule, so a run that deducts for
  free bytes never answers with a percent-full sentence, and vice versa.

Two recommendations exist without any deduction behind them, by design: `secure_boot_off`
(explained above) and `large_folder`, which fires when the biggest measured folder is over
20 GiB **or** over 10% of the drive it sits on. Both are needed — 20 GB is a lot on a 256 GB
laptop and unremarkable on a 4 TB desktop. The TEMP folder is excluded from that pick,
because it already has its own finding and reporting one measurement as two problems would
be double-counting.

Recommendation quoting follows the same honesty rule as the deductions: when a scan was
truncated, `large_temp`, `medium_temp` and `large_folder` quote the size as a floor too. One
run never states the same measurement two ways.

### When the data is incomplete

`data_complete` has exactly one definition, in `health_score.required_values_present()`.
It is true when all six of CPU usage, RAM usage, free disk space, process count, TEMP size
and uptime were measured **and the TEMP scan was not truncated**. Everything that talks
about completeness reads that one predicate: the `Data Complete` line in every report and
export, `HealthAssessment.data_complete`, and the `incomplete_data` recommendation — which
fires when the run produced warnings *or* the predicate is false.

The v2.1 collectors deliberately do **not** enter that predicate. A desktop has no battery,
a SATA drive publishes no wear figure, and a locked-down machine may not answer the Security
Center — none of those is an incomplete *analysis*, and marking the snapshot incomplete for
them would make the flag meaningless.

Two things about the TEMP folder can make it false.

**A scan that ran out of its time budget** is not a measurement:

- the snapshot carries `temp_truncated = true`, and every export surfaces it — the reports
  label the size "(partial scan)" and add one explanatory line, the JSON sets
  `temp.truncated`;
- the score still charges the `large_temp` rule if the partial size already crosses a
  threshold. A partial size can only be too small, so firing on it is never a false alarm
  and the deduction is at worst too mild;
- but the deduction, its advice and its parameters read as a floor — "The TEMP folder holds
  a lot of data (at least 12.0 GB)." — never as an exact total the app did not finish
  counting. The qualifier is stored as a language-neutral `bound` parameter and worded by
  the renderer, so the Slovak report reads "(aspoň 12.0 GB)" and no format has to invent
  its own phrasing;
- and `data_complete` goes false, so the reader is told the snapshot is a floor rather than
  a full picture.

**A TEMP folder that cannot be looked into** is not a measurement either. A path that is
missing, is not a directory, or that this account may not list is reported with
`size_bytes = null` — unknown, not zero — plus a warning naming the folder. It costs no
score points, and `data_complete` goes false. This matters because `TMP` is taken from the
environment as given: a broken `TMP` used to be scored as a spotlessly clean TEMP folder,
which was the one place the app invented a measurement.

### How long a run takes

The two folder scans share one wall-clock budget, `analyzer.TOTAL_SCAN_SECONDS` = 8 seconds.
TEMP goes first and normally finishes well inside its half; whatever it leaves is handed to
the biggest-folders scan, which is guaranteed at least one second whatever TEMP did. Adding
the folder measurement in v2.1 therefore cannot double the length of a run.

The console overrides the TEMP half with `--temp-scan-seconds` (12 s by default), so a CLI
run can spend longer on TEMP than the GUI does; the folder scan still gets the remainder of
the 8-second budget, floored at one second. Everything else in an analysis costs about a
second and a half plus the CPU sampling interval.

### Score bands

| Score | Status |
|---:|---|
| 90–100 | Excellent |
| 75–89 | Good |
| 50–74 | Needs Optimization |
| 0–49 | Poor |

This score is a snapshot, not a benchmark and not a diagnosis. A high CPU reading is
perfectly normal while a game, an update or a render is running. When a metric could not be
read, the report says the data was incomplete rather than pretending the measurement
succeeded.

## Languages

The interface, the report, every export, the console `--help`, the `--show-history` table
and the progress steps ship in **English** and **Slovak** (with full diacritics), **418 keys**
each, with identical placeholders per key. The language is chosen in this order:

1. the `--lang` option, or the GUI sidebar;
2. the `APOLIAK_LANG` environment variable;
3. the operating-system locale;
4. English.

```powershell
$env:APOLIAK_LANG = "sk"
.venv\Scripts\python.exe main.py
```

The catalogue is the single source of the rendered wording. A renderer asked for no
language does not print its own English sentence; it loads the catalogue's English, so two
formats of one run can never word the same finding differently. A missing key falls back to
the caller's English default instead of breaking a report, and a placeholder nobody could
supply a value for disappears together with its parenthetical rather than printing `(N/A)`.

Counted phrases are declined by the language, not by the renderer. Slovak needs three
forms where English needs two — 1 `bod`, 2–4 `body`, 0 and 5 upwards `bodov` — so the
report prints "− 3 body" and "− 5 bodov", not the wrong "− 3 bodov".

Qualifiers are translated for the same reason. A producer that could only put a floor under
a number attaches a `bound` parameter instead of writing "at least" into the value, and the
shared renderer resolves it through `report.at_least` — so the English report says
"at least 12.0 GB" and the Slovak one "aspoň 12.0 GB" from one and the same snapshot.

Every shipped key has a call site. A string in the catalogue is a promise that the product
shows it somewhere; keys that no longer had one were removed rather than left to look like
a feature.

## Local history (opt-in)

History is off by default. Nothing is written until you pass `--save-history` on the
console or tick **Save this analysis locally** in the GUI's History view.

- Location: `%LOCALAPPDATA%\Apoliak\Vitals\history.jsonl`
  (on systems without `%LOCALAPPDATA%`, the same path under your home folder)
- Format: JSON Lines, one small object per run, newest last
- Retention: the newest 200 runs; older records are dropped on the next append
- Contents: nine fields — timestamp, score, status, CPU %, RAM %, free disk bytes, TEMP
  bytes, process count and uptime. **No paths, no process names, no host name, no serial
  numbers, no account name.** The v2.1 collectors add nothing to the file: drive wear,
  battery wear, folder sizes and the protection state are not stored
- Order: `--show-history` prints oldest first; the GUI's History view lists newest first and
  draws the same runs as a score-over-time chart

The file is rewritten through a sibling temporary file and an atomic replace, so an
interrupted run cannot destroy it, and unparsable lines are skipped rather than fatal.
Deleting the file is always safe.

```powershell
.venv\Scripts\python.exe main.py --save-history --no-prompt   # store this run
.venv\Scripts\python.exe main.py --show-history 20            # print the last 20 runs
.venv\Scripts\python.exe main.py --compare --no-prompt        # change since the last run
```

## Privacy

The analyzer sends nothing anywhere. There is no telemetry, no update check, and no network
call of any kind — the HTML export is self-contained precisely so that opening a report
cannot reach out either. Network collection reads traffic counters and link state only:
**no IP address and no MAC address is ever collected**, in any format, redacted or not.

**No serial number, MAC address, IP address or machine identifier is collected anywhere.**
The storage device descriptor carries a serial number and `win_storage.py` deliberately steps
over that field; `psutil.net_if_addrs` is never called; there is no product key, machine GUID
or hardware-hash lookup in the project. The drive *model* and bus type are collected, and
they describe a component that is identical across every unit of that model — the serial,
which would identify this machine, is the part that is skipped.

An exported report can still contain identifying detail: your TEMP and user-folder paths
(which include the Windows account name), process names, startup-entry names, network
interface names, the machine manufacturer, model and BIOS version, the drive model, and the
protection state of this PC. The **JSON export additionally carries the full startup-entry
command lines**, which usually contain installed application paths; the text, HTML and
Markdown reports list startup entries by name and source only.

Redaction masks the account name — both the `C:\Users\<name>` segment, wherever it appears,
and any other occurrence of the name — throughout the report, the recommendations, the
warnings, the startup commands, the folder paths and the printed destination paths. It is
available in both interfaces:

- console: `--redact`;
- GUI: the **Redact personal data** checkbox in the sidebar, off by default, applied to
  every export format and to the clipboard copy.

It masks the account name; it does not anonymise the machine. The model, the BIOS version,
the drive model, the startup command lines and the process names survive redaction. Review a
report before sharing it. Details are in [SECURITY.md](SECURITY.md).

## Tests

The suite uses only Python's standard-library runner. **948 tests** across sixteen modules,
of which 2 skip themselves when the account may not create symbolic links — the default on
Windows outside Developer Mode:

```powershell
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

| Module | Tests |
|---|---:|
| `test_analyzer.py` | 141 |
| `test_exporters.py` | 111 |
| `test_health_score.py` | 100 |
| `test_cli.py` | 71 |
| `test_recommendations.py` | 70 |
| `test_i18n.py` | 62 |
| `test_win_storage.py` | 59 |
| `test_folder_usage.py` | 55 |
| `test_win_security.py` | 55 |
| `test_report.py` | 47 |
| `test_gui.py` | 38 |
| `test_win_battery.py` | 37 |
| `test_utils.py` | 34 |
| `test_history.py` | 29 |
| `test_models.py` | 27 |
| `test_readonly.py` | 12 |

Collectors take an optional `psutil_module` argument or an injectable reader, and the
renderers take an optional translator, so the tests pass fakes instead of touching the real
machine. The Win32 modules put their plumbing behind small seams — `_load_kernel32`,
`_open_device`, `_device_io_control`, `_load_api`, `_load_shell_api`, `provider_health` — so
a test replaces the operating system wholesale, while every buffer decoder is a pure
`bytes → value` function that needs no hardware at all. Each new collector is also asserted
to return a safe empty value with `platform.system()` monkeypatched to `"Linux"`.

`test_gui.py` exercises the window's pure helpers without opening one, so the suite needs no
display. `test_readonly.py` is the audit-hook suite described in
[SECURITY.md](SECURITY.md#4-the-proof-the-audit-hook-test); it runs a child interpreter, so
the cost of an always-on audit hook is paid once and leaves with that process.

## Rebuilding the executable

Double-click `build_exe.bat`. It is the only script in the project: it creates a private
`.venv`, installs the build requirements, runs the full test suite, and only then builds.
A failing test stops the build.

The output is **a single file**, `dist\Apoliak-Vitals.exe` (~11 MB), which carries the
icon, the version resource, and `app.manifest` — the manifest requests `asInvoker`, so the
app never asks for elevation. UPX compression is deliberately disabled, because compressed
PyInstaller binaries are a well-known false-positive trigger for antivirus heuristics.

The build must run on Windows: PyInstaller builds for the platform it runs on.

## Project structure

```text
Apoliak-Vitals/
├── src/
│   ├── __init__.py          # lazy submodule resolution, so one layer never drags in another
│   ├── analyzer.py          # read-only collection, analyze_pc, PROGRESS_LABELS
│   ├── win_registry.py      # KEY_READ registry lookups: edition, firmware, GPUs, startup
│   ├── win_security.py      # Security Center + KEY_READ: antivirus, firewall, Secure Boot
│   ├── win_storage.py       # query-only IOCTLs: drive model, bus, NVMe SMART wear
│   ├── win_battery.py       # battery IOCTLs: design vs full-charge capacity, cycles
│   ├── folder_usage.py      # SHGetKnownFolderPath + the shared walker: biggest folders
│   ├── processes.py         # read-only process ranking, memory and CPU
│   ├── models.py            # frozen typed snapshot models, SCHEMA_VERSION = "2.1"
│   ├── health_score.py      # the graded score table, the sub-scores, "complete data"
│   ├── recommendations.py   # safe advice, thresholds and settings pages
│   ├── i18n.py              # English and Slovak strings, incl. plural forms
│   ├── report.py            # plain-text renderer and the shared bound/label resolution
│   ├── exporters.py         # text / JSON / HTML / Markdown
│   ├── history.py           # opt-in local JSON Lines history
│   └── utils.py             # formatting, redaction, and the defensive folder walker
├── tests/                   # 948 unit tests in sixteen modules plus shared fakes in helpers.py
├── docs/
│   ├── architecture.md      # module map, threading, failure behaviour
│   └── roadmap.md           # what is done and what comes next
├── dist/
│   └── Apoliak-Vitals.exe   # the built application: one file, nothing else needed
├── main.py                  # console entry point
├── gui.py                   # graphical entry point
├── build_exe.bat            # the only script: venv, dependencies, tests, single-file build
├── Apoliak_Vitals.spec # PyInstaller spec for that one executable
├── app.ico                  # application icon, also shown on the window and taskbar
├── app.manifest             # asInvoker, DPI aware, long-path aware
├── version_info.txt         # Windows file-version resource
├── requirements.txt         # psutil, customtkinter
├── requirements-build.txt   # the above plus PyInstaller
├── pyproject.toml           # packaging metadata and the ruff configuration
├── CHANGELOG.md
├── SECURITY.md              # the read-only guarantee in detail
├── START_HERE_SK.md         # short Slovak guide for non-technical users
├── PROJECT_PLAN.md          # the original brief
└── LICENSE
```

## Philosophy

> Every tweak is explained. Every change is reversible.

Version 2.1 still only analyzes and recommends. The one thing it can make happen outside
itself is opening a Windows Settings page when you click a button — which shows you where a
setting lives and changes nothing. Actually changing a setting is not a refactor away: it is
a new module behind its own boundary, with confirmation, a preview of the exact change, a
restore path, and its own tests. The rules for that are written down in `docs/roadmap.md`
and `SECURITY.md`.

## License

MIT — see [LICENSE](LICENSE).
