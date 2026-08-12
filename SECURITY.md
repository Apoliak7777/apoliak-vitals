# Security policy

## Read-only guarantee for v2.1

Apoliak Vitals observes the machine. It does not:

- delete or modify any file, including TEMP files;
- write, create, or delete a registry value or key;
- disable Defender, the firewall, Windows Update, services, scheduled tasks, or startup
  entries;
- terminate, suspend, or change the priority of a process;
- change power plans, network settings, or any other persistent Windows setting;
- install drivers or software;
- request administrator privileges;
- execute an optimization command, a script, or any subprocess during analysis or export;
- reach the network, phone home, or check for updates.

The packaged executable carries `app.manifest` with `asInvoker`, so Windows never shows an
elevation prompt. The application does not need one and cannot use one.

v2.1 adds four new state collectors — Windows protection status, drive wear, battery wear,
and the biggest-folders scan — and one, and only one, thing the application may ask the
operating system to do. Both are specified below, and both are asserted by tests rather than
promised in prose.

## 1. The complete read surface

Every row is a query. Nothing in this table has a write mode, and nothing in it needs
administrator rights.

### Registry — `winreg`, `KEY_READ` only

| Reads | Key | Module |
|---|---|---|
| Windows edition, display version, build, install date | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `win_registry.py` |
| Firmware: manufacturer, model, BIOS version | `HKLM\HARDWARE\DESCRIPTION\System\BIOS` | `win_registry.py` |
| Processor marketing name | `HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0` | `win_registry.py` |
| Graphics adapters (max 4, max 32 subkeys enumerated) | the display-adapter driver class key under `HKLM\SYSTEM\CurrentControlSet` | `win_registry.py` |
| Startup entries (max 60) | the four `Run` / `RunOnce` keys (HKCU and HKLM) | `win_registry.py` |
| Firewall profile switches | `HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{Domain,Standard,Public}Profile` → `EnableFirewall` | `win_security.py` |
| Secure Boot switch | `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State` → `UEFISecureBootEnabled` | `win_security.py` |
| Pending restart, servicing | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending` (existence only) | `win_security.py` |
| Pending restart, Windows Update | `HKLM\SOFTWARE\…\WindowsUpdate\Auto Update\RebootRequired` (existence only) | `win_security.py` |
| Pending file renames | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager` → `PendingFileRenameOperations` (presence only; the queued paths are not reported) | `win_security.py` |
| Defender signature age and last scan time | `HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates` and `…\Windows Defender\Scan` | `win_security.py` |

Every key in the project is opened through a helper that passes `KEY_READ`, returns `None`
instead of raising, and closes the handle in a `finally` block — `win_registry._open_key`
and `win_security._open_key`. There is no `winreg.SetValue`, `SetValueEx`, `CreateKey`,
`DeleteKey`, `DeleteValue`, `SaveKey`, or `LoadKey` call anywhere in the codebase, and the
audit-hook test in section 4 proves that at runtime, including inside `psutil` and `ctypes`.

### Windows Security Center — `wscapi.dll`

`win_security.py` calls exactly one function: `WscGetSecurityProviderHealth`, once for the
firewall provider (`0x1`) and once for the antivirus provider (`0x4`). It is a health query;
it has no counterpart that changes a provider, and the module never loads any other symbol
from `wscapi.dll`.

The Security Center is used instead of a Defender-specific registry probe because it also
covers third-party antivirus. What it cannot supply is the product *name* — that needs
COM/WMI, which this project does not use — so `antivirus_name` is always `None` rather than
a guess. Reporting "Windows Defender" merely because Defender ships with Windows would be an
invention; the reference machine for this release has no Defender installed at all.

A provider that answers `NOTMONITORED`, a `wscapi.dll` that will not load, and a non-Windows
host all produce `unknown`, which the score never penalises. A failed query never becomes
"this machine is unprotected".

### Storage IOCTLs — `kernel32.CreateFileW` + `DeviceIoControl`

Volumes (`\\.\C:`) and physical devices (`\\.\PhysicalDrive0`) are opened with
**`dwDesiredAccess = 0`**. That grants metadata queries only: not read access, not write
access, and no administrator rights. Every handle is closed in a `finally` block.

| IOCTL | Property | Returns | Module |
|---|---|---|---|
| `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` (`0x560000`) | — | the physical disk number behind a drive letter | `win_storage.py` |
| `IOCTL_STORAGE_QUERY_PROPERTY` (`0x2D1400`) | `StorageDeviceProperty` | model (vendor + product) and bus type | `win_storage.py` |
| `IOCTL_STORAGE_QUERY_PROPERTY` | `StorageDeviceProtocolSpecificProperty` → NVMe SMART / Health Information log page `0x02` | wear percentage used, temperature, power-on hours, data written, critical warning | `win_storage.py` |
| `IOCTL_STORAGE_QUERY_PROPERTY` | `StorageDeviceSeekPenaltyProperty` | SSD / HDD classification | `analyzer.detect_media_type` |

All four are `FILE_ANY_ACCESS` control codes, which is why a zero-access handle can issue
them. `PROPERTY_STANDARD_QUERY` is the only query type used; `PropertySet` is never sent.

**The serial number is deliberately not read.** `STORAGE_DEVICE_DESCRIPTOR` carries it at
offset 24, and `win_storage.py` documents that offset only to record that it is skipped. The
module reads the vendor, product, and bus-type fields and nothing else from that buffer.

A SATA drive or a controller that rejects the NVMe log page leaves every wear field `None`;
the row still reports model, bus type, and media type. Nothing is estimated from a refused
query.

### Battery IOCTLs — `setupapi.dll` + `kernel32`

`win_battery.py` enumerates the present battery interfaces with `SetupDiGetClassDevs`
(`GUID_DEVCLASS_BATTERY`, `DIGCF_PRESENT | DIGCF_DEVICEINTERFACE`), opens the returned device
path, and issues two query IOCTLs: `IOCTL_BATTERY_QUERY_TAG` (`0x294040`) and
`IOCTL_BATTERY_QUERY_INFORMATION` (`0x294044`) at level `BatteryInformation`. Both are
`METHOD_BUFFERED` / `FILE_READ_ACCESS` queries. It reads design capacity, full-charge
capacity, cycle count, and chemistry; nothing else, and nothing is written back.

**This is the one place in the project where a device handle is opened with more than zero
access, and it is stated rather than hidden.** The battery control codes are
`FILE_READ_ACCESS`, so a zero-access handle opens fine and then fails the IOCTL with
`ERROR_ACCESS_DENIED` — measured on the reference laptop. `_ACCESS_LEVELS = (0, GENERIC_READ)`
therefore tries zero access first and falls back to `GENERIC_READ`, which is the minimum
Windows accepts here. `GENERIC_READ` on a battery interface needs **no administrator
rights**; it was verified from a standard, unelevated account. `GENERIC_WRITE` is never
requested, elevation is never asked for, and a machine that still refuses the query simply
reports nothing.

`BATTERY_CAPACITY_RELATIVE` packs report capacities on a scale the firmware never publishes.
Reporting those as mWh would be a made-up unit, so they are dropped and only the unit-free
fields are kept.

### Known folders — `shell32.SHGetKnownFolderPath`

`folder_usage.py` resolves Downloads, Desktop, Documents, Pictures, Videos, Music, Local app
data, and `…\AppData\Local\Packages` through `SHGetKnownFolderPath` with
**`KF_FLAG_DEFAULT`**. `KF_FLAG_CREATE` and `KF_FLAG_INIT` are never passed: this application
does not create folders, not even the ones Windows would happily create for it. The path
buffer is released with `CoTaskMemFree`, as the API requires.

Known folders are used rather than `%USERPROFILE%` joins because these folders really do
move — Documents and Desktop are routinely redirected into OneDrive — and a joined path would
measure an empty leftover directory and report a reassuring, wrong number. An environment
join remains only as the fallback for a failed shell call.

Measurement itself is `utils.scan_folder`: `os.scandir` plus `entry.stat()`, nothing opened,
nothing read, symbolic links and Windows reparse points never followed, unreadable entries
skipped. A folder that exists but cannot be listed reports `size_bytes = None` — unknown,
which is not the same as empty, and is never scored. A folder that is not there at all is
left out entirely.

### psutil and the standard library

| Reads | Access |
|---|---|
| CPU load overall and per core, frequency, core counts | `psutil` |
| RAM, page file, disk usage, partitions, process count, boot time, battery charge and plug state, network counters and link state | `psutil` |
| Top processes: PID, name, RSS, memory share, CPU share | `psutil.process_iter`, `Process.cpu_percent()` — the kernel's own accounting counters. No control method (`terminate`, `kill`, `suspend`, `nice`) is called anywhere in the project. |
| TEMP folders and the Startup folders | `os.scandir`, `os.path.isdir`, `os.stat` — sizes and counts only |

`psutil.net_if_addrs` is never called: **no IP address and no MAC address is read, in any
code path**. Network collection uses `net_io_counters` and `net_if_stats` only.

## 2. What is never collected

No code path in this project reads, stores, exports, or transmits:

- a **drive, board, battery, or Windows serial number** — the storage descriptor's serial
  field is deliberately skipped, and no other serial is queried anywhere;
- a **MAC address** — `psutil.net_if_addrs` is not called;
- an **IP address**, local or public — same reason, and there is no network call to learn one
  from;
- a **product key, licence ID, machine GUID, install ID, or hardware hash**;
- the **contents of any file**, or the file names inside TEMP or any measured folder;
- browsing data, credentials, documents, or clipboard contents that the app did not itself
  place there;
- the **queued paths** in `PendingFileRenameOperations` — only whether the value is present.

A drive **model** and **bus type** (`SAMSUNG MZVL21T0HCLR-00BL2`, `NVMe`) are collected and do
appear in a report. They describe a component, not a machine: they are identical across every
unit of that model. The serial, which would identify this machine, is the field that is
skipped.

## 3. The settings button — the one thing this app makes happen outside itself

This is the single exception to "the application only reads", and it is worth stating
precisely, because it is easy to overstate in either direction.

**What it is.** Some recommendations now carry an `action_uri`: a Windows settings page that
is *about* the finding. When one does, the GUI draws an **Open setting** button beside that
piece of advice. Clicking it calls `os.startfile("ms-settings:…")`, which asks Windows to open
that Settings page.

**What it is not.** Opening a settings page does not change the setting. The app has no code
that toggles the switch on that page, no code that fills in a field, and no code that clicks a
button in Settings. The user sees the page and decides. The button is a shortcut to the place
where a change *could* be made by hand; it is not a change.

The boundary is enforced by five properties, each checkable in the code:

1. **Only on a click.** `os.startfile` is reached from exactly one method,
   `gui.ApoliakAnalyzerApp.open_setting`, which is only ever bound to a button's `command`.
   It is never called during `analyze_pc`, during scoring, during recommendation generation,
   or during any renderer. `tests/test_readonly.py` parses `gui.py` with `ast` and asserts
   that `open_setting` is the *only* function in the module that contains the string
   `"startfile"` — a mention inside a docstring or comment does not count, and a second real
   lookup could not hide in one either.
2. **Only an `ms-settings:` URI.** `gui.is_settings_uri()` is the fence. It requires the
   literal lower-case prefix `ms-settings:` and then matches
   `^ms-settings:[A-Za-z0-9._~%!$&*+,;=:@/?-]*$`. Anything with a space, a quote, a
   backslash, a newline, a second scheme, or different capitalisation is **refused, not
   repaired** — including `MS-SETTINGS:windowsdefender`, `file:///C:/Windows/System32/cmd.exe`,
   `C:\Windows\System32\cmd.exe`, `\\server\share\payload.exe`, `http://…`, `shell:startup`,
   and any non-string value. A refusal is reported on the status line; nothing runs.
3. **Only from our own table.** The URI always originates in
   `recommendations.RECOMMENDATION_ACTIONS`, an eleven-entry constant map of
   recommendation key → page. It is still re-checked at the button, because "we wrote it" is
   not a property the fence can verify, and the check is the whole reason the button is safe.
   The complete list of pages the application can ever open is:
   `ms-settings:windowsdefender`, `ms-settings:windowsupdate`, `ms-settings:storagesense`,
   `ms-settings:batterysaver`, `ms-settings:startupapps`.
4. **Never elevated.** `os.startfile` is called with the URI as its only argument. The
   `operation` parameter — whose `"runas"` value is the elevating one — is never passed. A
   test asserts the exact call signature.
5. **GUI only.** The console has no equivalent. `main.py` never imports `os.startfile`, and
   the JSON export carries `action_uri` as data for a reader to look at, not as something any
   exporter follows.

The window says the same thing to the user, in the place it matters: when at least one
recommendation carries a page, a caption under the list reads *"Opens the matching Windows
settings page. Nothing is changed for you."*, and a successful open reports *"Windows opened
the settings page. Nothing was changed."*

Three recommendation keys deliberately have **no** page. `secure_boot_off` points at a
firmware switch that no Windows page can reach; `drive_worn` and `drive_failing` describe
physical wear that no setting can undo. A wrong page is worse than no page.

## 4. The proof: the audit-hook test

`tests/test_readonly.py` does not read the source and conclude it is clean. It runs the
analysis and all four renderers under `sys.addaudithook()` in a child interpreter, which sees
every event the CPython runtime raises — including the ones raised from inside `psutil` and
from inside `ctypes` wrappers, where a source-level grep sees nothing at all.

The probe watches for:

- **`open` with any writing mode or flag** — `w`, `a`, `x`, `+`, or `O_WRONLY | O_RDWR |
  O_APPEND | O_CREAT | O_TRUNC`;
- **file mutation** — `os.rename`, `os.remove`, `os.unlink`, `os.rmdir`, `os.mkdir`,
  `os.makedirs`, `os.chmod`, `os.chown`, `os.link`, `os.symlink`, `os.truncate`, `os.utime`,
  `os.replace`, the `shutil` copy/move/rmtree family, `tempfile.mkstemp`, `tempfile.mkdtemp`;
- **process launch** — `subprocess.Popen`, `os.system`, `os.exec*`, `os.spawn*`,
  `os.posix_spawn`, `os.fork`, `os.forkpty`, **`os.startfile`**, `winreg.LoadKey`;
- **network** — `socket.__new__`, `bind`, `connect`, `getaddrinfo`, `gethostbyname`,
  `gethostbyaddr`, `sendto`, `urllib.Request`;
- **registry mutation** — `winreg.CreateKey`, `DeleteKey`, `DeleteValue`, `SetValue`,
  `SaveKey`, `LoadKey`, `DisableReflectionKey`, `EnableReflectionKey`, `ConnectRegistry`, and
  any `winreg.OpenKey` whose access mask contains `KEY_SET_VALUE`, `KEY_CREATE_SUB_KEY`,
  `KEY_CREATE_LINK`, `DELETE`, `WRITE_DAC`, or `WRITE_OWNER`.

Under that hook it runs, against the real machine:

1. `analyze_pc()` with defaults — what both interfaces actually execute;
2. `analyze_pc()` with every v2.1 collector explicitly on;
3. `analyze_pc()` with every optional collector off, because a skip path must not write
   either;
4. all four renderers (`text`, `json`, `html`, `markdown`) in both languages, plain and
   redacted, plus `build_report`.

**The assertion is that the finding list is exactly empty.** Not "small", not "expected
entries only" — empty.

The probe begins with its own negative control: while armed, it writes a real file and
launches a real process, and the test asserts the hook noticed **both**. Without that, an
empty finding list could mean a broken hook rather than a clean run — the one way a test like
this fails silently.

A fifth check collects the `action_uri` values the advice produced and asserts they are pages
from `RECOMMENDATION_ACTIONS` **and that following one never happened**: `os.startfile` is in
the watched event set, so a single unattended launch would have appeared in the findings.

`tests/test_readonly.py` contributes 12 of the suite's 957 tests. The rest of the fence —
`is_settings_uri` against 7 accepted and 26 refused values, and `open_setting` against a
refused URI, a failing opener, a machine with no opener, and the no-elevation signature — is
tested there too, without a display and without ever launching anything.

## 5. Files the application writes

Exactly two, both under user control. This is unchanged in v2.1.

**1. An exported report.** Written only where and when you ask — `--export` / `--output` on
the console, or the Export button in the GUI. Missing parent folders of the destination you
named are created; nothing else on the path is touched. The console additionally offers an
interactive "Export this report? [y/N]" question, which is asked only on a real terminal and
is suppressed by `--no-prompt`. Answering anything but yes writes nothing.

A destination the user typed or picked in a save dialog is written as given: overwriting is
what naming a file means. A name the application generated itself — a bare `--export`, or a
directory target — is resolved to a free one instead (`…_2`, `…_3`, …), so two runs started
in the same second cannot silently replace each other's report.

**2. The opt-in history file.** `%LOCALAPPDATA%\Apoliak\Vitals\history.jsonl`
(under the home folder on systems without `%LOCALAPPDATA%`), or wherever `--history-path`
points.

- It is created only after an explicit opt-in: `--save-history`, or the **Save this
  analysis locally** checkbox in the GUI's History view. While that box is unchecked,
  nothing is written to disk.
- It contains numbers only — nine fields: timestamp, score, status, CPU %, RAM %, free disk
  bytes, TEMP bytes, process count, uptime. **No paths, no process names, no host name, no
  serial numbers, no user name.** The v2.1 collectors add nothing to it: drive wear, battery
  wear, folder sizes, and the protection state are not stored in history.
- It keeps the newest 200 runs and drops older records on the next append.
- It is rewritten via a sibling `.tmp` file and an atomic `os.replace`, so an interrupted
  run cannot corrupt it. Records that no longer parse are skipped, not repaired. The only
  delete call in the entire codebase removes that sibling `.tmp` file when the write fails,
  so a failed run does not leave a stray file behind.
- Deleting it is always safe and has no other effect than losing the trend.
- Reading history (`--show-history`, and the GUI's chart and table) touches no system API at
  all.

Three functions in the whole project write bytes — `exporters.export()`, its text-only
sibling `report.export_report()`, and `history.append_snapshot()`. All three are reached only
from `main.py` and `gui.py`, and only after the user asked.

### Resolving TEMP does not write

The temp folder is taken from the `TMP`, `TEMP`, and `TMPDIR` environment variables, in that
order, and only an environment that defines none of them falls through to
`tempfile.gettempdir()`.

That detour exists for one reason: `tempfile.gettempdir()` proves a candidate directory is
usable by **creating a probe file in it, writing to it, and deleting it again**. It is a
small write, it happens once per process, and it would still contradict the promise made at
the top of this document — so the analyzer does not trigger it on any normal Windows or
Linux system.

The trade-off is stated plainly: `gettempdir()` validates writability and silently moves on
to another candidate when a folder is unusable, whereas an environment value is taken as
given. A broken `TMP` therefore surfaces as an unreadable folder with an unknown size —
the honest answer — instead of a size measured somewhere else entirely.

That promise is kept in `analyzer.get_temp_locations`, not assumed. Before a candidate is
scanned it is checked for being an accessible directory: `os.path.isdir` plus opening it
with `os.scandir` and asking for one entry, which is exactly the permission that matters.
A path that fails the check is recorded with `size_bytes = None` — unknown — and named in a
warning. It is never reported as 0 bytes, because "I could not look" and "there was nothing
there" are different answers and only one of them is true. An unknown TEMP size costs no
score points and turns `data_complete` false.

`folder_usage.py` applies the same rule to the known folders, with the same walker.

### The folder scanners

Neither scanner follows symbolic links or Windows reparse points, so neither can wander off
the folder it was pointed at. Unreadable, protected, and disappearing files are skipped —
TEMP changes constantly while it is being measured. Each scan runs against a wall-clock
budget, checked both per directory and every 128 entries; when the budget runs out the result
is flagged as truncated rather than reported as a smaller number.

A truncated scan is treated as an incomplete measurement everywhere downstream: the size is
quoted as a lower bound, and for TEMP the snapshot's `temp_truncated` flag is set, every
export surfaces it, and the analysis is reported as incomplete data. The qualifier itself is
a translated sentence, not text baked into the number — "at least 5.0 GB" in English,
"aspoň 5.0 GB" in Slovak — and the recommendation that quotes the same folder quotes it as a
floor too, so one run never states the same measurement two ways.

The two scans share one wall-clock budget (`analyzer.TOTAL_SCAN_SECONDS`, 8 seconds), so
adding the biggest-folders measurement in v2.1 cannot double the length of a run. TEMP goes
first and hands its unused time to the folder scan; the folder scan is guaranteed at least
one second whatever TEMP did.

### The one console setting the tool touches

On Windows, colour output needs the console's virtual-terminal flag. When the console does
not already have it and colour is wanted, the analyzer sets
`ENABLE_VIRTUAL_TERMINAL_PROCESSING` on its own standard-output handle and **registers an
`atexit` handler that restores the previous mode**. Nothing is persisted: the console screen
buffer belongs to the parent shell, the change lives only for the run, and no registry
value, profile, or file records it. `--color never` avoids the call entirely.

## 6. Redaction and what an exported report contains

A report is a snapshot of your machine and can identify it. Every format contains:

- the TEMP path and the measured folder paths, which include the **Windows account name**
  (`C:\Users\<name>\AppData\Local\Temp`, `C:\Users\<name>\Downloads`);
- **running process names**, their memory use, and their CPU share;
- **startup-entry names and their source** (which registry key or Startup folder);
- the machine **manufacturer, model, and BIOS version**, and the Windows install date;
- **network interface names**, which on some systems are user-renamed;
- graphics adapter names, driver versions, and driver dates;
- drive letters, capacities, filesystem types, and media type;
- new in v2.1: the **drive model and bus type**, its wear percentage, temperature, power-on
  hours and total data written; the **battery's design and full-charge capacity, cycle count
  and chemistry**; the **sizes and file counts of your user folders**; and the **protection
  state** — whether antivirus and firewall are active, whether Secure Boot is on, whether a
  restart is pending, and how old the Defender signatures are;
- the analysis warnings, which can quote a path that could not be read.

The **JSON export additionally contains the full startup-entry command lines**, which
frequently include the account name and installed application paths. The text, HTML, and
Markdown reports list startup entries by name and source only.

No format ever contains IP addresses, MAC addresses, serial numbers, product keys, machine
identifiers, file names inside TEMP or inside a measured folder, browsing data, or the
contents of any file.

Redaction masks the Windows account name throughout the output: the `C:\Users\<name>` path
segment is replaced with `C:\Users\<user>` wherever it occurs — including in the middle of a
quoted startup command, and with forward slashes as well as backslashes — and any other
occurrence of the account name, in a warning or a printed destination path, is replaced with
`<user>`. It is applied to the report text, the recommendations, the warnings, the startup
commands, the folder paths, and every export format.

One limit is worth knowing: the free-standing name replacement only runs for account names
of three characters or more, because a one- or two-letter name would match half the words in
the document. The `C:\Users\…` path segment is always masked regardless of length.

It is available in both interfaces:

- **console:** `--redact`;
- **GUI:** the **Redact personal data** checkbox in the sidebar. It is **off by default**,
  and when ticked it applies to every export format *and* to the clipboard copy. If a
  writer in a trimmed installation cannot accept the redaction option, the GUI refuses the
  export and says so rather than writing an unmasked file.

Redaction masks the account name; it does not anonymise the machine. The manufacturer,
model, BIOS version, drive model, process names, and startup command lines all survive it.
Review a report before sharing it, particularly the startup-entry list.

## 7. Honest unknowns

A security tool that guesses is worse than one that admits a gap. Three rules are absolute
and are worth checking in the code:

- **A failed query is `unknown`, never `bad`.** A denied registry key, a `wscapi.dll` that
  will not load, a drive that rejects the SMART log page, a battery whose firmware reports
  `BATTERY_UNKNOWN_CAPACITY` — all produce `None` or `STATE_UNKNOWN`.
- **An unknown is never penalised.** Its score rule stays unevaluated and its category is
  reported as unavailable, so no interface reports a clean bill of health it never earned.
- **Secure Boot being off costs nothing.** It is reported and it produces one line of advice,
  and there is deliberately no deduction row for it. Secure Boot is off for many legitimate
  reasons — dual boot, older firmware — and taking points away for that would be dishonest.

Plausibility limits back this up: a drive temperature outside 233–398 K, more than 1 000 000
power-on hours, more than 1 EB written, a battery above 1 000 000 mWh or 100 000 cycles are
all treated as a wrong answer and dropped, because a wrong number is worse than no number.

## 8. Reporting a vulnerability

Do not include passwords, API keys, private reports, or personal system paths in a public
issue. Provide the affected version, reproduction steps, and expected versus actual
behaviour through the project's private maintainer contact channel.

If you find a code path that writes to the system outside the two files listed in section 5,
or a way to reach `os.startfile` with anything other than a page from
`RECOMMENDATION_ACTIONS`, or a way to reach it without a click, treat it as a security issue
rather than a bug.

## 9. Future optimizer modules

Any future write operation must live behind its own service boundary, require explicit
per-action confirmation, state the exact change before it is made, provide a restore path
where Windows supports one, record a reversible action log, and be separately testable from
the analyzer. No write may be added inside the collection or analysis layers.

The settings button is not a precedent for that. It is deliberately the weakest possible
version of "the app does something": one fixed scheme, five fixed pages, one call site, one
click, and no change to any setting. A module that actually changes a setting is a different
kind of thing and needs the full list of rules in [docs/roadmap.md](docs/roadmap.md).
