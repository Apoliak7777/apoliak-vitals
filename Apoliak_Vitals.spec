# PyInstaller specification for the single-file Windows application.
#
# One target, one file: dist/Apoliak-Vitals.exe. No console window, no installer,
# no folder of loose dependencies — the whole app is that one file.

from PyInstaller.utils.hooks import collect_data_files

datas = collect_data_files("customtkinter")
datas += [("app.ico", ".")]  # the window and taskbar icon, read at runtime from _MEIPASS

analysis = Analysis(
    ["gui.py"],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter.test", "unittest", "pydoc_data", "pytest", "PIL"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(analysis.pure)

executable = EXE(
    pyz,
    analysis.scripts,
    analysis.binaries,
    analysis.datas,
    [],
    name="Apoliak-Vitals",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    # UPX is deliberately off: compressed PyInstaller binaries are a well-known
    # false-positive trigger for Windows antivirus heuristics.
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon="app.ico",
    manifest="app.manifest",
    version="version_info.txt",
)
