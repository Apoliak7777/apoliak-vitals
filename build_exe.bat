@echo off
setlocal
cd /d "%~dp0"

rem The only script in this project: prepares everything and builds the single .exe.

where py >nul 2>nul
if errorlevel 1 (
    echo Python was not found.
    echo Install Python 3.10 or newer from https://www.python.org/downloads/windows/
    echo and enable "Add Python to PATH" during installation.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo [1/4] Creating the local build environment...
    py -3 -m venv .venv
    if errorlevel 1 goto :failed
) else (
    echo [1/4] Local build environment found.
)

echo [2/4] Installing dependencies...
".venv\Scripts\python.exe" -m pip install --upgrade pip --quiet
if errorlevel 1 goto :failed
".venv\Scripts\python.exe" -m pip install -r requirements-build.txt --quiet
if errorlevel 1 goto :failed

echo [3/4] Running the test suite...
".venv\Scripts\python.exe" -m unittest discover -s tests
if errorlevel 1 goto :failed

echo [4/4] Building the application...
".venv\Scripts\python.exe" -m PyInstaller --clean --noconfirm Apoliak_Vitals.spec
if errorlevel 1 goto :failed

echo.
echo Done. Your application is one file:
echo     %~dp0dist\Apoliak-Vitals.exe
echo.
echo Copy it anywhere and double-click it. Nothing else is needed.
pause
exit /b 0

:failed
echo.
echo Build failed. Review the error above.
pause
exit /b 1
