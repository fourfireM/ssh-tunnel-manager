@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>&1
if errorlevel 1 goto use_python
py -3 main.py --background --open
goto finished
:use_python
python main.py --background --open
:finished
set "TD_RESULT=%errorlevel%"
if not "%TD_RESULT%"=="0" (
  echo Startup failed. See README.md and the error above.
  pause
)
exit /b %TD_RESULT%
