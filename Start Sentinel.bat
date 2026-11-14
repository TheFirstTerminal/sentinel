@echo off
rem Double-click to start the Sentinel lab and open the demo menu.
rem Needs Git for Windows (Git Bash) and Docker Desktop.
cd /d "%~dp0"
set "MINTTY=%ProgramFiles%\Git\usr\bin\mintty.exe"
if not exist "%MINTTY%" (
  echo Git Bash was not found. Install Git for Windows, then try again.
  echo Any problem: talk to S.
  pause
  exit /b 1
)
set CHERE_INVOKING=1
start "" "%MINTTY%" --title "Sentinel" -s 110,40 /usr/bin/bash -lc "bash lab/start.sh"
