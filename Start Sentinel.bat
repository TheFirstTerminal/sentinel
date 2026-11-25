@echo off
rem Double-click to start the Sentinel lab and open the demo menu.
rem Needs Git for Windows (Git Bash) and Docker Desktop.
cd /d "%~dp0"
rem Git for Windows installed for all users, or for this user only.
set "MINTTY=%ProgramFiles%\Git\usr\bin\mintty.exe"
if not exist "%MINTTY%" set "MINTTY=%LOCALAPPDATA%\Programs\Git\usr\bin\mintty.exe"
if not exist "%MINTTY%" (
  echo Git Bash was not found. Install Git for Windows, then try again.
  echo Still stuck? Open an issue: https://github.com/TheFirstTerminal/sentinel/issues
  pause
  exit /b 1
)
set CHERE_INVOKING=1
rem The window in The First Terminal's colours: midnight background, light text, saffron cursor.
start "" "%MINTTY%" --title "Sentinel" -s 110,40 -o "Background=#0F1F2E" -o "Foreground=#F4F6F5" -o "CursorColour=#E8A33D" /usr/bin/bash -lc "bash lab/start.sh"
