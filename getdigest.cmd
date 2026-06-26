REM Lockout rollup digest - launched by the "LockoutsDigest" scheduled task on a timer.
REM  2026  Added: at-a-glance "who's locked out repeatedly / still" summary.

REM %~dp0 = the folder this .cmd lives in - install location is not hardcoded.
%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0LockoutDigest.ps1"
