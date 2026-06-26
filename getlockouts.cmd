REM Account lockout monitor - launched by the "Lockouts" scheduled task on event 4740.
REM  4/24/13  Created - JLH
REM  4/15/22  Added sensitive service account alerts (LockoutNotifications.csv)
REM  2026     Rewrite: single parameterized script + LockoutConfig.psd1, RecordId dedup.

REM %~dp0 = the folder this .cmd lives in (with trailing backslash), so the
REM install location is not hardcoded - copy the folder anywhere and it works.
%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0LockoutAlerts.ps1"
