<#
.SYNOPSIS
    Lockout rollup. Emails one table summarizing every account that has locked out
    in a recent window: how many times, first/last time, and whether it is still
    locked right now. This is the "who's locked out repeatedly / still" view.

.DESCRIPTION
    Runs on a time schedule (NOT on the 4740 event) - e.g. every 30 minutes - via
    its own scheduled task. Summarizes the durable history file that
    LockoutAlerts.ps1 appends to on each 4740, NOT the Security log directly - the
    log on a busy PDC rolls too fast for a retrospective window query to be reliable.
    Current lock state is read live from AD, so "StillLocked" is always accurate.

.PARAMETER ConfigPath
    Path to the .psd1 config. Defaults to LockoutConfig.psd1 next to this script.
#>

[CmdletBinding()]
param(
    # Defaults to LockoutConfig.psd1 next to this script (resolved in the body -
    # $PSScriptRoot is unreliable in a param default under `powershell -File`).
    [string]$ConfigPath,
    # Dry run: print the digest to the console instead of emailing it.
    [switch]$Preview
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PreviewMode = [bool]$Preview

# Resolve the script's own folder robustly (see LockoutAlerts.ps1 for why).
$scriptDir = $PSScriptRoot
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $PSCommandPath }
if (-not $scriptDir) { $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path }

if (-not $ConfigPath) { $ConfigPath = Join-Path $scriptDir 'LockoutConfig.psd1' }
if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw "Config not found: $ConfigPath  (copy LockoutConfig.sample.psd1 to LockoutConfig.psd1 and edit it)"
}
$cfg = Import-PowerShellDataFile -LiteralPath $ConfigPath
. (Join-Path $scriptDir 'LockoutCommon.ps1')
Resolve-ConfigPath -BaseDir $scriptDir

if (-not ($cfg.Digest -and $cfg.Digest.Enabled)) {
    Write-Log 'Digest disabled in config; nothing to do.'
    return
}

$hours = if ($cfg.Digest.WindowHours) { [int]$cfg.Digest.WindowHours } else { 24 }

# Read from the durable history file (populated by LockoutAlerts.ps1), not the log.
$rows = Get-LockoutHistory -Hours $hours

# Bound the history file while we're here (skip during preview).
if (-not $PreviewMode) {
    $retain = if ($cfg.HistoryRetentionDays) { [int]$cfg.HistoryRetentionDays } else { 30 }
    try { Remove-OldLockoutHistory -Days $retain } catch { Write-Log "History prune failed: $_" 'WARN' }
}

if (-not $rows) {
    Write-Log "No recorded lockouts in the last ${hours}h."
    if (-not $cfg.HistoryFile) {
        Write-Log "HistoryFile not configured - digest has no data source. Set it in the config." 'WARN'
    }
    if ($cfg.Digest.SendWhenEmpty) {
        Send-Notice -To $cfg.Digest.Recipients -Subject "Lockout digest - none in last ${hours}h" `
            -Body "<p>No account lockouts recorded in the last $hours hours.</p>" -Html
    }
    return
}

# Group by account, compute count / first / last, then add current AD state.
$summary = $rows | Group-Object UserID | ForEach-Object {
    $state = Get-ADUserState -Account $_.Name
    $lockedNow = switch ($state.Locked) {
        $true   { 'YES' }
        $false  { 'no' }
        default { '?' }
    }
    $times = $_.Group | ForEach-Object { [datetime]$_.TimeStamp }
    [pscustomobject]@{
        Account      = $_.Name
        Count        = $_.Count
        First        = ($times | Measure-Object -Minimum).Minimum
        Last         = ($times | Measure-Object -Maximum).Maximum
        StillLocked  = $lockedNow
    }
} | Sort-Object @{ Expression = 'StillLocked'; Descending = $true }, @{ Expression = 'Count'; Descending = $true }

$stillCount = @($summary | Where-Object { $_.StillLocked -eq 'YES' }).Count
$subject = "Lockout digest (last ${hours}h): $(@($summary).Count) accounts, $stillCount still locked"
$intro = "<p>Account lockouts in the last <b>$hours</b> hours. Accounts still locked are listed first.</p>"
$body = $intro + ($summary | ConvertTo-StyledTable)

Send-Notice -To $cfg.Digest.Recipients -Subject $subject -Body $body -Html
