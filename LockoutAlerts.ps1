<#
.SYNOPSIS
    Account-lockout monitor. Reacts to Security event 4740 on the PDC emulator and
    runs up to three reporting behaviors, all driven by an external config file.

.DESCRIPTION
    Launched by the "Lockouts" scheduled task (via getlockouts.cmd) on each 4740 event.
    Pulls the most recent 4740 events from the PDC emulator once, then runs whichever
    of the following are enabled in the config:

      1. WatchList - email named owners when a specific sensitive account locks out.
                     Each alert is enriched with how many times the account has locked
                     out recently and whether it is still locked right now.
      2. Tracing   - correlate the 4740 to 4625 (bad logon) events on the source
                     machine to surface the IP / workstation / process that caused it.
      3. Dump      - email a plain digest of the new lockouts to an ops mailbox.

    A point-in-time "who is locked out repeatedly / still" view is provided separately
    by LockoutDigest.ps1 (a scheduled rollup), not by this event-driven script.

    A state file records the last 4740 RecordId already processed, so each run only
    acts on NEW lockouts. Genuine repeat lockouts are distinct 4740 events (distinct
    RecordIds) and still alert each time; the state file only suppresses re-reporting
    the SAME event when an unrelated lockout re-triggers the task.

.PARAMETER ConfigPath
    Path to the .psd1 config. Defaults to LockoutConfig.psd1 next to this script.

.NOTES
    Send-MailMessage is deprecated by Microsoft but kept here to avoid an external
    module dependency on the DC. Swap for a Graph/SMTP client later if desired.
#>

[CmdletBinding()]
param(
    # Defaults to LockoutConfig.psd1 next to this script (resolved in the body -
    # $PSScriptRoot is unreliable in a param default under `powershell -File`).
    [string]$ConfigPath,
    # Dry run: print emails to the console instead of sending, and don't advance
    # the state file (so a preview doesn't "consume" new lockouts).
    [switch]$Preview
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PreviewMode = [bool]$Preview

#region ---- Config & helpers -------------------------------------------------

# Resolve the script's own folder robustly. $PSScriptRoot can be empty in a param
# default when launched via `powershell.exe -File` (as the scheduled task does),
# so compute it in the body with fallbacks.
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

#endregion

#region ---- Fetch 4740 events from the PDC (once) ----------------------------

try {
    $pdc = (Get-ADDomainController -Filter * |
        Where-Object { $_.OperationMasterRoles -contains 'PDCEmulator' }).HostName
    if (-not $pdc) { throw 'Could not locate the PDC emulator.' }
} catch {
    Write-Log "Could not resolve PDC emulator: $_" 'ERROR'
    throw
}

$maxEvents = if ($cfg.MaxEvents) { [int]$cfg.MaxEvents } else { 25 }

try {
    $raw = Get-LockoutEvent -ComputerName $pdc `
        -FilterHashtable @{ LogName = 'Security'; Id = 4740 } -MaxEvents $maxEvents
} catch {
    # Real failure (access-denied, RPC, etc.) - surface it loudly, do NOT pretend empty.
    Write-Log "Failed to read Security log on ${pdc}: $_" 'ERROR'
    throw
}

if (-not $raw) {
    Write-Log "No 4740 events on $pdc." 'INFO'
    return
}

# Parse into flat objects, keeping the raw event for the 4625 correlation step.
$events = foreach ($e in $raw) {
    $xml = [xml]$e.ToXml()
    [pscustomobject]@{
        RecordId  = [int64]$e.RecordId
        UserID    = Get-EventField $xml 'TargetUserName'
        Computer  = Get-EventField $xml 'TargetDomainName'  # = caller computer for 4740
        TimeStamp = $e.TimeCreated
    }
}

#endregion

#region ---- Record durable history -------------------------------------------
# Capture every fetched event before the Security log rolls. Deduped by RecordId,
# so re-fetching the same events across runs is harmless. The digest and the
# repeat-count read from this file, not the (fast-rolling) Security log.
if ($PreviewMode) {
    Write-Log "PREVIEW: history file not written."
} else {
    try { Add-LockoutHistory -Events $events }
    catch { Write-Log "Could not write history file: $_" 'WARN' }
}

#endregion

#region ---- Dedup against last-processed RecordId ----------------------------

$lastSeen = 0L
if ($cfg.StateFile -and (Test-Path -LiteralPath $cfg.StateFile)) {
    [int64]::TryParse((Get-Content -LiteralPath $cfg.StateFile -Raw).Trim(), [ref]$lastSeen) | Out-Null
}

# In preview, show everything fetched (the state file may already be past all
# current events from a prior real run, which would otherwise show nothing).
if ($PreviewMode) {
    $new = $events | Sort-Object RecordId
    Write-Log "PREVIEW: processing all $(@($new).Count) fetched event(s), ignoring state."
} else {
    $new = $events | Where-Object { $_.RecordId -gt $lastSeen } | Sort-Object RecordId
}
if (-not $new) {
    Write-Log "No new lockouts since RecordId $lastSeen."
    return
}
Write-Log ("{0} new lockout(s): {1}" -f @($new).Count, (($new | ForEach-Object { $_.UserID }) -join ', '))

#endregion

#region ---- Behavior 1: Watch-list alerts (enriched) -------------------------

if ($cfg.WatchList -and $cfg.WatchList.Enabled) {
    $repeatHours = if ($cfg.RepeatWindowHours) { [int]$cfg.RepeatWindowHours } else { 24 }

    foreach ($entry in $cfg.WatchList.Accounts) {
        $acct = $entry.Account
        $flagged = $new | Where-Object { $_.UserID -eq $acct -or $_.UserID -eq "$acct$" }
        if (-not $flagged) { continue }

        # #1 enrichment: recurrence count + current lock state.
        $count = Get-LockoutCount -Account $acct -Hours $repeatHours
        $state = Get-ADUserState -Account $acct
        $lockedNow = switch ($state.Locked) {
            $true    { if ($state.Since) { "Yes (since $($state.Since))" } else { 'Yes' } }
            $false   { 'No (already cleared)' }
            default  { 'unknown' }
        }
        $times = ('{0}x in last {1}h' -f $count, $repeatHours)

        $summary = "<p><b>$acct</b> &mdash; $times &middot; currently locked: $lockedNow</p>"
        $table = $flagged | Select-Object UserID, Computer, TimeStamp | ConvertTo-StyledTable
        Send-Notice -To $entry.Notify -Subject "Lockout alert for $acct ($times)" `
            -Body ($summary + $table) -Html
    }
}

#endregion

#region ---- Behavior 2: Source IP / culprit tracing --------------------------

if ($cfg.Tracing -and $cfg.Tracing.Enabled) {
    $excludes = @($cfg.Tracing.ExcludeMachinePatterns)
    $window   = if ($cfg.Tracing.CorrelationWindowSeconds) { [int]$cfg.Tracing.CorrelationWindowSeconds } else { 1 }

    foreach ($evt in $new) {
        $source = $evt.Computer
        if (-not $source) { continue }

        # Skip machines whose name matches an exclude pattern (e.g. end-user PCs).
        if ($excludes | Where-Object { $_ -and $source -match $_ }) {
            Write-Log "Tracing skipped (excluded machine): $source"
            continue
        }

        $start = $evt.TimeStamp
        $end   = $start.AddSeconds($window)

        try {
            $userinfo = Get-ADUser $evt.UserID -Properties PasswordLastSet, LastBadPasswordAttempt, PasswordExpired, LockedOut -ErrorAction Stop
            $upn = $userinfo.UserPrincipalName
        } catch {
            $userinfo = $null; $upn = $null
            Write-Log "Get-ADUser failed for '$($evt.UserID)': $_" 'WARN'
        }

        try {
            $bad = Get-LockoutEvent -ComputerName $source -FilterHashtable @{
                LogName = 'Security'; Id = 4625; StartTime = $start; EndTime = $end
            } | Sort-Object TimeCreated -Descending
        } catch {
            # Don't abort the whole run for one unreachable/denied source machine,
            # but log it as a real failure (distinct from "no matching 4625").
            Write-Log "Could not read 4625 from ${source} (access/RPC?): $_" 'WARN'
            continue
        }

        $rows = foreach ($b in $bad) {
            $bx = [xml]$b.ToXml()
            $target = Get-EventField $bx 'TargetUserName'
            if ($target -notmatch [regex]::Escape($evt.UserID) -and ($upn -and $target -notmatch [regex]::Escape($upn))) { continue }
            [pscustomobject]@{
                Time        = $b.TimeCreated
                User        = $target
                Workstation = Get-EventField $bx 'WorkstationName'
                IpAddress   = Get-EventField $bx 'IpAddress'
                Process     = Get-EventField $bx 'ProcessName'
            }
        }

        if (-not $rows) {
            Write-Log "No matching 4625 on $source for $($evt.UserID)."
            continue
        }

        $guidance = @"
New lockout for $($evt.UserID) sourced from $source.
Check the IP address below for the machine that caused the lockout, e.g.:

    ping -a <IpAddress>

A device repeatedly presenting an old/cached password (often a phone or a service
using stale credentials) is the usual culprit.
"@
        $detail = $rows | Format-Table -AutoSize | Out-String
        $acctInfo = if ($userinfo) {
            $userinfo | Select-Object SamAccountName, UserPrincipalName, PasswordLastSet, LockedOut | Format-List | Out-String
        } else { '' }

        Send-Notice -To $cfg.Tracing.Recipients `
            -Subject "Lockout trace: $($evt.UserID) from $source" `
            -Body ($guidance + "`r`n" + $detail + $acctInfo)
    }
}

#endregion

#region ---- Behavior 3: Raw lockout dump -------------------------------------

if ($cfg.Dump -and $cfg.Dump.Enabled) {
    $digest = $new | Select-Object UserID, Computer, TimeStamp
    $attachment = Join-Path $env:TEMP ("lockouts_{0}.txt" -f $env:COMPUTERNAME)
    $digest | Format-Table -AutoSize | Out-File -LiteralPath $attachment -Encoding UTF8

    $body = $digest | ConvertTo-StyledTable
    Send-Notice -To $cfg.Dump.Recipients -Subject 'Real-Time Lockouts' -Body $body -Attachments $attachment -Html
    Remove-Item -LiteralPath $attachment -ErrorAction SilentlyContinue
}

#endregion

#region ---- Advance state ----------------------------------------------------

if ($PreviewMode) {
    Write-Log "PREVIEW: state file not advanced (still at RecordId $lastSeen)."
} elseif ($cfg.StateFile) {
    try {
        $dir = Split-Path -Parent $cfg.StateFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        ($new | Measure-Object -Property RecordId -Maximum).Maximum |
            Set-Content -LiteralPath $cfg.StateFile
    } catch {
        Write-Log "Could not update state file: $_" 'WARN'
    }
}

#endregion
