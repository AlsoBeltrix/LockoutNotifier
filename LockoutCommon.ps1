<#
.SYNOPSIS
    Shared helpers for the lockout monitor. Dot-sourced by LockoutAlerts.ps1
    (event-driven) and LockoutDigest.ps1 (scheduled rollup).

    These functions reference the caller's $cfg / $pdc (populated before the
    dot-source), so dot-source AFTER loading config in each script.
#>

# Resolve the path-valued config keys against $BaseDir when they're relative, so
# the install location isn't hardcoded. Absolute paths are left untouched. Mutates
# $cfg in place. Call once, right after loading config + dot-sourcing this file.
function Resolve-ConfigPath {
    param([Parameter(Mandatory)][string]$BaseDir)
    foreach ($key in 'StateFile', 'LogFile', 'HistoryFile') {
        $val = $cfg[$key]
        if ($val -and -not [System.IO.Path]::IsPathRooted($val)) {
            $cfg[$key] = Join-Path $BaseDir $val
        }
    }
}

# Wrapper around Get-WinEvent that distinguishes "no matching events" (a normal,
# empty result) from real failures (access-denied, RPC/unreachable, bad log name).
# Get-WinEvent throws for BOTH; collapsing them would silently report access-denied
# as "no lockouts". This returns @() only when the log genuinely had no matches,
# and re-throws everything else for the caller to surface.
function Get-LockoutEvent {
    param(
        [Parameter(Mandatory)][string]$ComputerName,
        [Parameter(Mandatory)][hashtable]$FilterHashtable,
        [int]$MaxEvents
    )
    $params = @{ ComputerName = $ComputerName; FilterHashtable = $FilterHashtable; ErrorAction = 'Stop' }
    if ($MaxEvents) { $params.MaxEvents = $MaxEvents }
    try {
        Get-WinEvent @params
    } catch [System.Diagnostics.Eventing.Reader.EventLogException] {
        # Most "no events" cases surface here; also catch the PS-specific id below.
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return @() }
        throw
    } catch {
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or
            $_.Exception.Message -match 'No events were found') { return @() }
        throw   # access-denied, RPC unavailable, etc. - let the caller report it
    }
}

# Pull a named <Data> field out of an event's XML.
function Get-EventField {
    param([xml]$Xml, [string]$Name)
    ($Xml.Event.EventData.Data | Where-Object { $_.name -eq $Name }).'#text'
}

# Current AD lock state for an account. Returns Locked (bool/'unknown') + Since.
function Get-ADUserState {
    param([Parameter(Mandatory)][string]$Account)
    $sam = $Account.TrimEnd('$')
    try {
        $u = Get-ADUser $sam -Properties LockedOut, AccountLockoutTime -ErrorAction Stop
        [pscustomobject]@{ Locked = [bool]$u.LockedOut; Since = $u.AccountLockoutTime }
    } catch {
        [pscustomobject]@{ Locked = 'unknown'; Since = $null }
    }
}

# ---- Durable lockout history ------------------------------------------------
# The Security log on a busy PDC can roll several times an hour, so retrospective
# "last N hours" queries against it silently undercount. Instead, the event-driven
# alert script appends every 4740 it sees to a CSV at trigger time (before the log
# rolls), and the digest + repeat-count read from that file. $cfg must be set.

# Parse a stored ISO-8601 timestamp back to [datetime]; $null if unparseable.
function ConvertFrom-Iso {
    param([string]$Value)
    [datetime]$dt = 0
    if ([datetime]::TryParse($Value, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$dt)) { $dt } else { $null }
}

# Append new lockout events to the history CSV (deduped by RecordId).
function Add-LockoutHistory {
    param([Parameter(Mandatory)]$Events)
    if (-not $cfg.HistoryFile) { return }
    $path = $cfg.HistoryFile
    $dir = Split-Path -Parent $path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }

    $seen = @{}
    if (Test-Path -LiteralPath $path) {
        foreach ($r in (Import-Csv -LiteralPath $path)) { $seen[[string]$r.RecordId] = $true }
    }
    $rows = foreach ($e in $Events) {
        if ($seen.ContainsKey([string]$e.RecordId)) { continue }
        [pscustomobject]@{
            RecordId  = $e.RecordId
            UserID    = $e.UserID
            Computer  = $e.Computer
            TimeStamp = $e.TimeStamp.ToString('o')   # ISO 8601, culture-invariant + sortable
        }
    }
    if ($rows) { $rows | Export-Csv -LiteralPath $path -NoTypeInformation -Append }
}

# Read history rows, optionally filtered to the last $Hours and/or one account.
function Get-LockoutHistory {
    param([int]$Hours, [string]$Account)
    if (-not ($cfg.HistoryFile -and (Test-Path -LiteralPath $cfg.HistoryFile))) { return @() }
    $rows = @(Import-Csv -LiteralPath $cfg.HistoryFile)
    if ($Hours) {
        $since = (Get-Date).AddHours(-$Hours)
        $rows = $rows | Where-Object {
            $t = ConvertFrom-Iso $_.TimeStamp
            $t -and $t -ge $since
        }
    }
    if ($Account) {
        $sam = $Account.TrimEnd('$')
        $rows = $rows | Where-Object { $_.UserID -eq $sam -or $_.UserID -eq "$sam$" }
    }
    @($rows)
}

# Prune history rows older than $Days (keeps the file bounded). Run from the digest.
function Remove-OldLockoutHistory {
    param([int]$Days = 30)
    if (-not ($cfg.HistoryFile -and (Test-Path -LiteralPath $cfg.HistoryFile))) { return }
    $cutoff = (Get-Date).AddDays(-$Days)
    $kept = Import-Csv -LiteralPath $cfg.HistoryFile | Where-Object {
        $t = ConvertFrom-Iso $_.TimeStamp
        $t -and $t -ge $cutoff
    }
    $kept | Export-Csv -LiteralPath $cfg.HistoryFile -NoTypeInformation
}

# Count an account's lockouts in the last $Hours, from durable history.
function Get-LockoutCount {
    param([Parameter(Mandatory)][string]$Account, [int]$Hours = 24)
    @(Get-LockoutHistory -Hours $Hours -Account $Account).Count
}

# Wrap a ConvertTo-Html table in courier-new styling for the email body.
function ConvertTo-StyledTable {
    [CmdletBinding()]
    param([Parameter(ValueFromPipeline)]$InputObject)
    end {
        $html = $input | ConvertTo-Html -Fragment | Out-String
        $html = $html.Replace('<table>', "<table style='width:85%'>")
        $html = $html.Replace('<th>', "<th style='text-align:left'><font face='courier new'>").Replace('</th>', '</font></th>')
        $html = $html.Replace('<td>', "<td><font face='courier new'>").Replace('</td>', '</font></td>')
        $html
    }
}

# Append a line to the configured log file (and stdout). $cfg must be set.
function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ERROR')]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Write-Output $line
    if ($cfg.LogFile) {
        try {
            $dir = Split-Path -Parent $cfg.LogFile
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            Add-Content -LiteralPath $cfg.LogFile -Value $line
        } catch { Write-Warning "Could not write log: $_" }
    }
}

# Send mail via the configured relay/From. $cfg must be set.
# If the caller set $PreviewMode = $true, print the message to the console instead
# of sending it (dry run for "see what it's outputting").
function Send-Notice {
    param(
        [Parameter(Mandatory)][string[]]$To,
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string]$Body,
        [string[]]$Attachments,
        [switch]$Html
    )
    if ($PreviewMode) {
        # Make HTML readable in the console: turn row/cell boundaries into
        # separators before stripping the remaining tags.
        $text = $Body -replace '(?i)</t[dh]>', "`t" `
                      -replace '(?i)</tr>', "`n" `
                      -replace '(?i)</p>', "`n" `
                      -replace '<[^>]+>', ''
        $text = [System.Net.WebUtility]::HtmlDecode($text).Trim()
        Write-Host ''
        Write-Host ('=' * 72) -ForegroundColor DarkGray
        Write-Host "TO      : $($To -join ', ')" -ForegroundColor Cyan
        Write-Host "SUBJECT : $Subject" -ForegroundColor Cyan
        if ($Attachments) { Write-Host "ATTACH  : $($Attachments -join ', ')" -ForegroundColor Cyan }
        Write-Host ('-' * 72) -ForegroundColor DarkGray
        Write-Host $text
        Write-Host ('=' * 72) -ForegroundColor DarkGray
        Write-Log "PREVIEW (not sent): '$Subject' -> $($To -join ', ')"
        return
    }
    $params = @{
        To = $To; From = $cfg.From; SmtpServer = $cfg.SmtpServer
        Subject = $Subject; Body = $Body
    }
    if ($Html) { $params.BodyAsHtml = $true }
    if ($Attachments) { $params.Attachments = $Attachments }
    try {
        Send-MailMessage @params
        Write-Log "Sent '$Subject' to $($To -join ', ')"
    } catch {
        Write-Log "FAILED to send '$Subject' to $($To -join ', '): $_" 'ERROR'
    }
}
