@{
    # ---- Mail (required) -----------------------------------------------------
    # SMTP relay that accepts mail from this DC, and the From address to use.
    SmtpServer = 'mailhost.example.com'
    From       = 'LockoutMonitor@example.com'

    # ---- Event fetch ---------------------------------------------------------
    # How many recent 4740 events to pull from the PDC each run. The state file
    # dedups within this set, so this only needs to comfortably exceed the number
    # of lockouts that could occur between two firings of the event task.
    MaxEvents  = 25

    # Window used to count "Nth lockout in last X hours" in watch-list alerts.
    RepeatWindowHours = 24

    # ---- State & logging -----------------------------------------------------
    # Paths may be relative (resolved against the script folder, so the install
    # location is not hardcoded) or absolute (e.g. 'E:\LockoutData\state\...').
    #
    # StateFile tracks the last 4740 RecordId already processed (prevents repeat
    # emails of the SAME event). Used by LockoutAlerts.ps1 only.
    StateFile  = 'state\lastrecord.txt'
    LogFile    = 'logs\lockoutalerts.log'

    # Durable lockout history. LockoutAlerts.ps1 appends every 4740 here at trigger
    # time (before the Security log rolls); the digest and the watch-list repeat
    # count read from this file. REQUIRED for the digest and for accurate counts on
    # DCs whose Security log rolls quickly.
    HistoryFile          = 'state\lockouts.csv'
    HistoryRetentionDays = 30

    # ---- Behavior 1: Watch-list alerts (event-driven) -----------------------
    # Email a specific owner when a specific sensitive account locks out. Each
    # alert shows how many times it has locked out recently and whether it's
    # still locked right now.
    WatchList = @{
        Enabled  = $true
        Accounts = @(
            @{ Account = 'some-service-acct'; Notify = @('owner@example.com') }
            @{ Account = 'another-svc';       Notify = @('teamdl@example.com', 'oncall@example.com') }
        )
    }

    # ---- Behavior 2: Source IP / culprit tracing (event-driven) -------------
    # Correlate the 4740 to 4625 bad-logon events on the source machine to find
    # the IP/workstation/process responsible.
    Tracing = @{
        Enabled                  = $true
        Recipients               = @('lockout_reports@example.com')
        CorrelationWindowSeconds = 1
        # Regex patterns for machine names to SKIP tracing (e.g. end-user PCs whose
        # logs you can't or don't want to read). The legacy script filtered -L0/-D0/-T0.
        # Set to @() to trace every source machine.
        ExcludeMachinePatterns   = @('-L0', '-D0', '-T0')
    }

    # ---- Behavior 3: Raw lockout dump (event-driven) ------------------------
    # Email a plain digest of the new lockouts to an ops mailbox on each event.
    Dump = @{
        Enabled    = $true
        Recipients = @('lockout_reports@example.com')
    }

    # ---- Rollup digest (time-scheduled, separate task) ----------------------
    # The "who's locked out repeatedly / still" at-a-glance view. Run on a timer
    # via LockoutDigest.ps1 (see getdigest.cmd / the digest task XML), e.g. every
    # 30 min. One email: each account, lockout count, first/last time, still-locked.
    Digest = @{
        Enabled       = $true
        Recipients    = @('lockout_reports@example.com')
        WindowHours   = 24
        SendWhenEmpty = $false   # $true = still send a "none" email when quiet
    }
}
