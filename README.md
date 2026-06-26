# Lockout Alerts

Account-lockout monitoring for a domain. Two scheduled tasks share one config:

- **Lockouts** (event task) fires on Security event **4740** (account locked out)
  on the PDC emulator and runs `LockoutAlerts.ps1` — instant, per-event alerts.
- **LockoutsDigest** (timer task) runs `LockoutDigest.ps1` on an interval and
  emails a rollup of recent lockouts — the at-a-glance "who's locked out
  repeatedly / still" view.

## Behaviors

Event task (`LockoutAlerts.ps1`), each independently toggleable in config:

1. **WatchList** – email named owners when a specific sensitive account locks out.
   Each alert is enriched with **how many times** the account has locked out in
   `RepeatWindowHours` and whether it is **still locked right now**.
2. **Tracing** – correlate the 4740 to **4625** bad-logon events on the source
   machine to surface the IP / workstation / process that caused the lockout.
3. **Dump** – email a plain digest of the new lockouts to an ops mailbox.

Timer task (`LockoutDigest.ps1`):

4. **Digest** – one table per run: each account with a recent lockout, its count,
   first/last time, and current locked state (still-locked accounts listed first).

> **How the count and digest stay accurate.** A busy PDC's Security log can roll
> several times an hour, so a retrospective "last N hours" query against it
> silently undercounts. Instead, the event task appends every 4740 it sees to a
> durable history CSV (`HistoryFile`) *at trigger time* — before the log rolls —
> and both the repeat-count and the digest read from that file, not the log. The
> **current locked state** comes from live AD (`Get-ADUser`), so it's accurate even
> when the originating 4740 has long since rolled out of the log and history.

## Files

| File | Purpose | In git |
|------|---------|--------|
| `LockoutAlerts.ps1` | Event-driven script (behaviors 1–3). | yes |
| `LockoutDigest.ps1` | Timer-driven rollup (behavior 4). | yes |
| `LockoutCommon.ps1` | Shared helpers, dot-sourced by both. | yes |
| `LockoutConfig.sample.psd1` | Template config. Copy and edit. | yes |
| `LockoutConfig.psd1` | **Your** config (SMTP, recipients, account names). | **no (.gitignore)** |
| `getlockouts.cmd` | Wrapper the event task runs. | yes |
| `getdigest.cmd` | Wrapper the timer task runs. | yes |
| `Lockouts_Scheduled_Task.xml` | Event task (4740 trigger). | yes |
| `LockoutsDigest_Scheduled_Task.xml` | Timer task (default every 30 min). | yes |
| `state\lockouts.csv` | Durable lockout history the digest reads. Runtime. | **no (.gitignore)** |

## Deploy to a new domain

Install on the **PDC emulator** — the event task watches the *local* Security log,
where 4740s are authoritatively logged, and the script's log read is local (no RPC).
Find it with `netdom query fsmo` or `(Get-ADDomain).PDCEmulator`. If the PDC role
moves, move the task too.

The install folder is **not hardcoded** — the `.cmd` wrappers locate the scripts
via their own path (`%~dp0`), and relative config paths resolve against the script
folder. Drop the folder wherever your scripts live (here: `D:\Scripts\Lockouts`).
The **only** absolute path is the `<Command>` in each task XML, which Task Scheduler
requires — update those two if your path differs.

1. Copy the files to the install folder on the PDC emulator (e.g. `D:\Scripts\Lockouts`).
2. `Copy-Item LockoutConfig.sample.psd1 LockoutConfig.psd1` and edit it:
   - `SmtpServer`, `From`
   - `WatchList.Accounts`, and the `Recipients` for Tracing / Dump / Digest
   - `Tracing.ExcludeMachinePatterns` — **review this for the new domain.** The
     the `-L0/-D0/-T0` sample values are placeholders. Set patterns that match this
     domain's end-user PC naming, or `@()` to trace every source machine.
   - `HistoryFile` / `HistoryRetentionDays` — durable lockout record the digest and
     repeat-count read from. Paths are relative to the script folder by default
     (`state\`, `logs\`); absolute paths also work.
   - `RepeatWindowHours`, `Digest.WindowHours` to taste; the digest interval is in
     the timer task XML (`<Interval>PT30M</Interval>`).
   - Disable any behavior you don't want (`Enabled = $false`).
3. If your install path differs from `D:\Scripts\Lockouts`, update the `<Command>`
   in both task XMLs to match.
4. Import both scheduled tasks (see below), set them to run as a service account
   with rights to read the Security log on the PDC and the source machines, and to
   write under the script folder's `state\` and `logs\`.
5. Test: lock out a throwaway account that's in your `WatchList`, confirm the
   alert email (with count + still-locked line). The digest summarizes the history
   file, so it's **empty until the event task has recorded at least one 4740** —
   confirm a row lands in `state\lockouts.csv`, then check the next digest run.

## Scheduled tasks

Update the `<UserId>` principal in each XML to the new domain's service account,
then import:

```powershell
Register-ScheduledTask -Xml (Get-Content .\Lockouts_Scheduled_Task.xml -Raw) `
    -TaskName 'Lockouts' -User 'DOMAIN\svc_account' -Password '<prompt>'

Register-ScheduledTask -Xml (Get-Content .\LockoutsDigest_Scheduled_Task.xml -Raw) `
    -TaskName 'LockoutsDigest' -User 'DOMAIN\svc_account' -Password '<prompt>'
```

The event task triggers on Security 4740 and runs `getlockouts.cmd`. The timer
task runs `getdigest.cmd` every 30 minutes by default.

## Preview / dry run

Both scripts take `-Preview` to print the emails to the console instead of sending
them — use it to see exactly what would go out:

```powershell
.\LockoutAlerts.ps1 -Preview    # shows all fetched events; does NOT advance state
.\LockoutDigest.ps1 -Preview    # shows the rollup table
```

In preview, `LockoutAlerts.ps1` ignores the state file (so it shows current events
even if a real run already processed them), does not advance it (so the preview
doesn't "consume" new lockouts before the real task sees them), and does **not**
write to the history file. Because of that last point, a `-Preview` run won't seed
the digest — to populate history for a digest test, run `LockoutAlerts.ps1` once
without `-Preview` (or let the real event task fire).

A real fetch failure (access-denied, RPC unreachable) now throws loudly with an
ERROR log instead of being silently reported as "no events" — so if you run this
remotely against a DC with the Remote Event Log Management firewall closed, you'll
get a clear `RPC server is unavailable`, not a misleading empty result.

## Design notes

- **One email per genuine lockout, no repeats.** Each real lockout is a distinct
  4740 with its own RecordId; `StateFile` records the highest one processed so the
  *same* event is never re-emailed when the task fires again. Genuine repeat
  lockouts are new RecordIds and still alert each time.
- **Recurrence/persistence is explicit, not inferred from inbox volume.** Every
  alert states how many times the account locked out recently and whether it's
  still locked now; the digest gives the same view across all accounts.
- **Durable history vs. the Security log.** Recurrence data comes from the
  append-only `HistoryFile`, not retrospective log queries, because a busy DC's
  Security log can roll several times an hour and a "last N hours" query would
  silently undercount. The event task records each 4740 as it fires (when the
  event is guaranteed present); the digest and repeat-count summarize that file.
  Current lock state always comes from live AD, so it's accurate regardless.
- `Send-MailMessage` is deprecated by Microsoft but retained to avoid a module
  dependency on the DC. Replace with Graph/an SMTP client if/when desired.
