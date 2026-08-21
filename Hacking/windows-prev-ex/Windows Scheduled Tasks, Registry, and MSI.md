---
type: note
status: seed
created: 2026-08-21
aliases:
  - AlwaysInstallElevated
  - Windows Scheduled Tasks
tags:
  - hacking/windows
  - windows/scheduled-tasks
  - windows/registry
---

# Windows scheduled tasks, registry, and MSI

> [!summary] Inspect privileged launch points
> Scheduled tasks, Run keys, and installer policy can execute code in elevated contexts when their configuration or referenced files are weakly protected.

## Enumerate tasks and startup paths

```powershell
schtasks /query /fo LIST /v
Get-ScheduledTask | Select-Object TaskName, TaskPath, State
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

For each task, inspect its principal, trigger, action, and ACLs of every invoked file/directory. Confirm whether the current user can modify the executable or its inputs and whether the task runs at a higher privilege.

## AlwaysInstallElevated

The policy is risky only when **both** HKLM and HKCU `Policies\Microsoft\Windows\Installer\AlwaysInstallElevated` values are enabled. This causes Windows Installer packages to install with elevated privileges. Treat it as a configuration finding to remediate, not an excuse to deploy arbitrary installers.

## Connections

- Topic map: [[windows-prev-ex]]
- Related: [[Windows Services]], [[Windows Security Model]]
