---
type: note
status: seed
created: 2026-08-21
aliases:
  - Windows Basics
tags:
  - hacking/windows
  - windows/enumeration
---

# Windows shell and enumeration

> [!summary] Establish identity and execution context
> Use CMD and PowerShell to identify the host, user, token, processes, services, network exposure, and installed software before evaluating an escalation path.

## CMD and PowerShell

`cmd.exe` is the legacy command interpreter; PowerShell is an object-oriented shell with richer access to Windows management APIs. Prefer PowerShell for structured discovery and CMD for compatibility.

```powershell
whoami /all
hostname
systeminfo
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, OsBuildNumber
Get-Process
Get-Service
Get-NetTCPConnection -State Listen
```

Useful CMD equivalents include `whoami /all`, `ipconfig /all`, `tasklist /v`, `sc query`, `netstat -ano`, `driverquery`, and `wmic qfe list` (where available).

## File transfer in approved labs

```powershell
Invoke-WebRequest -Uri <url> -OutFile <path>
certutil -urlcache -split -f <url> <path>
```

Verify the origin and hash of every transferred file. Do not bypass endpoint protections or run untrusted binaries on a real system.

## Connections

- Topic map: [[windows-prev-ex]]
- Method: [[Windows Privilege-Escalation Methodology]]
