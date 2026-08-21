---
type: note
status: seed
created: 2026-08-21
aliases:
  - Weak Service Permissions
  - Unquoted Service Paths
tags:
  - hacking/windows
  - windows/services
  - windows/privilege-escalation
---

# Windows services

> [!summary] Services execute with their configured account
> A service can become an escalation path when an unprivileged principal can change its configuration, replace its executable, control a loaded component, or influence an ambiguously parsed path.

## Enumerate service configuration

```powershell
Get-CimInstance Win32_Service | Select-Object Name, StartName, State, PathName
sc.exe qc <service>
sc.exe query <service>
icacls "<service executable path>"
```

Review the `StartName`, binary path, arguments, startup type, and ACLs on both the service object and every directory/file in its launch path.

## Common conditions

- **Weak service DACL:** a low-privileged account can change the service configuration or start/stop it.
- **Weak binary or directory permissions:** the service runs a file that a low-privileged user can replace or modify.
- **Unquoted path:** a space-containing executable path without quotes can be interpreted as an earlier path. It is exploitable only if the implied candidate location is writable and the service can be restarted.
- **DLL search-order issue:** a service loads a library from an attacker-writable location. Confirm its actual load behavior rather than assuming it.

## Remediation

Quote paths, use a least-privileged service account, lock down service and filesystem ACLs, remove unnecessary writable directories from search paths, and monitor service configuration changes.

## Connections

- Topic map: [[windows-prev-ex]]
- Permission model: [[Windows Security Model]]
