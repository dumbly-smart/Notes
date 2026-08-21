---
type: note
status: seed
created: 2026-08-21
aliases:
  - Windows PrivEsc Methodology
tags:
  - hacking/windows
  - windows/enumeration
  - windows/privilege-escalation
---

# Windows privilege-escalation methodology

> [!summary] Build a reproducible chain from current token to elevated context
> Start with the OS, user and token; then examine explicit delegation, privileged execution paths, exposed data, and patch state. Verify each condition before attempting any change.

## Order of operations

1. Identify the user, groups, privileges, integrity level, OS build, patches, and installed security controls.
2. Review services, scheduled tasks, startup entries, file/directory ACLs, and registry ACLs.
3. Search authorized locations for stored credentials and configuration secrets.
4. Evaluate UAC and token privileges in context.
5. Research local vulnerabilities only after exact version and mitigation validation.

## Useful collection commands

```powershell
whoami /all
systeminfo
Get-CimInstance Win32_Service | Select Name,StartName,PathName
schtasks /query /fo LIST /v
Get-HotFix
```

Automated tools such as winPEAS, PowerUp, PrivescCheck, and Seatbelt can accelerate collection, but their findings require manual validation and their use may be detected.

## Connections

- Topic map: [[windows-prev-ex]]
- Related: [[Windows Shell and Enumeration]]
