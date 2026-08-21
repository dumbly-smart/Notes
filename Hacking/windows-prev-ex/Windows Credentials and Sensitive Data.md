---
type: note
status: seed
created: 2026-08-21
aliases:
  - Windows Hashes
  - Stored Credentials
tags:
  - hacking/windows
  - windows/credentials
  - windows/privilege-escalation
---

# Windows credentials and sensitive data

> [!summary] Look for exposure, not just password files
> Privilege escalation often follows credential discovery: unattended-install files, scripts, saved credentials, registry settings, backups, and application configuration can expose reusable secrets.

## Read-only discovery

```powershell
cmdkey /list
Get-ChildItem -Path C:\ -Include *.config,*.ini,*.xml,*.txt -Recurse -ErrorAction SilentlyContinue
reg query HKLM /f password /t REG_SZ /s
Get-ChildItem Env:
```

Check common locations such as `C:\Windows\Panther`, `C:\Unattend.xml`, user profile histories, deployment shares, IIS/application configuration, backup archives, and mapped drives. Record only the minimum evidence necessary; credentials and hashes are sensitive data.

## Hash context

Windows local account credential material is associated with the SAM database; domain credential data resides on domain controllers. Obtaining protected credential stores generally requires elevated access—do not treat their presence as proof of a low-privilege path.

## Connections

- Topic map: [[windows-prev-ex]]
- Domain context: [[active-directory-exploitation]]
