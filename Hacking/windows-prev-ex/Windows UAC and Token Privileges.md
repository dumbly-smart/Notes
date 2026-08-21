---
type: note
status: seed
created: 2026-08-21
aliases:
  - SeImpersonatePrivilege
  - UAC Bypass
tags:
  - hacking/windows
  - windows/uac
  - windows/tokens
---

# Windows UAC and token privileges

> [!summary] UAC is not a boundary between users
> User Account Control reduces accidental administrative use through split tokens and consent prompts. It is not a security boundary separating two different users or protecting against an administrator-level compromise.

## Token privileges

```powershell
whoami /priv
whoami /groups
```

Privileges such as `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeDebugPrivilege` can materially expand what a process may do. Their impact depends on whether they are present and enabled, the OS build, available services, and other preconditions.

## Assessment rules

Document the complete token state and the constrained service/account context that granted it. Validate privilege impact in an isolated authorized lab; public techniques can be version-specific and may trigger security controls. Remediation is to assign user rights sparingly, isolate service accounts, and keep Windows patched.

## Connections

- Topic map: [[windows-prev-ex]]
- Security model: [[Windows Security Model]]
