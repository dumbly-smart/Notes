---
type: note
status: seed
created: 2026-08-21
aliases:
  - Windows Permissions
  - Windows Access Tokens
tags:
  - hacking/windows
  - windows/permissions
  - windows/privilege-escalation
---

# Windows security model

> [!summary] Authorization is token-based
> Windows authenticates a security principal, then evaluates its access token—SIDs, group memberships, privileges, integrity level, and ACLs—when it accesses an object.

## Core terms

- A **SID** is the durable identifier for a user, group, computer, or other security principal. Local SIDs originate with the Local Security Authority; domain SIDs are issued by a domain controller.
- An **access token** represents a logon session and is attached to processes/threads.
- An **ACL** holds allow/deny rules for an object; `icacls` displays and changes NTFS ACLs.
- **Mandatory Integrity Control** adds integrity levels such as Low, Medium, High, and System. It is separate from ordinary discretionary ACLs.

## Enumerate access

```powershell
whoami /all
whoami /priv
whoami /groups
icacls <path>
Get-Acl <path> | Format-List
```

Treat permissive `Modify`, `Write`, or `FullControl` rights as leads, then prove whether a higher-privileged process uses that object. A writable file alone is not automatically privilege escalation.

## Connections

- Topic map: [[windows-prev-ex]]
- Related: [[Windows UAC and Token Privileges]], [[Windows Services]]
