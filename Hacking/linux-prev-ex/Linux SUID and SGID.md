---
type: note
status: seed
created: 2026-08-21
aliases:
  - SUID Exploitation
tags:
  - hacking/linux
  - linux/suid
  - linux/privilege-escalation
---

# Linux SUID and SGID

> [!summary] Effective identity matters
> A SUID executable runs with its file owner's effective UID; SGID uses the file's group. These bits are legitimate delegation mechanisms but are dangerous on unnecessary or user-controlled programs.

## Identify special files

```bash
find / -type f -perm -4000 -ls 2>/dev/null   # SUID
find / -type f -perm -2000 -ls 2>/dev/null   # SGID
find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null
```

In `ls -l`, `s` replaces the executable bit: `-rwsr-xr-x` is SUID and `-rwxr-sr-x` is SGID. Uppercase `S` means the special bit is set but its corresponding execute bit is not.

## Assess safely

- Establish owner, package provenance, and whether the binary is expected (for example, `passwd` needs controlled access to password data).
- Check whether it invokes external programs without absolute paths, accepts user-controlled files, honors unsafe environment variables, or contains an embedded shell/interpreter.
- Compare unusual binaries against documented behavior. [GTFOBins](https://gtfobins.github.io/) is useful for assessing known Unix utilities, but only a permitted configuration is in scope.

## Why it becomes critical

The real UID identifies the invoking user; the effective UID controls many access checks. A root-owned SUID program that lets untrusted input influence a command, library, file, or interpreter may cross the boundary to root.

## Hardening

Remove unnecessary special bits, keep packages patched, avoid SUID on scripts, use absolute paths, sanitize the environment, and mount untrusted filesystems with `nosuid` where appropriate.

## Connections

- Topic map: [[linux-prev-ex]]
- Permission model: [[Linux File System Permissions]]
