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

## Deep dive: identities during execution

Linux keeps several identity values for a process because a program may need to temporarily use authority without losing track of its caller.

The **real UID** is normally the user who launched the process.

The **effective UID** is normally the identity used for access-control checks.

The **saved UID** lets a program safely drop and later regain an effective identity when designed correctly.

The analogous real, effective, and saved group IDs exist for groups.

A SUID root program therefore does not make every line of code “root magic.”

It starts with a privileged effective identity and must carefully decide when that identity is needed.

`passwd` is the classic legitimate example.

It needs controlled access to password data that ordinary users cannot write directly.

It should not expose a general root shell, arbitrary file write, or arbitrary command execution while privileged.

That design distinction is the basis of SUID auditing.

## Deep dive: interpreting special mode bits

The owner execute position may contain `s` or `S`.

Lowercase `s` means SUID and execute are both set.

Uppercase `S` means SUID is set but execute is absent.

The group execute position uses the same notation for SGID.

The other-user execute position may show `t` or `T` for the sticky bit.

The sticky bit is unrelated to identity changes.

On a shared writable directory, it prevents users from deleting files they do not own.

Typical examples include `/tmp` and `/var/tmp`.

Use `stat` when you need an unambiguous numeric and ownership view.

```bash
stat /path/to/file
ls -l /path/to/file
```

## Deep dive: a safe audit sequence

Start with an inventory, not execution.

```bash
find / -xdev -type f -perm -4000 -print 2>/dev/null
find / -xdev -type f -perm -2000 -print 2>/dev/null
```

`-xdev` keeps the search on the current filesystem.

That reduces noise from mounted shares, containers, and pseudo-filesystems.

For every candidate, record its full path, owner, group, mode, package, and modification time.

```bash
ls -l <binary>
stat <binary>
dpkg -S <binary> 2>/dev/null
rpm -qf <binary> 2>/dev/null
```

A binary managed by the distribution is not automatically safe.

It is, however, easier to compare against expected behavior and security updates.

Custom binaries deserve a higher level of scrutiny.

## Deep dive: inputs that deserve review

Review command-line arguments first.

Ask whether an argument is interpreted as a filename, an option, a configuration path, or code.

Review environment variables next.

Ask whether the program trusts `PATH`, a home directory, locale, editor, pager, temporary directory, or language-specific module path.

Review its current directory and all relative file references.

Review temporary-file creation for predictable names, unsafe permissions, and race windows.

Review external command execution.

Absolute command paths are safer than relying on `PATH`.

Direct argument execution is safer than building a shell command string.

Review dynamic loading, plugins, configuration files, and helper programs.

The core rule is simple: privileged code must not interpret attacker-controlled data as an instruction.

## SGID directories and shared data

SGID on a directory is often intentional.

It makes newly created entries inherit the directory’s group.

Teams use this behavior to share project files without manually changing every group.

The security review still matters.

If that group has access to a privileged service’s configuration or executable content, group membership may become significant.

Check the directory’s write and execute permissions, its ACLs, and the service that consumes files from it.

Never judge a mode bit without its path and usage context.

## Common false positives

Finding `/usr/bin/passwd` is expected on most Linux systems.

Finding a SUID binary does not prove a vulnerability.

Finding an interpreter with SUID set is concerning, but modern interpreters may deliberately drop privileges.

Finding a writable file beside a SUID binary is not enough unless the binary reads or loads it.

Finding a known utility on a public technique list does not prove that its SUID behavior remains privileged on this distribution.

Validate the actual binary and version in an authorized lab.

## Defensive design and remediation

Remove SUID and SGID bits from software that does not require them.

Prefer narrow capabilities or a brokered service when a program needs one limited privileged action.

Use absolute paths for executables and configuration files.

Sanitize the environment before privileged work.

Drop effective privilege before parsing untrusted input whenever possible.

Use safe temporary-file APIs and restrictive modes.

Monitor changes to special-permission files with file-integrity tooling.

## Study exercise

In a disposable VM, list SUID binaries and classify each as expected, unexpected, or unknown.

For one expected program, explain why it needs privilege and what untrusted inputs it handles.

For one custom lab program, draw the path from your account to its effective UID.

Then write a remediation that removes the unsafe input rather than merely hiding the binary.
