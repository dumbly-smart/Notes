---
type: note
status: seed
created: 2026-08-21
aliases:
  - Sudo Exploitation
tags:
  - hacking/linux
  - linux/sudo
  - linux/privilege-escalation
---

# Linux sudo misconfigurations

> [!summary] Inspect delegation, not just membership
> `sudo` grants selected commands as another user, commonly root. A rule can be risky even when it does not literally say `ALL`.

## Enumerate the effective policy

```bash
sudo -l
sudo -V
```

Read command paths, permitted arguments, `NOPASSWD`, `SETENV`, `NOEXEC`, run-as users, and included configuration files. Do not edit `/etc/sudoers`; use `visudo` only when administering an authorized system.

## Common risky rule patterns

- `ALL` or an interactive shell/editor/interpreter as root.
- A program with a documented shell escape, plugin mechanism, or arbitrary file write.
- Wildcards that make an argument broader than intended.
- Relative commands or a writable directory earlier in `secure_path`/`PATH`.
- `SETENV` combined with programs affected by environment variables.

## Validate a finding

Confirm the exact command is authorized and that its documented options permit the claimed action. Record the complete `sudo -l` line and the program version. Prefer a harmless proof—such as an allowed read of a root-owned test file—in an approved lab.

## Defenses

Allow only absolute command paths and narrow arguments, avoid shells and interpreters, set a controlled `secure_path`, require authentication where practical, and review changes with `visudo -c`.

## Connections

- Topic map: [[linux-prev-ex]]
- Related: [[Linux Scheduled Tasks and Wildcards]]
