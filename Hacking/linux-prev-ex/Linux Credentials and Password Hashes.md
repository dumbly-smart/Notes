---
type: note
status: seed
created: 2026-08-21
aliases:
  - Linux Unshadow Attack
tags:
  - hacking/linux
  - linux/credentials
  - linux/privilege-escalation
---

# Linux credentials and password hashes

> [!summary] Credentials often provide the cleanest path
> Readable secrets, password reuse, and backup files can yield legitimate account access; handle them as sensitive evidence and test only within authorization.

## Search deliberately

```bash
find /home /opt /var/www -type f \( -name '*.conf' -o -name '*.bak' -o -name '*history*' \) -readable 2>/dev/null
grep -RniE 'password|passwd|token|secret|api[_-]?key' /home /opt /var/www 2>/dev/null
cat /etc/passwd
```

`/etc/passwd` contains account metadata; password hashes normally reside in `/etc/shadow` and should not be broadly readable. Configuration files, shell histories, deployment artifacts, private keys, and mounted backups are common exposure points.

## Offline hash workflow

When an approved assessment provides matching passwd/shadow data, `unshadow` can combine them into input for an offline password-auditing tool. Preserve the original evidence, use a copy, and never disclose recovered passwords in notes or reports beyond the approved audience.

## Connections

- Topic map: [[linux-prev-ex]]
- Workflow: [[Linux Privilege-Escalation Methodology]]
