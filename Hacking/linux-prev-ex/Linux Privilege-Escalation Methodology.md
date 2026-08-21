---
type: note
status: seed
created: 2026-08-21
aliases:
  - Linux PrivEsc Methodology
tags:
  - hacking/linux
  - linux/enumeration
  - linux/privilege-escalation
---

# Linux privilege-escalation methodology

> [!summary] Work from evidence
> Enumerate the host, identify a privilege boundary that is genuinely misconfigured, validate it safely, then use the least disruptive authorized path to root.

## Triage checklist

```bash
id; whoami; hostname; uname -a
cat /etc/os-release
ps auxww
ss -lntup
ip a; ip r
sudo -l
```

Record the current user and groups, OS/kernel and architecture, listening services, network context, and every `sudo` rule. Treat automated enumerators as leads: verify their output manually before acting.

## High-value checks

```bash
# Files with special permissions
find / -type f -perm -4000 -ls 2>/dev/null
getcap -r / 2>/dev/null

# Scheduled execution
cat /etc/crontab
ls -al /etc/cron.* /var/spool/cron 2>/dev/null
systemctl list-timers --all

# Writable paths and local services
find / -xdev -type d -writable 2>/dev/null
systemctl --type=service --state=running
```

## Decision order

1. Check intended delegation: `sudo`, groups, SUID/SGID, capabilities, and service accounts.
2. Check execution paths controlled by a privileged process: cron, systemd units, writable scripts, `PATH`, and unsafe wildcard expansion.
3. Search for exposed credentials in readable configuration, history, backups, and mounted shares.
4. Consider a local binary or kernel vulnerability only after confirming the exact version, preconditions, impact, and scope.

## Reporting discipline

Preserve the command, relevant output, ownership and permissions, affected version, and the smallest reproducible proof. Avoid changing production configuration, deleting evidence, or blindly running public exploits.

## Connections

- Topic map: [[linux-prev-ex]]
- Primitives: [[Linux SUID and SGID]], [[Linux Sudo Misconfigurations]], [[Linux Capabilities and Local Services]]
