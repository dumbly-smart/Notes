---
type: note
status: seed
created: 2026-08-21
aliases:
  - Cron Jobs and Wildcard Expansion
tags:
  - hacking/linux
  - linux/cron
  - linux/privilege-escalation
---

# Linux scheduled tasks and wildcards

> [!summary] Privileged automation inherits its inputs
> Cron, systemd timers, and backups are important escalation surfaces when a privileged task executes a writable script or expands attacker-controlled filenames.

## Find scheduled work

```bash
cat /etc/crontab
ls -al /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null
crontab -l
systemctl list-timers --all
systemctl cat <unit>
```

Check the user that runs the task; its executable, working directory, environment, and every referenced script or directory. A writable file is only material if a more-privileged process actually consumes it.

## Wildcard expansion

The shell expands patterns before invoking a command: `*` matches many characters, `?` one character, and bracket patterns match sets/ranges. If a privileged script passes `*` to a utility that interprets filenames beginning with `-` as options, filenames can alter the utility's behavior.

Review backup/archive jobs using `tar`, `rsync`, `find`, or similar tools. Safe designs use absolute paths, a controlled working directory, `--` before untrusted filenames, and avoid shell globbing when an explicit file list is possible.

## Connections

- Topic map: [[linux-prev-ex]]
- Workflow: [[Linux Privilege-Escalation Methodology]]
