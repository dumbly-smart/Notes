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

## Deep dive: scheduled execution models

Cron is a time-based scheduler.

Systemd timers pair a timer unit with a service unit.

Anacron runs periodic work on machines that are not always online.

At jobs schedule one-off commands.

Application frameworks may implement their own schedulers outside these standard locations.

The name of the scheduler matters less than the execution chain it creates.

Find the account, command, input, trigger, and error handling.

## Cron files explained

System-wide cron entries usually include a user field.

```text
minute hour day-of-month month day-of-week user command
```

User crontabs omit the user field because the owner is already known.

`/etc/crontab` and files in `/etc/cron.d` are system-wide locations.

The `/etc/cron.daily`, `cron.weekly`, and similar directories contain scripts launched by another scheduler.

Do not assume the directory name tells you the exact schedule; inspect the invoking configuration.

## Systemd timer files explained

`OnCalendar` describes calendar-based schedules.

`OnBootSec` and `OnUnitActiveSec` describe delays and intervals.

The timer normally activates a service with the matching base name or an explicit `Unit=` setting.

```bash
systemctl list-timers --all
systemctl cat <timer>.timer
systemctl cat <service>.service
```

Read both units.

The service unit tells you the actual `ExecStart`, `User`, `Group`, `WorkingDirectory`, `EnvironmentFile`, and hardening options.

## A complete audit sequence

Locate the job.

Identify the privilege level of its account.

Trace every command and script it invokes.

Check ownership, modes, ACLs, and parent directories for every referenced path.

Check command lookup and the working directory.

Check data directories, log files, archives, temporary files, and configuration inputs.

Determine whether the job can be triggered or when it will run.

Only then decide whether a low-privileged user controls a meaningful input.

## Wildcard expansion explained

Globbing is performed by the shell before a program receives arguments.

For example, `tool *` may become `tool a.txt b.txt report.log`.

The program does not know that the shell used a wildcard.

If a filename begins with `-`, a program may parse it as an option.

This is why archives and backup jobs should not expand untrusted directories carelessly.

It is not enough to create an unusual filename; the target program must support an option that changes security-relevant behavior.

## Safe scripting practices

Set a trusted `PATH` at the top of a privileged script.

Use absolute paths for commands and data.

Set a known working directory before operating on files.

Quote variable expansions unless intentional word splitting is required.

Use `--` before untrusted positional filenames when supported.

Avoid parsing `ls` output.

Use restricted permissions for scripts, configuration, logs, and state directories.

Run scheduled jobs under a dedicated low-privilege service account when root is unnecessary.

## Common false positives

A cron job is not vulnerable merely because it runs as root.

A writable file is not relevant if the job never reads it.

A wildcard is not automatically exploitable if the directory is trusted and option-like names are not controllable.

A systemd unit file owned by root is not weak simply because it can be read.

Always connect a controllable input to privileged execution.

## Evidence and remediation

Record the scheduler source, job schedule, execution identity, command chain, and weak object permissions.

Explain the impact as a causal chain rather than a command transcript.

Remediate by correcting ownership and ACLs, using absolute paths, avoiding unsafe globbing, and reducing the job account’s privilege.

After remediation, verify the job still completes successfully.

## Study exercise

Create a harmless timer in a disposable VM that writes a timestamp to a root-owned directory.

Trace it from the timer unit to the service unit to the script.

List every file and directory it depends on.

Then explain which single permission change would create risk and why.
