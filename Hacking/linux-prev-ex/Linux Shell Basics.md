---
type: note
status: seed
created: 2026-08-16
aliases:
  - Linux Basics
tags:
  - hacking/linux
  - linux/enumeration
---

# Linux shell basics

> [!summary] First-pass Linux orientation
> Identify the current user, host, environment, filesystem, resources, and software before deeper [[linux-prev-ex|privilege-escalation]] checks.

## Shell model

`user ↔ terminal ↔ TTY ↔ shell`

- A terminal displays output and forwards input.
- The TTY manages terminal communication.
- A shell such as Bash interprets and runs commands.

## Quick enumeration

```bash
whoami                 # current username
id                     # UID, GID, and groups
hostname               # host name
pwd                    # current directory
env                    # environment variables
echo "$SHELL"           # configured shell
which <command>         # command resolved through $PATH
```

Absolute paths begin at `/`; relative paths begin at the current directory.

## Files and resources

```bash
ls -alh                # detailed directory listing
cd <path>              # change directory
cp <src> <dst>         # copy
mv <src> <dst>         # move or rename
rm <path>              # remove carefully

df -h                  # filesystem space
du -h <path>           # path size
fdisk -l               # disks and partitions
ps aux                 # processes
ps -axjf               # process hierarchy
ip a                   # network interfaces
netstat -ltp           # listening TCP ports and owners
```

## Users and groups

- `/etc/passwd` records account metadata; `/etc/shadow` stores password hashes and is normally root-readable only.
- `groups <user>` lists memberships.
- Administrative commands include `useradd`, `passwd`, `userdel`, `groupadd`, and `usermod -aG`.

## Packages

```bash
apt search <term>
sudo apt update
sudo apt install <package>
sudo apt upgrade
sudo apt purge <package>
```

## Connections

- Topic map: [[linux-prev-ex]]
- Parent map: [[Hacking]]

