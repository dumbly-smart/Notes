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
whoami                 # Current user
id                     # User identity
hostname               # Host name
pwd                    # Working directory
env                    # Environment variables
echo "$SHELL"           # Login shell
which <command>         # Locate command
```

Absolute paths begin at `/`; relative paths begin at the current directory.

## Files and resources

```bash
ls -alh                # List files
cd <path>              # Change directory
cp <src> <dst>         # Copy file
mv <src> <dst>         # Move file
rm <path>              # Remove file

df -h                  # Filesystem usage
du -h <path>           # Directory usage
fdisk -l               # List partitions
ps aux                 # List processes
ps -axjf               # Process hierarchy
ip a                   # Network addresses
netstat -ltp           # Listening ports
```

## Users and groups

```bash
sudo useradd -m <user>          # Create user
sudo passwd <user>              # Change password
sudo userdel -r <user>          # Delete user
sudo groupadd <group>           # Create group
sudo usermod -aG <group> <user> # Add membership
groups <user>                   # List memberships
cat /etc/passwd                 # Account metadata
sudo cat /etc/shadow            # Password hashes
```

## Packages

```bash
apt search <term>          # Search packages
sudo apt update           # Refresh indexes
sudo apt install <package> # Install package
sudo apt upgrade          # Upgrade packages
sudo apt purge <package>   # Remove package
```

## Connections

- Topic map: [[linux-prev-ex]]
- Parent map: [[Hacking]]
