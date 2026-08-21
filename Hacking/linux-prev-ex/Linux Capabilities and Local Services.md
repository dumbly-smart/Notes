---
type: note
status: seed
created: 2026-08-21
aliases:
  - Linux Capabilities
  - Local Service Exploitation
tags:
  - hacking/linux
  - linux/capabilities
  - linux/services
---

# Linux capabilities and local services

> [!summary] Root privileges can be split up
> Linux capabilities grant narrow privileged operations to processes. They are safer than full SUID in principle, but a capability on an interpreter or network-facing service can still be high impact.

## Enumerate capabilities and services

```bash
getcap -r / 2>/dev/null
ps auxww
ss -lntup
systemctl --type=service --state=running
systemctl cat <service>
```

Useful capability names include `cap_setuid`, `cap_setgid`, `cap_dac_override`, `cap_dac_read_search`, and `cap_sys_admin`. Determine which executable has the capability, whether untrusted users control its arguments/configuration, and whether the capability is in its effective set.

## Local-service review

For each listening service, identify the owning process, account, binary path, unit file, configuration, logs, and Unix socket permissions. Look for weak file ownership, insecure plugin/search paths, credentials in configuration, and a local-only management endpoint that is reachable from the current account.

## Connections

- Topic map: [[linux-prev-ex]]
- Related: [[Linux SUID and SGID]], [[Linux Privilege-Escalation Methodology]]
