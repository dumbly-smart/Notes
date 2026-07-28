# Host-Server Configuration Reviews

Source: [TryHackMe room](https://tryhackme.com/room/hostserverconfigurationreviews)

## Why configuration reviews matter

- Operating systems begin with default settings, then administrators add users, software, services, permissions, and other changes.
- Unsafe deviations can introduce privilege-escalation paths even when the installed software is fully patched.
- Common causes include oversight, convenience, and lack of security awareness.
- After gaining a low-privileged foothold, an attacker reviews the host for a path to administrator or root access.

## Two privilege-escalation categories

| Category | What it targets | Examples |
| --- | --- | --- |
| Vulnerability-based | Bugs in code | Kernel vulnerabilities, buffer overflows, known CVEs in services |
| Configuration-based | Insecure administrator decisions or setup | Excessive file permissions, insecure service settings, plaintext credentials in accessible locations |

### Key distinction

- **Vulnerability-based escalation** generally depends on vulnerable or unpatched software.
- **Configuration-based escalation** can work against a fully patched machine because the weakness is in how the system is configured.

## Review mindset

When reviewing a host, ask:

1. What changed from the secure/default configuration?
2. Which users, files, services, or credentials can the current account access?
3. Does any low-privileged user control something executed by a higher-privileged user?
4. Were permissions broadened for convenience?
5. Are secrets stored in plaintext or in locations accessible to unintended users?

> A patched host is not necessarily a securely configured host.
