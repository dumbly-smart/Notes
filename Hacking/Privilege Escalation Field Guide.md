---
type: guide
status: seed
created: 2026-08-21
aliases:
  - PrivEsc Field Guide
  - OSCP Privilege Escalation Guide
tags:
  - hacking
  - privilege-escalation
  - oscp
---

# Privilege escalation field guide

> [!summary] A practical, evidence-led guide
> Privilege escalation is the process of moving from an initial, limited identity to a more capable one. This guide covers Linux, Windows, and Active Directory workflows for authorized labs and assessments.

> [!warning] Authorization and safety
> Use these techniques only on systems you own or are explicitly authorized to test. Begin with read-only enumeration, preserve evidence, and choose the least disruptive validation method.

## How to use this guide

1. Identify the current identity and the intended objective.
2. Enumerate systematically instead of trying techniques at random.
3. Convert observations into testable hypotheses.
4. Verify every prerequisite before making a change.
5. Record the exact evidence, impact, and remediation.

## Core concepts

### Authentication, authorization, and accounting

- **Authentication** answers: “who are you?”
- **Authorization** answers: “what may you do?”
- **Accounting** records: “what did you do, and when?”
- Privilege escalation is usually an authorization failure.
- Credential discovery can turn into authentication as a different identity.
- A local administrator is not necessarily a domain administrator.

### Read the context before the system

- Confirm the written scope, target list, and maintenance window.
- Identify prohibited actions such as denial-of-service or password spraying.
- Record a support contact and stop condition.
- Use dedicated assessment accounts when supplied.
- Prefer a lab snapshot before validating risky local vulnerabilities.
- Do not assume that a CTF-style proof is safe in production.

### Evidence standard

A useful finding contains all of the following:

- The affected host and timestamp.
- The current account and privilege context.
- The vulnerable object or configuration.
- The exact permission, version, or policy that creates exposure.
- The preconditions required to reproduce it.
- A minimal proof of impact.
- A specific, actionable remediation.

## Universal workflow

### Phase 1: establish access context

Capture the current user, groups, hostname, OS version, architecture, IP configuration, and open network listeners.

Do not skip this phase. A technique that works on one version or service account may be irrelevant on another.

### Phase 2: map privilege boundaries

Look for boundaries that are intentionally delegated:

- `sudo`, SUID, SGID, Linux capabilities, cron, and systemd on Linux.
- Access tokens, privileges, services, tasks, registry keys, and UAC on Windows.
- Domain groups, ACLs, GPOs, shares, service accounts, and trusts in Active Directory.

### Phase 3: inspect inputs to privileged execution

Ask four questions for every privileged process:

1. Which account runs it?
2. Which binary, script, library, configuration, and working directory does it use?
3. Which of those inputs can the current identity change?
4. Can the process be triggered or will it execute on a known schedule?

### Phase 4: search for credentials deliberately

Focus on configuration, source code, history, backups, deployment artifacts, and shared folders.

Avoid indiscriminate collection. Handle passwords, hashes, private keys, tickets, and tokens as sensitive evidence.

### Phase 5: research version-specific paths last

Only after checking permissions and configuration should you assess a local application or kernel vulnerability.

Confirm product, version, architecture, vendor patch state, mitigation, and exploit prerequisites.

### Phase 6: validate and document

Use a harmless proof where possible:

- Demonstrate read access to a non-sensitive authorized test file.
- Demonstrate that a low-privileged account can modify a high-privileged launch path.
- Demonstrate a policy value or ACL rather than deploying a payload.
- Capture command output and restore any test changes.

## Linux privilege escalation

### Linux orientation

Linux separates kernel-space from user-space and represents users, groups, processes, files, and devices through a consistent permission model.

The root account has UID `0`, but “root” is not a technique. The task is to identify a flawed path that grants root-equivalent authority.

### First commands

```bash
id
whoami
hostname
uname -a
cat /etc/os-release
pwd
env
```

Interpret output before moving on:

- `id` reveals UID, primary group, and supplementary groups.
- `uname -a` gives kernel and architecture clues.
- `/etc/os-release` identifies distribution packaging and support context.
- `env` can reveal application paths, proxy settings, and accidental secrets.
- `pwd` tells you whether you are already in an application or home directory.

### Process and network enumeration

```bash
ps auxww
ps -ef --forest
ss -lntup
ip a
ip r
```

Look for services running as `root`, dedicated service users, and unexpected local listeners.

For each process, identify its command line, binary path, user, parent process, configuration files, and restart mechanism.

### Filesystem fundamentals

The first character in `ls -l` is file type:

- `-` regular file.
- `d` directory.
- `l` symbolic link.
- `s` socket.
- `p` named pipe.
- `b` or `c` device.

The remaining permission bits are owner, group, and other:

```text
-rwxr-x---
 ||| ||| |||
 ||| ||| ||+-- other
 ||| ||+---- group
 ||+------ owner
```

On a file, read allows content access, write allows modification, and execute allows execution.

On a directory, read lists names, write creates/removes entries, and execute permits traversal.

Directory write without careful ownership can be particularly dangerous because it can alter a privileged process’s path to a file.

### Useful filesystem checks

```bash
ls -alh <path>
find / -xdev -type d -writable 2>/dev/null
find / -xdev -type f -writable 2>/dev/null
find /home /opt /var/www -type f -readable 2>/dev/null
```

Use `-xdev` to keep a search on the current filesystem when appropriate.

Assess ownership, group membership, ACLs, mount options, and whether a privileged process actually uses the discovered path.

### SUID and SGID

SUID means an executable runs with the effective UID of its owner.

SGID means an executable runs with the effective group ID of its owner; on a directory it can cause new files to inherit the directory’s group.

```bash
find / -type f -perm -4000 -ls 2>/dev/null
find / -type f -perm -2000 -ls 2>/dev/null
```

In a permission string, a lowercase `s` indicates the special bit and execute bit are both set.

Examples such as `passwd` are expected to be SUID root because they need controlled access to protected account data.

Unexpected SUID binaries deserve careful review, especially custom programs, interpreters, editors, file-transfer utilities, and programs with shell escapes.

### SUID review checklist

- Is the binary vendor-supplied and expected on this host?
- Who owns it, and can any unprivileged user modify it?
- Does it invoke another command using a relative path?
- Does it accept a user-controlled file, configuration, plugin, or environment variable?
- Does it preserve a privileged effective UID while launching an interpreter?
- Does it drop privilege before handling untrusted input?

### Sudo

`sudo` delegates specific commands to another account, usually root.

```bash
sudo -l
sudo -V
```

`sudo -l` is the definitive view of what the current user may run.

Read every command path, allowed argument, run-as user, `NOPASSWD`, `SETENV`, and wildcard.

High-risk rules commonly include broad `ALL` delegation, shells, editors, interpreters, archive tools, package managers, and commands that allow arbitrary file writes.

An allowed command is not necessarily exploitable, and an apparently restricted command can still be dangerous if its arguments are over-broad.

### Sudo hardening

- Use absolute paths.
- Restrict arguments precisely.
- Do not delegate general-purpose interpreters or editors unless necessary.
- Use a controlled `secure_path`.
- Avoid `SETENV` unless justified.
- Validate policy edits with `visudo -c`.

### Scheduled tasks

Cron and systemd timers execute work without an interactive user.

```bash
cat /etc/crontab
ls -al /etc/cron.d /etc/cron.daily /etc/cron.hourly 2>/dev/null
crontab -l
systemctl list-timers --all
systemctl cat <unit>
```

For each job, find its account, command, working directory, environment, and referenced scripts.

A root cron job is material only when an unprivileged user can control something it executes or consumes.

### Wildcard expansion

Shells expand filename patterns before the target program starts.

- `*` matches zero or more characters.
- `?` matches one character.
- `[abc]` matches one character in a set.
- `{a,b}` expands alternatives in shells that support brace expansion.

Danger arises when a privileged job expands attacker-controlled filenames and passes a name beginning with `-` to a program that treats it as an option.

Design scripts to use absolute paths, a controlled working directory, explicit file lists, and `--` before untrusted filenames.

### Linux capabilities

Capabilities split traditional root power into smaller rights.

```bash
getcap -r / 2>/dev/null
```

Examples include `cap_setuid`, `cap_setgid`, `cap_dac_override`, `cap_dac_read_search`, and `cap_sys_admin`.

Assess the executable, its effective capability set, and whether its user-controlled behavior can apply the capability beyond its intended purpose.

### Credentials and configuration

```bash
grep -RniE 'password|passwd|token|secret|api[_-]?key' /home /opt /var/www 2>/dev/null
find /home /opt /var/www -type f \( -name '*.conf' -o -name '*.bak' -o -name '*history*' \) -readable 2>/dev/null
```

Common locations include shell history, application configuration, CI/CD files, backups, deployment scripts, mounted shares, and private-key directories.

`/etc/passwd` contains account metadata; hashes are usually protected in `/etc/shadow`.

If authorized to perform offline password auditing, preserve originals and use copied evidence only.

### Kernel and local binaries

Kernel exploitation is disruptive and version-sensitive.

```bash
uname -r
cat /etc/os-release
```

Confirm the precise vendor build and patch status using authoritative advisories before considering it.

For native binaries, identify input surface and mitigations such as ASLR, NX, PIE, RELRO, and stack canaries.

Prefer a configuration or permission fix over an operational exploit whenever possible.

### Linux closeout checklist

- [ ] Current user and groups recorded.
- [ ] `sudo -l` reviewed.
- [ ] SUID/SGID and capabilities reviewed.
- [ ] Cron, timers, services, and writable execution paths reviewed.
- [ ] Sensitive configuration and backup locations checked within scope.
- [ ] Kernel/application version applicability verified before exploit research.
- [ ] Evidence and remediation captured.

## Windows privilege escalation

### Windows orientation

Windows authorization centers on security principals, SIDs, access tokens, ACLs, privileges, and integrity levels.

The relevant goal is usually to move from a standard user or constrained service account to local administrator or `NT AUTHORITY\SYSTEM`.

### First commands

```powershell
whoami /all
whoami /priv
whoami /groups
hostname
systeminfo
Get-ComputerInfo | Select WindowsProductName, WindowsVersion, OsBuildNumber
```

`whoami /all` presents user, group, privilege, logon, and integrity details in one place.

Record the Windows build and hotfix context before researching local vulnerabilities.

### CMD and PowerShell

CMD is the legacy command processor.

PowerShell works with .NET objects and management interfaces, so it is normally more useful for structured local enumeration.

Useful CMD commands include `tasklist /v`, `ipconfig /all`, `netstat -ano`, `sc query`, and `schtasks /query /fo LIST /v`.

Useful PowerShell commands include `Get-Process`, `Get-Service`, `Get-CimInstance`, `Get-ScheduledTask`, and `Get-Acl`.

### SIDs and tokens

A SID uniquely identifies a user, group, computer, or other security principal.

An access token is the security context attached to a process or thread.

The token includes user/group SIDs, privileges, a logon session, and an integrity level.

Authorization evaluates the requested operation against object ACLs and the token.

### NTFS permissions

```powershell
icacls <path>
Get-Acl <path> | Format-List
```

Look for `FullControl`, `Modify`, `Write`, and rights that allow changing an owner or ACL.

Check both files and parent directories because a writable directory can allow replacement or redirection.

Do not conclude escalation from a writable item until proving that a higher-privileged process uses it.

### Mandatory Integrity Control

Windows adds integrity labels such as Low, Medium, High, and System.

Integrity control is separate from normal ACL evaluation.

UAC commonly gives an administrator a filtered medium-integrity token and an elevated high-integrity token.

### Services

Services often run as `LocalSystem`, `LocalService`, `NetworkService`, or a domain/local service account.

```powershell
Get-CimInstance Win32_Service | Select Name, StartName, State, PathName
sc.exe qc <service>
sc.exe query <service>
```

Inspect the service object ACL, configured account, binary path, arguments, directories, executable, dependencies, and restart behavior.

### Weak service permissions

An escalation condition may exist if a low-privileged user can change a high-privileged service’s configuration or start/stop it after modifying its executable path.

Validate the service DACL separately from file-system permissions.

Service configuration access and binary-write access are distinct conditions.

### Unquoted service paths

An unquoted executable path containing spaces can be parsed ambiguously.

The issue is exploitable only when a candidate earlier path is writable and the service can be started or restarted in a higher privilege context.

Quoted paths are the normal remediation.

### DLL search paths

Windows applications may search several directories when loading a DLL.

Potential exposure requires evidence that the specific process loads a missing or controllable library from a location writable by the current user.

Verify with process behavior and application documentation; do not assume every writable DLL-named path is loaded.

### Scheduled tasks and startup

```powershell
schtasks /query /fo LIST /v
Get-ScheduledTask | Select TaskName, TaskPath, State
reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

Review the task principal, action, trigger, and the permissions of every executable or script it uses.

For startup entries, distinguish user-level persistence from execution by an elevated account.

### Windows Installer policy

`AlwaysInstallElevated` is a risky policy when enabled in both per-machine and per-user Installer policy locations.

The key lesson is configuration review: policy must be checked in both places, and remediation should disable the setting unless there is a documented need.

### UAC and privileges

UAC is a usability control that helps limit accidental use of administrative privileges.

It is not a security boundary between separate users.

`whoami /priv` lists token privileges such as `SeImpersonatePrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, and `SeDebugPrivilege`.

The presence of a privilege is not enough; its enabled state, service context, build, and additional prerequisites determine impact.

### Credentials and sensitive files

```powershell
cmdkey /list
Get-ChildItem Env:
Get-ChildItem -Path C:\Windows\Panther -ErrorAction SilentlyContinue
```

Search approved locations for unattended-install files, application configuration, scripts, PowerShell history, mapped drives, deployment artifacts, and backups.

The SAM is a protected local account credential store; its existence does not imply low-privileged access.

Handle recovered secrets and hashes under the assessment’s evidence-handling rules.

### Windows security tools

Local enumeration tools can save time but may generate endpoint alerts or be blocked.

Use them only when permitted, understand every reported condition, and preserve their output as supporting—not sole—evidence.

Examples often used in labs include winPEAS, PowerUp, PrivescCheck, and Seatbelt.

### Windows closeout checklist

- [ ] User, groups, privileges, integrity, and OS build recorded.
- [ ] Services and service ACLs examined.
- [ ] Binary paths, directories, DLL loading, and restart conditions verified.
- [ ] Scheduled tasks and startup paths reviewed.
- [ ] Registry and installer policy checked.
- [ ] Authorized secret locations examined.
- [ ] Patch level confirmed before local exploit research.

## Active Directory exploitation

### What Active Directory provides

Active Directory centralizes identity, authentication, authorization, directory queries, and policy for a Windows domain.

It is an ecosystem rather than a single service: AD-integrated DNS, LDAP, Kerberos, SMB, GPOs, and Windows hosts all interact.

### Core components

- **Domain controller:** stores directory data and authenticates domain principals.
- **Domain:** an administrative/security boundary with a shared directory.
- **Forest:** one or more domains sharing schema and configuration.
- **Organizational unit:** a container for organization and delegated administration.
- **Group Policy Object:** centrally applied configuration.
- **LDAP:** directory query/update protocol.
- **SYSVOL:** replicated policy and logon-script content.
- **NTDS.dit:** directory database on a DC.
- **Global Catalog:** searchable partial replica across the forest.

### Lab preparation

Build an isolated lab with a domain controller, a joined workstation, separate test accounts, internal-only networking, and snapshots.

Record the domain name, DC IP, DNS configuration, account roles, and time source.

Do not connect an intentionally vulnerable lab DC to a production network.

### Domain-controller service map

| Port | Typical service | Why it matters |
| --- | --- | --- |
| 53 | DNS | Domain records and discovery |
| 88 | Kerberos | Domain ticket authentication |
| 135 | RPC | Windows management endpoints |
| 139/445 | SMB | Shares and remote administration |
| 389/636 | LDAP/LDAPS | Directory services |
| 464 | Kerberos password change | Account password operations |
| 3268/3269 | Global Catalog | Forest-wide directory queries |
| 5985/5986 | WinRM | Remote management |

The service list guides investigation; no port alone proves a vulnerability.

### Initial network discovery

```bash
nmap -sC -sV -Pn <dc-ip>
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
```

Synchronize time before Kerberos troubleshooting.

Record whether SMB signing, LDAP signing, and channel binding are required.

Avoid broad password attempts and relay activity unless written authorization explicitly permits them.

### LDAP and directory data

LDAP exposes directory objects such as users, groups, computers, OUs, and service accounts.

With approved credentials, enumerate only the data necessary to build an access graph.

Prioritize group membership, delegated rights, SPNs, GPO links, and permissions on sensitive objects.

### SMB fundamentals

SMB provides file, printer, and named-pipe sharing.

```bash
smbclient -L //<host> -N
smbmap -H <host>
netexec smb <host>
```

Anonymous access is worth checking, but lack of anonymous access is normal.

With permitted credentials, enumerate shares, access rights, and files without modifying data.

### SMB assessment questions

- Are guest or anonymous shares exposed?
- Do shares contain configuration, scripts, backups, or sensitive documents?
- Is SMB signing required and enforced?
- Is SMBv1 disabled?
- Do credentials have administrative-share access?
- Are local administrator passwords reused across hosts?

Captured Net-NTLM material is sensitive authentication data, not a plaintext password.

SMB signing reduces the feasibility of many relay scenarios; verify policy rather than relying on assumptions.

### Kerberos foundations

Kerberos uses a Key Distribution Center (KDC) to issue tickets and session-key material.

The KDC combines an Authentication Service (AS) and Ticket Granting Service (TGS).

A principal can be a user, computer, or service.

A realm normally corresponds to the AD domain.

### Kerberos ticket flow

1. The client sends an AS-REQ to authenticate and request a Ticket Granting Ticket (TGT).
2. The KDC returns an AS-REP with a TGT and session-key material.
3. The client uses its TGT in a TGS-REQ for a service principal name.
4. The KDC returns a TGS-REP containing a service ticket.
5. The client presents the service ticket in an AP-REQ to the service.
6. The service may respond with AP-REP for mutual authentication.

Kerberos depends on DNS and clock synchronization. Diagnose those basics before assuming an attack or configuration failure.

### User enumeration risk

An authentication endpoint can expose valid usernames through response messages, error codes, or timing differences.

This is a security risk because valid names improve later credential attacks.

Use consistent failures where practical, rate-limit abuse, and monitor unusual authentication volume.

### AS-REP roasting

AS-REP roasting applies to accounts configured without Kerberos pre-authentication.

For such an account, ticket material protected using a key derived from the account password can be requested and then guessed offline.

The root causes are disabled pre-authentication and weak/reused passwords.

Remediate by requiring pre-authentication, using strong unique passwords, and monitoring suspicious AS-REQ activity.

### Kerberoasting

Kerberoasting targets service accounts with SPNs.

An authenticated domain user can request service tickets; the ticket material can be subject to offline guessing against the service account secret.

Strong, unique, managed service-account passwords and limited SPN assignment reduce this risk.

Monitor anomalous requests for service tickets, especially unusual volume or encryption types.

### Delegation and ACLs

AD attack paths frequently arise from excessive permissions rather than software flaws.

Review object ownership, generic write/all rights, password-reset rights, group-management rights, GPO edit rights, and delegation settings.

An ACL finding should be explained as a graph edge: which principal can change which object, and what higher privilege would that change produce?

### Trusts

Trusts determine how identities can be authenticated across domains or forests.

Document trust direction, transitivity, selective authentication, SID filtering, and the actual permissions granted after crossing the trust.

Do not assume that a trust automatically creates administrative access.

### AD assessment workflow

1. Confirm scope and test accounts.
2. Identify domain, DCs, DNS, and time source.
3. Map exposed services and security settings.
4. Enumerate approved directory information.
5. Inspect groups, ACLs, GPOs, shares, service accounts, and trusts.
6. Build a minimal candidate path to the objective.
7. Validate the path safely and document remediation.

### AD reporting checklist

- [ ] Domain, forest, and affected hosts identified.
- [ ] Relevant principal and object names documented.
- [ ] Exact ACL, policy, service, or configuration captured.
- [ ] Preconditions and authentication level described.
- [ ] Minimal impact proof recorded.
- [ ] Sensitive tickets, hashes, and passwords excluded from general notes.
- [ ] Remediation includes an owner and verification step.

## Quick reference tables

### Linux priority order

| Priority | Check | Reason |
| --- | --- | --- |
| 1 | `sudo -l` | Explicit delegated authority |
| 2 | SUID/SGID and capabilities | Special execution privileges |
| 3 | Cron, timers, systemd | Privileged automation |
| 4 | Services and writable paths | Controlled privileged inputs |
| 5 | Credentials and backups | Identity switching opportunities |
| 6 | Kernel/local CVEs | Risky and version-specific |

### Windows priority order

| Priority | Check | Reason |
| --- | --- | --- |
| 1 | Token and OS build | Defines current boundary |
| 2 | Services and ACLs | Frequent local escalation paths |
| 3 | Tasks, startup, registry | Privileged launch points |
| 4 | Credentials/configuration | May enable higher identity |
| 5 | UAC and privileges | Context-dependent authority |
| 6 | Local CVEs | Last-resort version-specific work |

### AD priority order

| Priority | Check | Reason |
| --- | --- | --- |
| 1 | Domain discovery and DNS | Establishes environment |
| 2 | LDAP, groups, ACLs | Reveals authorization graph |
| 3 | SMB and shares | Finds data and management paths |
| 4 | Kerberos configuration | Identifies account risks |
| 5 | GPOs, delegation, trusts | Identifies cross-object paths |
| 6 | Validate one path | Avoids noisy technique collection |

## Connections

- Linux notes: [[linux-prev-ex]]
- Windows notes: [[windows-prev-ex]]
- Directory notes: [[active-directory-exploitation]]
- Parent map: [[Hacking]]
- Source series: [LeonardoE95/yt-en](https://github.com/LeonardoE95/yt-en/tree/main/src)
