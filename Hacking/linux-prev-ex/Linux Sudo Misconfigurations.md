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

## Deep dive: what sudo actually controls

`sudo` is a policy engine, not simply “run command as root.”

It decides who may run which command, as which target user, from which host, and with which arguments.

The policy can also decide whether a password is needed and which environment survives.

That means a correct audit begins with the effective policy rather than assumptions about group membership.

```bash
sudo -l
sudo -ll
```

`sudo -ll` can provide a more verbose listing on versions that support it.

Read the output one rule at a time.

Record the invoking user, run-as user, command path, argument restriction, tags, and defaults.

## Important sudoers concepts

`ALL` is a broad matcher and needs careful context.

`NOPASSWD` removes the authentication prompt for the matching command.

`SETENV` permits environment preservation or assignment beyond normal restrictions.

`NOEXEC` attempts to prevent a program from executing child processes.

`secure_path` can override the command-search path for sudo commands.

`runas` controls whether a rule runs as root or another account.

Command aliases make large policies easier to read but can hide breadth.

Included files under `/etc/sudoers.d` are part of the effective policy.

Only administrators should use `visudo` to change that policy.

## Why arguments matter

Allowing `/usr/bin/less /var/log/app.log` is meaningfully different from allowing `/usr/bin/less *`.

The first narrows the command to a specific resource.

The second may permit access to files the policy author did not intend.

Programs can interpret options, file names, configuration paths, environment variables, plugins, and shell escapes.

An audit must understand those interfaces.

Do not reduce the analysis to whether the binary name appears on a public list.

## Categories of risky delegates

Shells and interpreters execute supplied instructions.

Editors and pagers may open other files or invoke external commands.

Archive utilities can read/write paths and sometimes invoke helpers.

Package managers install code or run maintainer scripts.

Backup and synchronization tools may follow paths, execute hooks, or accept options from filenames.

Diagnostic tools may load plugins, configuration, or scripts.

Each category is a review starting point, not a conclusion.

## Safe validation strategy

First confirm the exact command and arguments shown by `sudo -l`.

Then consult the local manual page and program documentation.

In a permitted lab, select a non-destructive proof such as reading an approved test file.

Do not edit `/etc/sudoers`, alter production data, or install packages to “prove” a rule.

Capture the policy line and the minimal result.

If a rule is not exploitable, record why its path, arguments, and environment are effectively constrained.

That prevents weak reports and improves your future reasoning.

## Environment handling

The environment is process input.

Variables can affect command lookup, language runtimes, temporary files, configuration, plugin discovery, and network behavior.

Sudo normally filters dangerous variables.

This filtering is not a substitute for safe program design.

When `SETENV` or environment preservation is allowed, determine exactly which variables remain effective for the delegated program.

Avoid treating `LD_PRELOAD` or similar variables as universal techniques; secure execution frequently disables them.

## Policy review checklist

- Is every command an absolute path?
- Are arguments specific enough to enforce intent?
- Does the command expose arbitrary file read/write?
- Can it invoke an editor, shell, plugin, hook, or interpreter?
- Can a wildcard absorb option-like filenames?
- Does the rule preserve dangerous environment state?
- Is the run-as account broader than necessary?
- Is `NOPASSWD` justified and monitored?

## Remediation principles

Delegate a small purpose-built wrapper instead of a general utility when possible.

The wrapper should use absolute paths and fixed arguments.

It should validate every user-supplied value against an allowlist.

It should run with the minimum account and privilege required.

Keep sudoers fragments owned by root and unreadable/writable only as policy requires.

Review policy after package or operational changes.

## Study exercise

Write a hypothetical rule that lets an operator restart one service.

Then explain why allowing `systemctl *` would be broader than that job requires.

Rewrite it with an absolute path, a fixed unit name, and no environment inheritance.

Finally, describe how you would test the policy without changing a production service.
