# archlock

A modular, reversible hardening tool for Arch Linux workstations.

archlock applies sensible security defaults without blindly overwriting your system.  
Every change is tracked. Every file is backed up. Every module can be reverted — even after reboot.

This is not a compliance tool.  
This is not a replacement for SELinux.  
This is structured, transparent baseline hardening for personal Arch systems.

---

## Scope & Threat Model

archlock is designed for:

- Personal Arch Linux workstations and laptops
- Users who want reduced attack surface without breaking usability
- Systems where the owner has full root access and reviews changes

archlock is **not** designed for:

- Enterprise deployments
- CIS or compliance requirements
- High-assurance or nation-state threat environments
- Fully automated configuration management

If you need those, look at dedicated frameworks instead.

---

## Design Principles

- **Reversibility first** – Every change is logged and restorable
- **No destructive defaults** – No silent overwrites
- **Explicit risk levels** – High-impact modules are clearly marked
- **Minimal surface area** – Only enable what you choose
- **Readable architecture** – Config generation is pure and side-effect free

---

## Features

- Modular architecture (apply only what you need)
- Persistent state tracking (`/var/lib/archlock/state.json`)
- Verified backups with SHA256 checksums
- Atomic file writes (no partial configs)
- Safe interruption handling (Ctrl+C triggers rollback)
- Read-only system audit mode
- Presets for common setups (desktop, server, hardened)

---

## Installation

```bash
git clone https://github.com/yourusername/archlock.git
cd archlock

chmod +x archlock.py
sudo cp archlock.py /usr/local/bin/archlock
```

Python 3.6+ required.

Each module checks for its own package dependencies (e.g. `nftables`, `apparmor`, `audit`). Missing dependencies are reported before changes are made.

---

## Usage

Most commands require root (`sudo`).

### Inspect

```bash
archlock list
archlock status
archlock doctor
archlock audit
archlock backups --days 7 --limit 20
```

### Apply a Module

```bash
archlock apply firewall
archlock apply firewall --profile workstation
archlock apply kernel --dry-run
archlock apply usb_lockdown --force
archlock apply apparmor --verify
```

### Apply a Preset

```bash
archlock apply --preset desktop
archlock apply --preset server
archlock apply --preset hardened
```

### Revert

```bash
archlock revert firewall
archlock revert usb_lockdown
```

Revert restores original files or removes newly created ones.

---

## Modules

| Module            | Risk   | Description |
|-------------------|--------|-------------|
| firewall          | medium | nftables baseline (isolated table) with profiles |
| apparmor          | high   | Enable and enforce AppArmor |
| kernel            | medium | Sysctl hardening |
| services          | high   | Disable unnecessary services |
| firejail          | medium | Minimal sandbox profiles for browsers |
| auditd            | medium | Enable auditd with basic monitoring rules |
| usb_lockdown      | high   | Blacklist usb-storage module |
| systemd_sandbox   | high   | Harden selected systemd services |

High-risk modules may affect hardware, networking, or boot behavior. Review before applying.

---

## How It Works

- State file: `/var/lib/archlock/state.json`
- Backups: `/var/backups/archlock/`
- Each backup includes a SHA256 checksum
- File writes are atomic (`write -> fsync -> rename`)
- Ownership and permissions are preserved
- Interruptions trigger automatic rollback

Internally, each module implements:

- `pre_check()`
- `gen_config()`  (pure configuration generation)
- `apply()`
- `revert()`
- `status()`
- `verify()`

`gen_config()` never performs side effects.

---

## Caveats

- AppArmor requires kernel support and boot parameters.
- USB lockdown disables USB storage devices.
- Strict firewall profiles may block outgoing connections.
- Service minimization may not match your setup.
- This tool assumes systemd (Arch default).

Use `--dry-run` when in doubt.

---

## License

MIT

No warranty. Review changes before applying them.
