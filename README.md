# ArchLinux-Security-Auditor

```markdown
# 🔒 archlock – Hardening for Arch Linux, but like, the sane way

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![Arch Linux](https://img.shields.io/badge/arch-linux-1793d1?logo=arch-linux)
![License](https://img.shields.io/badge/license-MIT-green)

**archlock** is a modular hardening tool for Arch Linux that **actually tells you what it's doing**, never overwrites files without asking, and keeps a persistent record of every change so you can revert even after a reboot.  

I wrote it because I was tired of copy‑pasting random forum snippets and hoping for the best. This is not Ansible. This is not SELinux. This is just a structured way to apply sensible defaults without shooting yourself in the foot.

---

## 🧠 Threat Model (read this before you rage)

This tool is designed for a **personal workstation or laptop**, **not** a production server.  
It aims to reduce attack surface while preserving usability for daily tasks.  
It assumes you have root access and are willing to **review changes**.  
It is **NOT** intended to withstand nation‑state attacks – it's a sensible baseline.  
It is **NOT** a CIS compliance tool and **NOT** a replacement for SELinux.

If you're a hardcore Arch user who hates colors and emoji, use `--quiet` and `--no-color` to get minimal, monochrome output. You do you.

---

## ✨ Features

- **Modular** – Pick and choose what you want (firewall, AppArmor, kernel tweaks, service minimizer, auditd, USB lockdown, systemd sandboxing…)
- **Reversible** – Every change is logged. `archlock revert firewall` puts everything back exactly how it was.
- **Safe by default** – Never overwrites without asking, shows diffs (with `--verbose`), creates backups with checksums.
- **Persistent state** – Changes survive reboots, stored in `/var/lib/archlock/state.json`.
- **Atomic writes** – No half‑written config files. If something fails, it rolls back cleanly.
- **Signal‑aware** – Hit `Ctrl+C` during an apply and it will roll back the changes already made.
- **Doctor & audit** – Read‑only scans to see what's going on (`archlock doctor`, `archlock audit`).
- **No bloat** – Only install what you need. Presets available for common setups.

---

## 📦 Installation

```bash
# Clone the repo (or just download the script)
git clone https://github.com/yourusername/archlock.git
cd archlock

# Make it executable and copy it somewhere in your PATH
chmod +x archlock.py
sudo cp archlock.py /usr/local/bin/archlock
```

Dependencies are checked per module – most modules require the corresponding packages (e.g., `nftables`, `apparmor`, `audit`). The tool will tell you if something is missing.

---

## 🚀 Usage

All commands need root (`sudo`) except `list`, `status`, `doctor`, `audit`, and `backups` (though backups live in `/var/backups/archlock`, so you might still need root to read them).

### Basic commands

```bash
# Show available modules and their current status
archlock list

# Show only the status (applied/partial/unknown)
archlock status

# Run a quick health check (read‑only)
archlock doctor

# Read‑only system security scan (listening ports, setuid bins, enabled services, sysctl values, AUR packages)
archlock audit

# List backup history (with optional filters)
archlock backups --days 7 --limit 20
```

### Applying modules

```bash
# Apply a module (you'll be prompted for each file change)
archlock apply firewall

# Apply with a specific profile (firewall only)
archlock apply firewall --profile workstation

# Preview changes without touching the system
archlock apply kernel --dry-run

# Skip confirmations and override conflict checks (use with caution!)
archlock apply usb_lockdown --force

# Verify after applying (runs module-specific checks)
archlock apply apparmor --verify

# Extra paranoid kernel settings
archlock apply kernel --paranoid
```

### Presets

Apply multiple modules at once:

```bash
archlock apply --preset desktop      # firewall, kernel, services, firejail
archlock apply --preset server       # firewall, kernel, services, auditd
archlock apply --preset hardened     # everything except maybe the kitchen sink
```

### Reverting

```bash
archlock revert firewall
archlock revert usb_lockdown
```

Revert will restore the exact file from backup (or delete files that were created).

---

## 🧩 Modules

| Module            | Kind       | Risk   | Description |
|-------------------|------------|--------|-------------|
| `firewall`        | firewall   | medium | nftables with profiles: workstation, server, paranoid, strict |
| `apparmor`        | mac        | high   | Enforce AppArmor, add kernel parameters, set common profiles to enforce |
| `kernel`          | kernel     | medium | sysctl hardening (kptr_restrict, dmesg_restrict, ASLR, etc.) |
| `services`        | service    | high   | List and optionally disable unnecessary services (avahi, cups, bluetooth, …) |
| `firejail`        | sandbox    | medium | Create basic firejail profiles for browsers (Firefox, Chromium, Brave) |
| `auditd`          | audit      | medium | Enable auditd with basic rules (file access, exec, mounts) |
| `usb_lockdown`    | filesystem | high   | Blacklist usb-storage module (use --force, this one hurts) |
| `systemd_sandbox` | sandbox    | high   | Add sandboxing options to systemd services (networkd, resolved, cups, bluetooth) |

Each module comes with its own `pre_check`, `gen_config`, `apply`, `revert`, `status`, and `verify` methods. They're designed to be **pure** where possible – `gen_config` only generates config strings, no side effects.

---

## 🔧 How it works (the boring but important part)

- State is stored in `/var/lib/archlock/state.json` (with schema versioning, so future updates won't break).
- Backups go to `/var/backups/archlock/` with filenames like `sshd_config.firewall.20250323_041530_123456.backup`.
- Each backup includes a SHA256 checksum, verified on restore.
- File writes are atomic: write to temp file in the same directory, `rename()` only on success.
- Permissions and ownership are preserved using the original file (or backup) as reference.
- If you hit `Ctrl+C` during an apply, it rolls back everything that was already written.
---

## ⚠️ Caveats & Warnings

- **High‑risk modules** (`apparmor`, `services`, `usb_lockdown`, `systemd_sandbox`) can break things. Read the warnings, use `--force` only if you know what you're doing.
- **AppArmor** requires kernel support and boot parameters. The module will try to add them for GRUB, but for systemd‑boot you'll need to do it manually.
- **USB lockdown** blacklists `usb-storage`. That means no USB drives until you revert or manually remove the blacklist.
- **Service minimizer** uses a hardcoded list of "suspicious" services. It might not fit your setup – check the list before disabling.
- **Firewall strict profile** blocks almost all outgoing traffic except DNS, HTTP/HTTPS, NTP, and ICMP. Use only if you really need it.
- **State file** is plain JSON. Don't edit it manually unless you enjoy restoring from backups.

---

## 🤝 Contributing

PRs welcome! Keep modules focused, reversible, and safe.  
If you add a new module, make sure it:
- Has a clear risk level
- Implements `pre_check`, `gen_config`, `apply`, `revert`, `status`, and `verify`
- Uses the `BackupKeeper` and `State` classes
- Respects `--quiet` and `--no-color`

Also, update the `PRESETS` if your module should be included in a preset.

---

## 📄 License
MIT – do what you want, but don't blame me if your system catches fire (metaphorically or literally).
---
**Now go secure your Arch box and get some sleep.** 😴
