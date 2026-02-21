#!/usr/bin/env python3
"""
archlock – personal workstation hardening for Arch Linux

This tool applies security settings in a modular, reversible way.
It never overwrites without asking, shows diffs (if verbose), and keeps a persistent
record of every change so you can revert even after a reboot.

I wrote this because I wanted something more structured than random forum
snippets, but less heavy than full-blown SELinux or Ansible.

THREAT MODEL: This is designed for a personal workstation or laptop,
NOT a production server. It aims to reduce attack surface while preserving
usability for daily tasks. It assumes the user has root access and is willing
to review changes. It is NOT intended to withstand nation-state attacks;
it's a sensible baseline. This is NOT a CIS compliance tool and NOT a
replacement for SELinux.

If you are a hardcore Arch user who dislikes colors and emoji,
use --quiet to get minimal output, or --no-color for monochrome.
"""

import os
import sys
import json
import shutil
import argparse
import subprocess
import hashlib
import signal
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import difflib
import re


# signal handler for clean rollback

_interrupted = False

def _signal_handler(sig, frame):
    global _interrupted
    _interrupted = True
    print("\n\n⚠️ interrupted – will rollback if possible", file=sys.stderr)

signal.signal(signal.SIGINT, _signal_handler)


# logging – structured output to journald (if available)

def log_action(module: str, msg: str, level: str = "info", quiet: bool = False, no_color: bool = False):
    """log to journald via logger command, fallback to print if not quiet"""
    try:
        subprocess.run(["logger", "-t", f"archlock[{module}]", f"{level}: {msg}"],
                       check=False)
    except Exception:  # broad but safe; I think we don't want logging to crash anything
        pass
    if not quiet:
        if level == "error":
            prefix = "[{}] ".format(module)
            if no_color:
                print(f"{prefix}{msg}")
            else:
                print(f"\033[91m{prefix}{msg}\033[0m")
        elif level == "warning":
            prefix = "[{}] ".format(module)
            if no_color:
                print(f"{prefix}{msg}")
            else:
                print(f"\033[93m{prefix}{msg}\033[0m")
        else:
            prefix = "[{}] ".format(module)
            if no_color:
                print(f"{prefix}{msg}")
            else:
                print(f"\033[92m{prefix}{msg}\033[0m")


# core types

class ModStatus(Enum):
    UNKNOWN = "unknown"
    APPLIED = "applied"
    PARTIAL = "partial"
    CONFLICT = "conflict"
    ERROR = "error"

class ModKind(Enum):
    FIREWALL = "firewall"
    MAC = "mac"
    SANDBOX = "sandbox"
    KERNEL = "kernel"
    SERVICE = "service"
    FILESYSTEM = "filesystem"
    AUDIT = "audit"

@dataclass
class ModInfo:
    """metadata for a hardening module"""
    name: str
    kind: ModKind
    desc: str
    version: str
    author: str
    deps: List[str]               # required packages
    conflicts: List[str]           # packages that conflict
    reversible: bool
    risk: str                      # low or medium or high


# persistent state – survives reboots, with schema versioning

class State:
    """keeps a json log of all changes made by modules"""
    STATE_DIR = Path("/var/lib/archlock")
    STATE_FILE = STATE_DIR / "state.json"
    SCHEMA_VERSION = 1

    def __init__(self):
        self.STATE_DIR.mkdir(parents=True, exist_ok=True)
        self.data = self._load()

    def _load(self) -> Dict[str, List[Dict]]:
        if self.STATE_FILE.exists():
            try:
                with open(self.STATE_FILE) as f:
                    raw = json.load(f)
                # Check for schema version
                if isinstance(raw, dict) and "_schema_version" in raw:
                    version = raw["_schema_version"]
                    if version != self.SCHEMA_VERSION:
                        print(f"warning: state file has schema v{version}, expected v{self.SCHEMA_VERSION}. Attempting to load anyway.", file=sys.stderr)
                    return raw.get("modules", {})
                else:
                    # old format (pre-schema) – assume it's the modules dict
                    return raw
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self):
        # wrap modules in a versioned envelope
        out = {
            "_schema_version": self.SCHEMA_VERSION,
            "modules": self.data
        }
        with open(self.STATE_FILE, 'w') as f:
            json.dump(out, f, indent=2)

    def add(self, module: str, path: str, backup: str, checksum: str = ""):
        rec = {
            "module": module,
            "path": path,
            "backup": backup,
            "when": datetime.now().isoformat()
        }
        if checksum:
            rec["checksum"] = checksum
        self.data.setdefault(module, []).append(rec)
        self._save()

    def get(self, module: str = None, since: datetime = None, limit: int = None) -> List[Dict]:
        recs = []
        if module:
            recs = self.data.get(module, [])
        else:
            recs = [r for modlist in self.data.values() for r in modlist]
        # sort by timestamp descending so the most recent come first
        recs.sort(key=lambda r: r["when"], reverse=True)
        if since:
            recs = [r for r in recs if datetime.fromisoformat(r["when"]) >= since]
        if limit:
            recs = recs[:limit]
        return recs

    def remove(self, module: str, path: str, backup: str):
        if module in self.data:
            self.data[module] = [
                r for r in self.data[module]
                if not (r["path"] == path and r["backup"] == backup)
            ]
            if not self.data[module]:
                del self.data[module]
            self._save()


# backup manager – uses state to track backups

class BackupKeeper:
    BACKUP_DIR = Path("/var/backups/archlock")

    def __init__(self, state: State):
        self.dir = self.BACKUP_DIR
        self.dir.mkdir(parents=True, exist_ok=True)
        self.state = state

    def _file_hash(self, path: Path) -> str:
        sha = hashlib.sha256()
        with open(path, 'rb') as f:
            for block in iter(lambda: f.read(65536), b''):
                sha.update(block)
        return sha.hexdigest()

    def _copy_with_permissions(self, src: Path, dst: Path):
        """copy file preserving mode and ownership.
        If src is a symlink, we copy the target; but for config files we expect regular files."""
        shutil.copy2(src, dst)  # copy2 tries to preserve metadata
        stat = src.stat()
        os.chown(dst, stat.st_uid, stat.st_gid)
        os.chmod(dst, stat.st_mode)

    def create(self, path: str, module: str) -> Optional[Path]:
        src = Path(path)
        if not src.exists():
            return None
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dest = self.dir / f"{src.name}.{module}.{stamp}.backup"
        self._copy_with_permissions(src, dest)
        h = self._file_hash(dest)
        self.state.add(module, path, str(dest), h)
        return dest

    def restore(self, path: str, backup_path: Path, expected_hash: str = "") -> bool:
        if expected_hash:
            actual = self._file_hash(backup_path)
            if actual != expected_hash:
                log_action("backup", f"hash mismatch for {backup_path}", "error")
                return False
        try:
            dest = Path(path)
            dest.parent.mkdir(parents=True, exist_ok=True)
            self._copy_with_permissions(backup_path, dest)
            return True
        except (OSError, shutil.Error):
            return False

    def list(self, module: str = None) -> List[Path]:
        pat = f"*.{module}.*.backup" if module else "*.backup"
        return sorted(self.dir.glob(pat), reverse=True)


# diff viewer – unified diff with colours (if verbose and not no_color)

def show_diff(old: str, new: str, path: str, verbose: bool, no_color: bool):
    if not verbose:
        return
    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    diff = difflib.unified_diff(old_lines, new_lines,
                                fromfile=f"{path} (current)",
                                tofile=f"{path} (new)")
    print("\n" + "="*60)
    print(f"Changes for: {path}")
    print("="*60)
    for line in diff:
        if line.startswith('+'):
            if no_color:
                print(line, end='')
            else:
                print(f"\033[92m{line}\033[0m", end='')
        elif line.startswith('-'):
            if no_color:
                print(line, end='')
            else:
                print(f"\033[91m{line}\033[0m", end='')
        elif line.startswith('@'):
            if no_color:
                print(line, end='')
            else:
                print(f"\033[94m{line}\033[0m", end='')
        else:
            print(line, end='')
    print("\n" + "="*60)


# atomic file write with rollback

def atomic_write(path: Path, content: str, backup: Optional[Path], no_color: bool) -> bool:
    """write content to path atomically via tempfile, preserving metadata.
    If backup exists, we'll use its mode/ownership as reference, otherwise system defaults."""
    try:
        # Write to temporary file in same directory
        fd, tmp_path = tempfile.mkstemp(dir=path.parent, prefix=path.name + '.tmp')
        with os.fdopen(fd, 'w') as f:
            f.write(content)
        tmp = Path(tmp_path)

        # Set permissions: if original exists, use its mode; else use default (0o644)
        if backup and backup.exists():
            # use backup's mode/ownership
            st = backup.stat()
            os.chown(tmp, st.st_uid, st.st_gid)
            os.chmod(tmp, st.st_mode)
        elif path.exists():
            st = path.stat()
            os.chown(tmp, st.st_uid, st.st_gid)
            os.chmod(tmp, st.st_mode)
        else:
            # new file, set sane defaults: root:root 644
            os.chown(tmp, 0, 0)
            os.chmod(tmp, 0o644)

        # Atomic rename
        tmp.rename(path)
        return True
    except Exception as e:
        log_action("atomic_write", f"failed: {e}", "error", no_color=no_color)
        # Cleanup temp file if it still exists
        if 'tmp' in locals() and tmp.exists():
            tmp.unlink()
        return False


# base class for all hardening modules

class Module:
    info = ModInfo(
        name="base",
        kind=ModKind.KERNEL,
        desc="base module – you should not see this",
        version="0.6.2",   # bumped for final release tweaks
        author="archlock",
        deps=[],
        conflicts=[],
        reversible=True,
        risk="low"
    )

    def __init__(self, state: State, quiet: bool = False, verbose: bool = False, no_color: bool = False):
        self.state = state
        self.backups = BackupKeeper(state)
        self.quiet = quiet
        self.verbose = verbose
        self.no_color = no_color
        self._pre_checked = False   # track if pre_check has been run (for gen_config purity)

    def pre_check(self, force: bool = False) -> Tuple[bool, str]:
        for p in self.info.deps:
            r = subprocess.run(["pacman", "-Q", p], capture_output=True)
            if r.returncode != 0:
                return False, f"package '{p}' is not installed"
        for p in self.info.conflicts:
            r = subprocess.run(["pacman", "-Q", p], capture_output=True)
            if r.returncode == 0:
                if not force:
                    return False, f"conflicting package '{p}' is installed (use --force to override)"
                log_action(self.info.name, f"warning: conflicting package '{p}' is installed", "warning", self.quiet, self.no_color)
        self._pre_checked = True
        return True, "ok"

    def gen_config(self, **kwargs) -> Dict[str, str]:
        """return {file: new_content} – must be pure (no side effects, no subprocess).
        For modules that need pre_check info, ensure pre_check() is called before this."""
        return {}

    def apply(self, dry: bool = False, force: bool = False, verify: bool = False, **kw) -> Tuple[bool, str]:
        global _interrupted
        if _interrupted:
            return False, "interrupted before starting"

        if not dry:
            ok, msg = self.pre_check(force)
            if not ok:
                return False, f"pre‑check failed: {msg}"

        configs = self.gen_config(**kw)
        if not configs:
            return True, "nothing to do"

        # We'll track changes we successfully made so we can rollback if something fails
        applied_changes = []  # list of (path, backup_path, is_new)

        changed = False
        for path, new in configs.items():
            if _interrupted:
                log_action(self.info.name, "interrupted – rolling back", "warning", self.quiet, self.no_color)
                self._rollback_changes(applied_changes)
                return False, "interrupted"

            p = Path(path)
            old = ""
            if p.exists():
                try:
                    with open(p) as f:
                        old = f.read()
                except OSError as e:
                    log_action(self.info.name, f"cannot read {path}: {e}", "warning", self.quiet, self.no_color)
                    continue

            if old == new:
                continue

            changed = True
            show_diff(old, new, path, self.verbose, self.no_color)

            if dry:
                continue

            if not force:
                resp = input(f"apply changes to {path}? [y/N] ")
                if resp.lower() != 'y':
                    continue

            # Backup existing file if it exists
            backup_path = None
            is_new = False
            if p.exists():
                b = self.backups.create(path, self.info.name)
                if b:
                    backup_path = b
                    log_action(self.info.name, f"backup saved to {b}", quiet=self.quiet, no_color=self.no_color)
            else:
                self.state.add(self.info.name, path, "NEW_FILE")
                is_new = True

            # Write new content atomically
            success = atomic_write(p, new, backup_path if backup_path else None, self.no_color)
            if not success:
                log_action(self.info.name, f"failed to write {path}", "error", self.quiet, self.no_color)
                # Rollback already applied changes
                self._rollback_changes(applied_changes)
                return False, f"write failed for {path}"

            log_action(self.info.name, f"applied {path}", quiet=self.quiet, no_color=self.no_color)
            # Record the change for possible rollback
            applied_changes.append((path, backup_path, is_new))

        if not changed:
            return True, "no changes needed (already up‑to‑date)"

        if verify and not dry:
            ok, msg = self.verify()
            if not ok:
                log_action(self.info.name, f"verification warning: {msg}", "warning", self.quiet, self.no_color)
            else:
                log_action(self.info.name, "runtime verification passed", quiet=self.quiet, no_color=self.no_color)

        return True, "module applied"

    def _rollback_changes(self, changes):
        """rollback a list of changes: each item is (path, backup_path, is_new)"""
        for path, backup_path, is_new in changes:
            if not is_new and backup_path and Path(backup_path).exists():
                self.backups.restore(path, Path(backup_path))
                log_action(self.info.name, f"rolled back {path} from {backup_path}", quiet=self.quiet, no_color=self.no_color)
                # also remove the state entry for this backup
                self.state.remove(self.info.name, path, backup_path)
            else:
                # file was new; remove it and its state entry
                try:
                    Path(path).unlink()
                    log_action(self.info.name, f"removed newly created file {path}", quiet=self.quiet, no_color=self.no_color)
                    self.state.remove(self.info.name, path, "NEW_FILE")
                except OSError as e:
                    log_action(self.info.name, f"failed to remove {path} during rollback: {e}", "error", self.quiet, self.no_color)

    def revert(self) -> Tuple[bool, str]:
        if not self.info.reversible:
            return False, "module is not reversible"

        changes = self.state.get(self.info.name)
        if not changes:
            return False, "no recorded changes for this module"

        changes_sorted = sorted(changes, key=lambda x: x["when"], reverse=True)
        reverted = 0
        for rec in changes_sorted:
            path = rec["path"]
            backup = rec["backup"]
            if backup == "NEW_FILE":
                try:
                    Path(path).unlink()
                    log_action(self.info.name, f"removed created file {path}", quiet=self.quiet, no_color=self.no_color)
                    reverted += 1
                    self.state.remove(self.info.name, path, backup)
                except OSError as e:
                    log_action(self.info.name, f"failed to remove {path}: {e}", "error", self.quiet, self.no_color)
            else:
                bp = Path(backup)
                if bp.exists():
                    exp_hash = rec.get("checksum", "")
                    if self.backups.restore(path, bp, exp_hash):
                        log_action(self.info.name, f"restored {path} from {bp.name}", quiet=self.quiet, no_color=self.no_color)
                        reverted += 1
                        self.state.remove(self.info.name, path, backup)
                    else:
                        log_action(self.info.name, f"failed to restore {path} from {bp}", "error", self.quiet, self.no_color)
                else:
                    log_action(self.info.name, f"backup {bp} missing, cannot restore {path}", "error", self.quiet, self.no_color)

        if reverted:
            return True, f"reverted {reverted} change(s)"
        return False, "no changes could be reverted"

    def status(self) -> ModStatus:
        return ModStatus.UNKNOWN

    def verify(self) -> Tuple[bool, str]:
        return True, "ok"


# helper: bootloader detection

def detect_bootloader() -> Tuple[str, Optional[Path]]:
    if Path("/boot/grub/grub.cfg").exists():
        return "grub", Path("/boot/grub/grub.cfg")
    if Path("/boot/loader/entries").is_dir():
        return "systemd-boot", None
    if Path("/efi/EFI").is_dir() and list(Path("/efi/EFI").glob("*.efi")):
        return "efistub", None
    return None, None


# module: firewall (nftables)

class Firewall(Module):
    info = ModInfo(
        name="firewall",
        kind=ModKind.FIREWALL,
        desc="nftables with profiles (workstation/server/paranoid/strict)",
        version="0.3.6",
        author="archlock",
        deps=["nftables"],
        conflicts=["ufw", "iptables"],
        reversible=True,
        risk="medium"
    )

    def pre_check(self, force=False) -> Tuple[bool, str]:
        ok, msg = super().pre_check(force)
        if not ok:
            return ok, msg
        for svc in ["docker", "libvirtd"]:
            r = subprocess.run(["systemctl", "is-active", svc], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip() == "active":
                log_action(self.info.name, f"{svc} is running – nftables flush will remove its rules", "warning", self.quiet, self.no_color)
                if not force:
                    return False, f"{svc} is active, use --force to override"
        return True, "ok"

    def gen_config(self, profile="workstation") -> Dict[str, str]:
        if profile == "strict":
            config = """#!/usr/sbin/nft -f

# archlock generated firewall – profile: strict
# This configuration replaces all existing nftables rules.
# It uses input and output drop policies with explicit allowances.

flush ruleset

table inet firewall {
    chain input {
        type filter hook input priority filter; policy drop;
        iif "lo" accept
        ct state invalid drop
        ct state established,related accept
        udp sport 67 udp dport 68 accept
        udp sport 547 udp dport 546 accept
        counter drop
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy drop;
        oif "lo" accept
        ct state established,related accept
        udp dport 53 accept
        tcp dport 53 accept
        tcp dport { 80, 443 } accept
        udp dport 123 accept
        ip protocol icmp accept
        ip6 nexthdr ipv6-icmp accept
        counter drop
    }
}
"""
            return {"/etc/nftables.conf": config}

        head = """#!/usr/sbin/nft -f

# archlock generated firewall – profile: {profile}
# default‑drop policy, logs dropped packets
# ⚠️ This configuration replaces all existing nftables rules.

flush ruleset

table inet filter {{
    chain input {{
        type filter hook input priority 0; policy drop;

        iif lo accept
        ct state established,related accept

        ip protocol icmp icmp type {{ echo-request, echo-reply, destination-unreachable, time-exceeded }} accept
        ip6 nexthdr icmpv6 icmpv6 type {{ echo-request, echo-reply, destination-unreachable, time-exceeded, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept
"""

        tail = """
        log prefix "nftables INPUT drop: " counter drop
    }}

    chain forward {{
        type filter hook forward priority 0; policy drop;
        log prefix "nftables FORWARD drop: " counter drop
    }}

    chain output {{
        type filter hook output priority 0; policy accept;
    }}
}}
"""

        profiles = {
            "workstation": """
        udp dport 68 accept                     # DHCP client
        # udp dport 5353 accept                 # mDNS (Avahi) – uncomment if needed
        tcp dport 22 ct state new limit rate 10/minute accept   # SSH rate limited
""",
            "server": """
        tcp dport 22 ct state new limit rate 10/minute accept
        # tcp dport {80,443} accept             # uncomment for web
""",
            "paranoid": """
        # tcp dport 22 ct state new limit rate 10/minute accept   # optional SSH
""",
        }
        middle = profiles.get(profile, profiles["workstation"])
        full = head.format(profile=profile) + middle + tail
        return {"/etc/nftables.conf": full}

    def apply(self, dry=False, force=False, verify=False, **kw) -> Tuple[bool, str]:
        profile = kw.get("profile", "workstation")
        if profile == "strict" and not force and not dry:
            return False, "strict profile is high‑risk – use --force to apply"
        ok, msg = super().apply(dry, force, verify, profile=profile)
        if ok and not dry:
            subprocess.run(["systemctl", "enable", "nftables"], check=False)
            subprocess.run(["systemctl", "start", "nftables"], check=False)
            log_action(self.info.name, "nftables service enabled and started", quiet=self.quiet, no_color=self.no_color)
        return ok, msg

    def status(self) -> ModStatus:
        r = subprocess.run(["systemctl", "is-active", "nftables"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip() == "active":
            return ModStatus.APPLIED
        r2 = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
        if r2.returncode == 0 and r2.stdout.strip():
            return ModStatus.PARTIAL
        return ModStatus.UNKNOWN

    def verify(self) -> Tuple[bool, str]:
        r = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
        if r.returncode != 0:
            return False, "nftables not running or failed to list rules"
        if "# archlock generated firewall" not in r.stdout:
            return False, "ruleset does not contain archlock marker"
        return True, "ok"

# module: apparmor

class AppArmor(Module):
    info = ModInfo(
        name="apparmor",
        kind=ModKind.MAC,
        desc="enforce apparmor profiles, add kernel parameters",
        version="0.2.8",
        author="archlock",
        deps=["apparmor"],
        conflicts=["selinux"],
        reversible=True,
        risk="high"
    )

    def pre_check(self, force=False) -> Tuple[bool, str]:
        ok, msg = super().pre_check(force)
        if not ok:
            return ok, msg
        if not Path("/sys/kernel/security/apparmor").exists():
            return False, "kernel does not support apparmor (need CONFIG_SECURITY_APPARMOR)"
        r = subprocess.run(["systemctl", "cat", "apparmor.service"], capture_output=True)
        if r.returncode != 0:
            return False, "apparmor.service not found – is the package installed correctly?"
        return True, "ok"

    def gen_config(self) -> Dict[str, str]:
        configs = {}
        parser = "/etc/apparmor/parser.conf"
        try:
            if Path(parser).exists():
                with open(parser) as f:
                    cur = f.read()
            else:
                cur = ""
        except OSError as e:
            log_action(self.info.name, f"cannot read {parser}: {e}", "warning", self.quiet, self.no_color)
            cur = ""

        needed = [
            "# Enable AppArmor",
            'AA_ENABLED="yes"',
            "# Set profiles to enforce mode",
            'APPARMOR_PROFILE_MODE="enforce"',
            "# Cache compiled profiles",
            'WRITE_CACHE="yes"'
        ]
        new = cur
        for line in needed:
            if line not in new:
                new += line + "\n"
        if new != cur:
            configs[parser] = new

        bl_type, _ = detect_bootloader()
        if bl_type == "grub":
            grub = "/etc/default/grub"
            try:
                if Path(grub).exists():
                    with open(grub) as f:
                        grub_cur = f.read()
                else:
                    grub_cur = ""
            except OSError as e:
                log_action(self.info.name, f"cannot read {grub}: {e}", "warning", self.quiet, self.no_color)
                grub_cur = ""

            if grub_cur and 'GRUB_CMDLINE_LINUX_DEFAULT' in grub_cur:
                def add_apparmor(m):
                    line = m.group(0)
                    if 'apparmor=1' not in line:
                        line = line.rstrip('"') + ' apparmor=1 security=apparmor"'
                    return line
                grub_new = re.sub(r'GRUB_CMDLINE_LINUX_DEFAULT="[^"]*"', add_apparmor, grub_cur)
                if grub_new != grub_cur:
                    configs[grub] = grub_new
            elif grub_cur:
                log_action(self.info.name, "GRUB_CMDLINE_LINUX_DEFAULT not found, cannot add apparmor automatically", "warning", self.quiet, self.no_color)
        elif bl_type == "systemd-boot":
            log_action(self.info.name, "systemd-boot detected – you need to manually add 'apparmor=1 security=apparmor' to kernel command line", "warning", self.quiet, self.no_color)
        else:
            log_action(self.info.name, "unknown bootloader – you must add apparmor kernel parameters manually", "warning", self.quiet, self.no_color)

        return configs

    def apply(self, dry=False, force=False, verify=False) -> Tuple[bool, str]:
        ok, msg = super().apply(dry, force, verify)
        if ok and not dry:
            subprocess.run(["systemctl", "enable", "apparmor"], check=False)
            subprocess.run(["systemctl", "start", "apparmor"], check=False)

            aa_enforce = shutil.which("aa-enforce")
            if aa_enforce:
                profiles_dir = Path("/etc/apparmor.d")
                if profiles_dir.exists():
                    common = ["usr.bin.firefox", "usr.bin.chromium", "usr.bin.ssh",
                              "usr.sbin.cupsd", "usr.bin.evince"]
                    for prof in common:
                        p = profiles_dir / prof
                        if p.exists():
                            subprocess.run([aa_enforce, str(p)], check=False)
            else:
                log_action(self.info.name, "aa-enforce not found – install apparmor-utils to enforce profiles", "warning", self.quiet, self.no_color)

            changes = self.state.get(self.info.name)
            if any(c["path"] == "/etc/default/grub" for c in changes):
                log_action(self.info.name, "grub configuration changed, updating grub.cfg...", quiet=self.quiet, no_color=self.no_color)
                subprocess.run(["grub-mkconfig", "-o", "/boot/grub/grub.cfg"], check=False)
                log_action(self.info.name, "reboot required for apparmor kernel parameters to take effect", "warning", self.quiet, self.no_color)

        return ok, msg

    def status(self) -> ModStatus:
        r = subprocess.run(["aa-status", "--enabled"], capture_output=True)
        if r.returncode == 0:
            return ModStatus.APPLIED
        return ModStatus.UNKNOWN

    def verify(self) -> Tuple[bool, str]:
        r = subprocess.run(["aa-status", "--enabled"], capture_output=True)
        if r.returncode != 0:
            return False, "apparmor not enabled in kernel"
        return True, "ok"

# module: kernel (sysctl)

class Kernel(Module):
    info = ModInfo(
        name="kernel",
        kind=ModKind.KERNEL,
        desc="sysctl hardening (kptr_restrict, dmesg_restrict, etc.)",
        version="0.3.5",
        author="archlock",
        deps=[],
        conflicts=[],
        reversible=True,
        risk="medium"
    )

    def gen_config(self, paranoid=False) -> Dict[str, str]:
        content = """# archlock kernel hardening
# these values are generally safe for workstations

kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1

# kernel.unprivileged_bpf_disabled = 1   # breaks some containers – uncomment if you don't need it

fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

kernel.yama.ptrace_scope = 1

kernel.randomize_va_space = 2

net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
"""
        if paranoid:
            extra = """
# paranoid additions
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_enable = 0
kernel.kexec_load_disabled = 1
kernel.sysrq = 0
kernel.perf_event_paranoid = 3
kernel.perf_cpu_time_max_percent = 1
kernel.perf_event_max_sample_rate = 1
"""
            content += extra
        return {"/etc/sysctl.d/99-archlock.conf": content}

    def apply(self, dry=False, force=False, verify=False, **kw) -> Tuple[bool, str]:
        paranoid = kw.get("paranoid", False)
        ok, msg = super().apply(dry, force, verify, paranoid=paranoid)
        if ok and not dry:
            subprocess.run(["sysctl", "--system"], check=False)
        return ok, msg

    def status(self) -> ModStatus:
        checks = [
            ("kernel.kptr_restrict", "2"),
            ("kernel.dmesg_restrict", "1"),
        ]
        applied = 0
        for param, expected in checks:
            r = subprocess.run(["sysctl", "-n", param], capture_output=True, text=True)
            if r.returncode == 0 and r.stdout.strip() == expected:
                applied += 1
        if applied == len(checks):
            return ModStatus.APPLIED
        elif applied > 0:
            return ModStatus.PARTIAL
        return ModStatus.UNKNOWN

    def verify(self) -> Tuple[bool, str]:
        checks = [
            ("kernel.kptr_restrict", "2"),
            ("kernel.dmesg_restrict", "1"),
        ]
        for param, expected in checks:
            r = subprocess.run(["sysctl", "-n", param], capture_output=True, text=True)
            if r.returncode != 0 or r.stdout.strip() != expected:
                return False, f"{param} = {r.stdout.strip()} (expected {expected})"
        return True, "ok"


# module: service minimizer


class ServiceMin(Module):
    info = ModInfo(
        name="services",
        kind=ModKind.SERVICE,
        desc="list and optionally disable unnecessary services",
        version="0.3.5",
        author="archlock",
        deps=[],
        conflicts=[],
        reversible=True,
        risk="high"
    )

    def __init__(self, state: State, quiet=False, verbose=False, no_color=False):
        super().__init__(state, quiet, verbose, no_color)
        self.suspicious = [
            "avahi-daemon.service",
            "cups.service",
            "bluetooth.service",
            "rpcbind.service",
            "nfs-server.service",
            "smb.service",
            "telnet.socket",
            "vsftpd.service"
        ]

    def analyze(self) -> Dict[str, List[str]]:
        r = subprocess.run(
            ["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend"],
            capture_output=True, text=True
        )
        enabled = [line.split()[0] for line in r.stdout.splitlines() if line]

        r = subprocess.run(
            ["systemctl", "list-units", "--type=service", "--state=running", "--no-legend"],
            capture_output=True, text=True
        )
        running = [line.split()[0] for line in r.stdout.splitlines() if line]

        susp_running = [s for s in running if s in self.suspicious]
        susp_enabled = [s for s in enabled if s in self.suspicious]

        return {
            "running": running,
            "enabled": enabled,
            "susp_running": susp_running,
            "susp_enabled": susp_enabled
        }

    def apply(self, dry=False, force=False, verify=False) -> Tuple[bool, str]:
        data = self.analyze()

        if self.verbose:
            if not self.no_color:
                print("\n📊 service analysis:")
            else:
                print("\nservice analysis:")
            print(f"  total running: {len(data['running'])}")
            print(f"  total enabled: {len(data['enabled'])}")

        suspicious = set(data['susp_running'] + data['susp_enabled'])
        if not suspicious:
            log_action(self.info.name, "no suspicious services found", quiet=self.quiet, no_color=self.no_color)
            return True, "nothing to do"

        if self.verbose:
            if not self.no_color:
                print("\n⚠ potentially unnecessary services:")
            else:
                print("\npotentially unnecessary services:")
            for svc in sorted(suspicious):
                flags = []
                if svc in data['susp_running']:
                    flags.append("running")
                if svc in data['susp_enabled']:
                    flags.append("enabled")
                print(f"  - {svc} ({', '.join(flags)})")

        if dry:
            return True, "analysis complete (dry run)"

        if not force:
            resp = input("disable these services? [y/N] ")
            if resp.lower() != 'y':
                return True, "no changes made"

        for svc in suspicious:
            was_running = svc in data['susp_running']
            log_action(self.info.name, f"disabling {svc}...", quiet=self.quiet, no_color=self.no_color)
            subprocess.run(["systemctl", "stop", svc], check=False)
            subprocess.run(["systemctl", "disable", svc], check=False)
            marker = "DISABLED_RUNNING" if was_running else "DISABLED_ENABLED"
            self.state.add(self.info.name, f"service:{svc}", marker)
            log_action(self.info.name, f"disabled {svc}", quiet=self.quiet, no_color=self.no_color)

        if verify:
            new_data = self.analyze()
            if set(new_data['susp_running'] + new_data['susp_enabled']).intersection(suspicious):
                log_action(self.info.name, "some services still appear active – manual check advised", "warning", self.quiet, self.no_color)
        return True, "services disabled"

    def revert(self) -> Tuple[bool, str]:
        changes = self.state.get(self.info.name)
        if not changes:
            return False, "no recorded changes for this module"

        reverted = 0
        for rec in changes:
            if not rec["path"].startswith("service:"):
                continue
            svc = rec["path"][8:]
            marker = rec["backup"]
            if marker in ("DISABLED_RUNNING", "DISABLED_ENABLED"):
                log_action(self.info.name, f"re-enabling {svc}...", quiet=self.quiet, no_color=self.no_color)
                subprocess.run(["systemctl", "enable", svc], check=False)
                if marker == "DISABLED_RUNNING":
                    subprocess.run(["systemctl", "start", svc], check=False)
                log_action(self.info.name, f"re-enabled {svc}", quiet=self.quiet, no_color=self.no_color)
                reverted += 1
                self.state.remove(self.info.name, rec["path"], rec["backup"])

        if reverted:
            return True, f"re-enabled {reverted} service(s)"
        return False, "no services could be re-enabled"

    def status(self) -> ModStatus:
        data = self.analyze()
        if not data['susp_running'] and not data['susp_enabled']:
            return ModStatus.APPLIED
        return ModStatus.PARTIAL


# module: firejail profiles

class Firejail(Module):
    info = ModInfo(
        name="firejail",
        kind=ModKind.SANDBOX,
        desc="create firejail profiles for browsers",
        version="0.2.7",
        author="archlock",
        deps=["firejail"],
        conflicts=[],
        reversible=True,
        risk="medium"
    )

    def gen_config(self) -> Dict[str, str]:
        content = """# firejail profile for {browser} – generated by archlock
# basic sandboxing: private /tmp, no network except needed, seccomp

netfilter
protocol unix,inet,inet6
private
private-dev
private-tmp
private-opt none
seccomp
caps.drop all
ipc-namespace
x11
"""
        res = {}
        fj_dir = Path("/etc/firejail")
        for br in ["firefox", "chromium", "brave"]:
            path = fj_dir / f"{br}.local"
            if not path.exists():
                res[str(path)] = content.format(browser=br)
        return res

    def apply(self, dry=False, force=False, verify=False) -> Tuple[bool, str]:
        Path("/etc/firejail").mkdir(parents=True, exist_ok=True)
        return super().apply(dry, force, verify)

    def status(self) -> ModStatus:
        if not shutil.which("firejail"):
            return ModStatus.UNKNOWN
        profiles = list(Path("/etc/firejail").glob("*.local"))
        if profiles:
            return ModStatus.APPLIED
        return ModStatus.PARTIAL


# module: auditd


class Audit(Module):
    info = ModInfo(
        name="auditd",
        kind=ModKind.AUDIT,
        desc="enable auditd with basic rules (file access, exec, mounts)",
        version="0.1.8",
        author="archlock",
        deps=["audit"],
        conflicts=[],
        reversible=True,
        risk="medium"
    )

    def gen_config(self) -> Dict[str, str]:
        rules = """# archlock audit rules
-D
-b 8192
-f 1

-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh/sshd_config -p wa -k sshd

-a always,exit -F arch=b64 -S execve -k process_execution
-a always,exit -F arch=b32 -S execve -k process_execution

-a always,exit -F arch=b64 -S mount -k mounting
-a always,exit -F arch=b32 -S mount -k mounting

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
"""
        return {"/etc/audit/rules.d/archlock.rules": rules}

    def apply(self, dry=False, force=False, verify=False) -> Tuple[bool, str]:
        ok, msg = super().apply(dry, force, verify)
        if ok and not dry:
            subprocess.run(["systemctl", "enable", "auditd"], check=False)
            subprocess.run(["systemctl", "start", "auditd"], check=False)
            subprocess.run(["augenrules", "--load"], check=False)
            log_action(self.info.name, "auditd enabled and rules loaded", quiet=self.quiet, no_color=self.no_color)
        return ok, msg

    def status(self) -> ModStatus:
        r = subprocess.run(["systemctl", "is-active", "auditd"], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip() == "active":
            return ModStatus.APPLIED
        return ModStatus.UNKNOWN

    def verify(self) -> Tuple[bool, str]:
        r = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
        if r.returncode != 0:
            return False, "auditctl failed"
        if "-k identity" not in r.stdout:
            return False, "identity rules not loaded"
        return True, "ok"


#usb lockdown (module)


class UsbLockdown(Module):
    info = ModInfo(
        name="usb_lockdown",
        kind=ModKind.FILESYSTEM,
        desc="blacklist usb-storage module",
        version="0.1.8",
        author="archlock",
        deps=[],
        conflicts=[],
        reversible=True,
        risk="high"
    )

    def pre_check(self, force=False) -> Tuple[bool, str]:
        ok, msg = super().pre_check(force)
        if not ok:
            return ok, msg
        if not force:
            return False, "USB lockdown is high‑risk; use --force to apply"
        return True, "ok"

    def gen_config(self) -> Dict[str, str]:
        return {"/etc/modprobe.d/archlock-usb-blacklist.conf": "blacklist usb-storage\n"}

    def apply(self, dry=False, force=False, verify=False) -> Tuple[bool, str]:
        ok, msg = super().apply(dry, force, verify)
        if ok and not dry:
            subprocess.run(["modprobe", "-r", "usb-storage"], check=False)
            log_action(self.info.name, "USB storage blacklisted (module unloaded)", quiet=self.quiet, no_color=self.no_color)
        return ok, msg

    def status(self) -> ModStatus:
        if Path("/etc/modprobe.d/archlock-usb-blacklist.conf").exists():
            return ModStatus.APPLIED
        return ModStatus.UNKNOWN

#systemd sandboxing (module)

class SystemdSandbox(Module):
    info = ModInfo(
        name="systemd_sandbox",
        kind=ModKind.SANDBOX,
        desc="add sandboxing options to systemd services",
        version="0.1.8",
        author="archlock",
        deps=[],
        conflicts=[],
        reversible=True,
        risk="high"
    )

    def __init__(self, state: State, quiet=False, verbose=False, no_color=False):
        super().__init__(state, quiet, verbose, no_color)
        self.targets = ["systemd-networkd.service", "systemd-resolved.service", "cups.service", "bluetooth.service"]
        self.available_targets = []  # filled in pre_check

    def pre_check(self, force=False) -> Tuple[bool, str]:
        ok, msg = super().pre_check(force)
        if not ok:
            return ok, msg
        self.available_targets = []
        for svc in self.targets:
            r = subprocess.run(["systemctl", "cat", svc], capture_output=True)
            if r.returncode == 0:
                self.available_targets.append(svc)
            else:
                log_action(self.info.name, f"service {svc} not found, skipping", "warning", self.quiet, self.no_color)
        if not self.available_targets:
            return False, "no target services found"
        return True, "ok"

    def gen_config(self) -> Dict[str, str]:
        """Generates override files for available services.
        Must be called after pre_check() to populate self.available_targets."""
        # If pre_check hasn't been run (e.g., dry run), we can't know available targets, so return empty.
        if not self._pre_checked:
            # This can happen in dry run mode – we assume we would generate configs for any existing services,
            # but since we don't know, we return empty to avoid errors. The diff will show nothing, which is okay.
            return {}
        overrides = {}
        for svc in self.available_targets:
            d = Path(f"/etc/systemd/system/{svc}.d")
            f = d / "archlock-sandbox.conf"
            if not f.exists():
                content = """[Service]
# added by archlock
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
NoNewPrivileges=yes
RestrictSUIDSGID=yes
"""
                overrides[str(f)] = content
        return overrides

    def apply(self, dry=False, force=False, verify=False) -> Tuple[bool, str]:
        ok, msg = super().apply(dry, force, verify)
        if ok and not dry:
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            if force:
                changes = self.state.get(self.info.name)
                for rec in changes:
                    if rec["backup"] == "NEW_FILE" and rec["path"].endswith(".conf"):
                        p = Path(rec["path"])
                        svc = p.parent.parent.name
                        subprocess.run(["systemctl", "restart", svc], check=False)
                log_action(self.info.name, "sandboxing applied and affected services restarted", quiet=self.quiet, no_color=self.no_color)
            else:
                log_action(self.info.name, "overrides created – run 'systemctl daemon-reload' and restart services manually (or use --force)", "warning", self.quiet, self.no_color)
        return ok, msg

    def status(self) -> ModStatus:
        # Determine which target services exist on the system
        existing_targets = []
        for svc in self.targets:
            r = subprocess.run(["systemctl", "cat", svc], capture_output=True)
            if r.returncode == 0:
                existing_targets.append(svc)
        if not existing_targets:
            return ModStatus.UNKNOWN  # no services to harden
        found = 0
        for svc in existing_targets:
            if Path(f"/etc/systemd/system/{svc}.d/archlock-sandbox.conf").exists():
                found += 1
        if found == len(existing_targets):
            return ModStatus.APPLIED
        elif found > 0:
            return ModStatus.PARTIAL
        return ModStatus.UNKNOWN

#audit command (read only)

def run_audit(quiet=False, no_color=False):
    if quiet:
        return

    if not no_color:
        print("\n🔍 archlock audit – read‑only system scan")
    else:
        print("\narchlock audit – read‑only system scan")
    print("="*60)

    if not no_color:
        print("\n📡 listening ports (IPv4):")
    else:
        print("\nlistening ports (IPv4):")
    r = subprocess.run(["ss", "-tulpn4"], capture_output=True, text=True)
    for line in r.stdout.splitlines():
        if "LISTEN" in line:
            print(f"  {line}")

    if not no_color:
        print("\n🔑 setuid binaries (common):")
    else:
        print("\nsetuid binaries (common):")
    suid_dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    all_suid = []
    for d in suid_dirs:
        if Path(d).exists():
            out = subprocess.run(["find", d, "-perm", "-4000", "-ls"], capture_output=True, text=True)
            all_suid.extend(out.stdout.splitlines())
    for line in all_suid[:10]:
        print(f"  {line}")
    if len(all_suid) > 10:
        print("  ... (more)")

    if not no_color:
        print("\n⚙️ enabled services (suspicious ones highlighted):")
    else:
        print("\nenabled services:")
    r = subprocess.run(["systemctl", "list-unit-files", "--type=service", "--state=enabled", "--no-legend"],
                       capture_output=True, text=True)
    suspicious = ["avahi", "cups", "bluetooth", "rpcbind", "nfs", "smb", "telnet", "vsftpd"]
    for line in r.stdout.splitlines():
        svc = line.split()[0]
        if not no_color and any(s in svc for s in suspicious):
            print(f"  \033[93m{svc}\033[0m")
        else:
            print(f"  {svc}")

    if not no_color:
        print("\n🧠 sysctl values (compared to kernel module recommendations):")
    else:
        print("\nsysctl values:")
    rec = {
        "kernel.kptr_restrict": "2",
        "kernel.dmesg_restrict": "1",
        "fs.protected_hardlinks": "1",
        "fs.protected_symlinks": "1",
    }
    for k, v in rec.items():
        cur = subprocess.run(["sysctl", "-n", k], capture_output=True, text=True).stdout.strip()
        if cur == v:
            if not no_color:
                print(f"  ✓ {k} = {cur}")
            else:
                print(f"  OK: {k} = {cur}")
        else:
            if not no_color:
                print(f"  \033[91m✗ {k} = {cur} (should be {v})\033[0m")
            else:
                print(f"  FAIL: {k} = {cur} (should be {v})")

    if not no_color:
        print("\n📦 AUR packages (if any):")
    else:
        print("\nAUR packages:")
    r = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True)
    if r.stdout:
        for line in r.stdout.splitlines()[:10]:
            print(f"  {line}")
        if len(r.stdout.splitlines()) > 10:
            print("  ...")
    else:
        print("  none")

    print("\n" + "="*60)

#the doctor, basic diagnostic

def run_doctor(quiet=False, no_color=False):
    if quiet:
        return

    if not no_color:
        print("\n🩺 archlock doctor – system diagnostics")
    else:
        print("\narchlock doctor – system diagnostics")
    print("="*60)

    # check nftables
    if not no_color:
        print("\n firewall:")
    else:
        print("\nfirewall:")
    
    # check if nftables package is installed
    nft_installed = subprocess.run(["pacman", "-Q", "nftables"], capture_output=True)
    if nft_installed.returncode != 0:
        if not no_color:
            print("  ✗ nftables package not installed")
        else:
            print("  FAIL: nftables package not installed")
    else:
        # check service status
        nft_active = subprocess.run(["systemctl", "is-active", "nftables"], capture_output=True, text=True)
        nft_enabled = subprocess.run(["systemctl", "is-enabled", "nftables"], capture_output=True, text=True)
        
        # check if any rules are loaded
        nft_rules = subprocess.run(["nft", "list", "ruleset"], capture_output=True, text=True)
        rules_loaded = (nft_rules.returncode == 0 and nft_rules.stdout.strip() != "")
        
        # service status
        if nft_active.returncode == 0 and nft_active.stdout.strip() == "active":
            if not no_color:
                print("  ✓ nftables service is active and running")
            else:
                print("  OK: nftables service is active and running")
        else:
            if rules_loaded:
                if not no_color:
                    print("  ⚠ nftables service is not active BUT rules are loaded")
                    print("    (firewall is working, service may be masked or managed manually)")
                else:
                    print("  WARN: nftables service not active but rules are loaded")
            else:
                if not no_color:
                    print("  ✗ nftables service is not active and no rules loaded")
                else:
                    print("  FAIL: nftables service not active and no rules loaded")
        
        # check if enabled on boot
        if nft_enabled.returncode == 0 and nft_enabled.stdout.strip() == "enabled":
            if not no_color:
                print("  ✓ nftables enabled on boot")
            else:
                print("  OK: nftables enabled on boot")
        else:
            if not no_color:
                print("  ⚠ nftables not enabled on boot (will need manual start after reboot)")
            else:
                print("  WARN: nftables not enabled on boot")
        
        # show rule count if verbose
        if rules_loaded and not quiet:
            rule_count = len([line for line in nft_rules.stdout.splitlines() 
                            if 'chain' in line or 'rule' in line])
            if not no_color:
                print(f"  📊 {rule_count} rules currently loaded")
            else:
                print(f"  STATS: {rule_count} rules loaded")

    # check apparmor
    if not no_color:
        print("\n🛡️ apparmor:")
    else:
        print("\napparmor:")
    
    # check if apparmor package is installed
    aa_installed = subprocess.run(["pacman", "-Q", "apparmor"], capture_output=True)
    if aa_installed.returncode != 0:
        if not no_color:
            print("  ✗ apparmor package not installed")
        else:
            print("  FAIL: apparmor package not installed")
    else:
        aa_enabled = subprocess.run(["aa-status", "--enabled"], capture_output=True)
        if aa_enabled.returncode == 0:
            if not no_color:
                print("  ✓ apparmor enabled in kernel")
            else:
                print("  OK: apparmor enabled in kernel")
            
            # check service status
            aa_active = subprocess.run(["systemctl", "is-active", "apparmor"], capture_output=True, text=True)
            if aa_active.returncode == 0 and aa_active.stdout.strip() == "active":
                if not no_color:
                    print("  ✓ apparmor service active")
                else:
                    print("  OK: apparmor service active")
            else:
                if not no_color:
                    print("  ⚠ apparmor service not active")
                else:
                    print("  WARN: apparmor service not active")
            
            # Get profile counts if aa-status available...
            aa_status = subprocess.run(["aa-status"], capture_output=True, text=True)
            if aa_status.returncode == 0:
                import re
                enforced = re.search(r'(\d+) profiles are in enforce mode', aa_status.stdout)
                complain = re.search(r'(\d+) profiles are in complain mode', aa_status.stdout)
                if enforced:
                    if not no_color:
                        print(f"  📊 {enforced.group(1)} profiles in enforce mode")
                    else:
                        print(f"  STATS: {enforced.group(1)} profiles enforced")
                if complain and int(complain.group(1)) > 0:
                    if not no_color:
                        print(f"  ⚠ {complain.group(1)} profiles in complain mode")
                    else:
                        print(f"  WARN: {complain.group(1)} profiles in complain mode")
        else:
            if not no_color:
                print("  ✗ apparmor not enabled in kernel (need apparmor=1 security=apparmor)")
            else:
                print("  FAIL: apparmor not enabled in kernel")

    # check kernel sysctl
    if not no_color:
        print("\n🧠 kernel:")
    else:
        print("\nkernel:")
    
    checks = [
        ("kernel.kptr_restrict", "2", "restricts kernel pointer exposure"),
        ("kernel.dmesg_restrict", "1", "restricts dmesg access"),
        ("fs.protected_hardlinks", "1", "prevents hardlink attacks"),
        ("fs.protected_symlinks", "1", "prevents symlink attacks"),
        ("kernel.yama.ptrace_scope", "1", "restricts ptrace"),
        ("kernel.randomize_va_space", "2", "full ASLR"),
    ]
    
    all_ok = True
    for param, expected, desc in checks:
        r = subprocess.run(["sysctl", "-n", param], capture_output=True, text=True)
        if r.returncode == 0 and r.stdout.strip() == expected:
            if not no_color:
                print(f"  ✓ {param} = {r.stdout.strip()} ({desc})")
            else:
                print(f"  OK: {param} = {r.stdout.strip()}")
        else:
            all_ok = False
            current = r.stdout.strip() if r.returncode == 0 else "N/A"
            if not no_color:
                print(f"  ✗ {param} = {current} (should be {expected}) - {desc}")
            else:
                print(f"  FAIL: {param} = {current} (should be {expected})")
    
    if all_ok and not no_color:
        print("  ✓ all kernel parameters optimally configured")
    elif all_ok:
        print("  OK: all kernel parameters optimal")

    # check auditd
    if not no_color:
        print("\n📋 auditd:")
    else:
        print("\nauditd:")
    
    # check if the audit package is installed
    audit_installed = subprocess.run(["pacman", "-Q", "audit"], capture_output=True)
    if audit_installed.returncode != 0:
        if not no_color:
            print("  ✗ audit package not installed")
        else:
            print("  FAIL: audit package not installed")
    else:
        audit_active = subprocess.run(["systemctl", "is-active", "auditd"], capture_output=True, text=True)
        if audit_active.returncode == 0 and audit_active.stdout.strip() == "active":
            if not no_color:
                print("  ✓ auditd service active")
            else:
                print("  OK: auditd service active")
            
            # check rules
            audit_rules = subprocess.run(["auditctl", "-l"], capture_output=True, text=True)
            if audit_rules.returncode == 0:
                if "-k identity" in audit_rules.stdout:
                    if not no_color:
                        print("  ✓ audit rules loaded (identity monitoring active)")
                    else:
                        print("  OK: audit rules loaded")
                else:
                    if not no_color:
                        print("  ⚠ audit running but no identity rules loaded")
                    else:
                        print("  WARN: audit running but no rules")
                
                # count the rules
                rule_count = len([line for line in audit_rules.stdout.splitlines() if line.strip()])
                if not no_color and rule_count > 0:
                    print(f"  📊 {rule_count} audit rules active")
            else:
                if not no_color:
                    print("  ⚠ auditctl failed to list rules")
                else:
                    print("  WARN: cannot list audit rules")
        else:
            if not no_color:
                print("  ✗ auditd service not active")
            else:
                print("  FAIL: auditd service not active")

    # check for common issues
    if not no_color:
        print("\n⚠️ common issues:")
    else:
        print("\ncommon issues:")
    
    issues_found = False
    
    # check if reboot required (kernel updates)
    if Path("/usr/lib/modules").exists():
        latest_kernel = sorted(Path("/usr/lib/modules").glob("*-ARCH"), reverse=True)
        if latest_kernel:
            running = subprocess.run(["uname", "-r"], capture_output=True, text=True).stdout.strip()
            if running not in str(latest_kernel[0]):
                if not no_color:
                    print("  ⚠ system running older kernel - reboot recommended")
                else:
                    print("  WARN: reboot needed - kernel updated")
                issues_found = True
    
    # check for pending package updates (optional)
    if not quiet:
        updates = subprocess.run(["pacman", "-Qu"], capture_output=True, text=True)
        if updates.stdout.strip():
            update_count = len(updates.stdout.splitlines())
            if not no_color:
                print(f"  ℹ {update_count} package updates available")
            else:
                print(f"  INFO: {update_count} updates available")
    
    if not issues_found:
        if not no_color:
            print("  ✓ no obvious issues detected")
        else:
            print("  OK: no issues detected")

    print("\n" + "="*60)

#to apply multiple modules

PRESETS = {
    "desktop": ["firewall", "kernel", "services", "firejail"],
    "server": ["firewall", "kernel", "services", "auditd"],
    "hardened": ["firewall", "apparmor", "kernel", "services", "firejail", "auditd", "usb_lockdown", "systemd_sandbox"]
}

#the main cli

class ArchLock:
    def __init__(self, quiet=False, verbose=False, no_color=False):
        self.quiet = quiet
        self.verbose = verbose
        self.no_color = no_color
        self.state = State()
        self.modules = {
            "firewall": Firewall(self.state, quiet, verbose, no_color),
            "apparmor": AppArmor(self.state, quiet, verbose, no_color),
            "kernel": Kernel(self.state, quiet, verbose, no_color),
            "services": ServiceMin(self.state, quiet, verbose, no_color),
            "firejail": Firejail(self.state, quiet, verbose, no_color),
            "auditd": Audit(self.state, quiet, verbose, no_color),
            "usb_lockdown": UsbLockdown(self.state, quiet, verbose, no_color),
            "systemd_sandbox": SystemdSandbox(self.state, quiet, verbose, no_color),
        }
        for preset, mods in PRESETS.items():
            for m in mods:
                if m not in self.modules:
                    raise RuntimeError(f"preset '{preset}' references unknown module '{m}'")

    def list(self):
        if not self.quiet:
            if not self.no_color:
                print("\n📦 available modules:")
            else:
                print("\navailable modules:")
            print("="*60)
        for name, mod in self.modules.items():
            info = mod.info
            stat = mod.status()
            sym = {
                ModStatus.APPLIED: "✓",
                ModStatus.PARTIAL: "◔",
                ModStatus.UNKNOWN: "○",
                ModStatus.CONFLICT: "✗",
                ModStatus.ERROR: "⚠"
            }.get(stat, "○")
            if not self.quiet:
                if not self.no_color:
                    print(f"\n{sym} \033[1m{name}\033[0m")
                else:
                    print(f"\n{sym} {name}")
                print(f"  📝 {info.desc}")
                print(f"  🔧 type: {info.kind.value}")
                print(f"  ⚡ risk: {info.risk}")
                print(f"  🔄 reversible: {'✓' if info.reversible else '✗'}")
                if info.deps:
                    print(f"  📦 deps: {', '.join(info.deps)}")
            else:
                print(f"{name}: {stat.value}")

    def apply_one(self, name: str, dry=False, force=False, verify=False, **kw):
        if name not in self.modules:
            print(f"unknown module '{name}'")
            return
        mod = self.modules[name]
        if not self.quiet:
            if not self.no_color:
                print(f"\n🔧 applying \033[1m{name}\033[0m – {mod.info.desc}")
            else:
                print(f"\napplying {name} – {mod.info.desc}")
            print("-"*50)
        if dry and not self.quiet:
            if not self.no_color:
                print("🔍 dry run – no changes will be written")
            else:
                print("dry run – no changes will be written")
        ok, msg = mod.apply(dry, force, verify, **kw)
        if ok:
            if not self.quiet:
                if not self.no_color:
                    print(f"\n\033[92m✓ {msg}\033[0m")
                else:
                    print(f"\nOK: {msg}")
            else:
                print(f"{name}: applied ({msg})")
        else:
            if not self.quiet:
                if not self.no_color:
                    print(f"\n\033[91m✗ {msg}\033[0m")
                else:
                    print(f"\nFAIL: {msg}")
            else:
                print(f"{name}: failed – {msg}")

    def apply_preset(self, preset: str, dry=False, force=False, verify=False):
        if preset not in PRESETS:
            print(f"unknown preset '{preset}'")
            return
        if not self.quiet:
            if not self.no_color:
                print(f"\n🎯 applying preset: \033[1m{preset}\033[0m")
            else:
                print(f"\napplying preset: {preset}")
        for mod in PRESETS[preset]:
            self.apply_one(mod, dry, force, verify)
            if not self.quiet:
                print()

    def revert(self, name: str):
        if name not in self.modules:
            print(f"unknown module '{name}'")
            return
        mod = self.modules[name]
        if not self.quiet:
            if not self.no_color:
                print(f"\n↻ reverting \033[1m{name}\033[0m")
            else:
                print(f"\nreverting {name}")
            print("-"*50)
        if not mod.info.reversible:
            print("module is not reversible")
            return
        ok, msg = mod.revert()
        if ok:
            if not self.quiet:
                if not self.no_color:
                    print(f"\n\033[92m✓ {msg}\033[0m")
                else:
                    print(f"\nOK: {msg}")
            else:
                print(f"{name}: reverted")
        else:
            if not self.quiet:
                if not self.no_color:
                    print(f"\n\033[91m✗ {msg}\033[0m")
                else:
                    print(f"\nFAIL: {msg}")
            else:
                print(f"{name}: revert failed – {msg}")

    def status(self):
        if not self.quiet:
            if not self.no_color:
                print("\n📊 system hardening status:")
            else:
                print("\nsystem hardening status:")
            print("="*60)
        for name, mod in self.modules.items():
            stat = mod.status()
            if not self.quiet:
                if not self.no_color:
                    disp = {
                        ModStatus.APPLIED: "\033[92mAPPLIED\033[0m",
                        ModStatus.PARTIAL: "\033[93mPARTIAL\033[0m",
                        ModStatus.UNKNOWN: "\033[90mNOT APPLIED\033[0m",
                        ModStatus.CONFLICT: "\033[91mCONFLICT\033[0m",
                        ModStatus.ERROR: "\033[91mERROR\033[0m"
                    }.get(stat, "\033[90mUNKNOWN\033[0m")
                else:
                    disp = stat.value.upper()
                print(f"{name:20} : {disp}")
            else:
                print(f"{name}: {stat.value}")

    def backups(self, module=None, days=None, limit=None):
        since = None
        if days is not None:
            since = datetime.now() - timedelta(days=days)
        recs = self.state.get(module, since=since, limit=limit)
        if not recs:
            print("no backups found")
            return
        if not self.quiet:
            if not self.no_color:
                print("\n📂 backup history:")
            else:
                print("\nbackup history:")
            print("="*60)
        for r in recs:
            if not self.quiet:
                print(f"  • {r['when']} – {r['module']}: {r['path']} -> {r['backup']}")
            else:
                print(f"{r['when']} {r['module']} {r['path']} {r['backup']}")

#the entry point

def main():
    parser = argparse.ArgumentParser(
        description="archlock – modular hardening for Arch Linux",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  archlock list
  archlock status
  archlock doctor
  archlock apply firewall --profile workstation
  archlock apply kernel --dry-run
  archlock apply --preset desktop
  archlock revert firewall
  archlock backups --days 7 --limit 20
  archlock audit
        """
    )
    parser.add_argument("--quiet", action="store_true", help="minimal output (no emoji, less verbose)")
    parser.add_argument("--verbose", action="store_true", help="show diffs and detailed output")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI color codes")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="show available modules")
    sub.add_parser("status", help="show applied status")
    sub.add_parser("doctor", help="run system diagnostics (read-only)")

    bp = sub.add_parser("backups", help="list change history")
    bp.add_argument("--module", help="filter by module name")
    bp.add_argument("--days", type=int, help="show only last N days")
    bp.add_argument("--limit", type=int, help="max number of records to show")

    sub.add_parser("audit", help="read‑only system security scan")

    ap = sub.add_parser("apply", help="apply a module or preset")
    ap.add_argument("name", nargs="?", help="module name (omit if using --preset)")
    ap.add_argument("--preset", choices=PRESETS.keys(), help="apply a preset instead of a single module")
    ap.add_argument("--dry-run", action="store_true", help="preview changes")
    ap.add_argument("--force", "-f", action="store_true", help="skip confirmations AND override conflict checks")
    ap.add_argument("--verify", action="store_true", help="run runtime verification after applying")
    ap.add_argument("--profile", choices=["workstation", "server", "paranoid", "strict"],
                    help="firewall profile (only used with firewall module)")
    ap.add_argument("--paranoid", action="store_true", help="enable extra paranoid sysctl options (kernel module)")

    rv = sub.add_parser("revert", help="undo a module's changes")
    rv.add_argument("module", help="module name")

    args = parser.parse_args()

    # automatically disable colors if stdout is not a tty (e.g., redirected to file)
    if not sys.stdout.isatty() and not args.no_color:
        args.no_color = True

    if args.cmd in ["apply", "revert"] and os.geteuid() != 0:
        print("this command needs root – try again with sudo", file=sys.stderr)
        sys.exit(1)

    app = ArchLock(quiet=args.quiet, verbose=args.verbose, no_color=args.no_color)

    if args.cmd == "list":
        app.list()
    elif args.cmd == "status":
        app.status()
    elif args.cmd == "doctor":
        run_doctor(args.quiet, args.no_color)
    elif args.cmd == "backups":
        app.backups(args.module, args.days, args.limit)
    elif args.cmd == "audit":
        run_audit(args.quiet, args.no_color)
    elif args.cmd == "apply":
        if args.preset:
            app.apply_preset(args.preset, args.dry_run, args.force, args.verify)
        elif args.name:
            kw = {}
            if args.name == "firewall" and args.profile:
                kw["profile"] = args.profile
            if args.name == "kernel" and args.paranoid:
                kw["paranoid"] = True
            app.apply_one(args.name, args.dry_run, args.force, args.verify, **kw)
        else:
            parser.print_help()
    elif args.cmd == "revert":
        app.revert(args.module)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
