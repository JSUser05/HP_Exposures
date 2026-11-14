#!/usr/bin/env python3
"""
env_library.py - Honeypot Environment Profile Library & Switcher for HP_Exposures.

Provides a Python API and CLI to define, inspect, customize, and activate
pre-packaged Cowrie honeypot environments (cowrie.cfg, userdb.txt, filesystem
pickle, and honeyfs file overrides) when deploying across VMs.

Usage (CLI):
    python3 env_library.py list
    python3 env_library.py show env1
    python3 env_library.py apply env1
    python3 env_library.py apply env2 --port 2222 --hostname custom-lab
    python3 env_library.py status

Usage (Python import):
    from env_library import apply_environment, list_environments, get_environment
    apply_environment("env1")
"""

from __future__ import annotations

import argparse
import configparser
import copy
import json
import pickle
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent
COWRIE_DIR = REPO_ROOT / "cowrie"
COWRIE_ETC_DIR = COWRIE_DIR / "etc"
ACTIVE_CFG_PATH = COWRIE_ETC_DIR / "cowrie.cfg"
ACTIVE_USERDB_PATH = COWRIE_ETC_DIR / "userdb.txt"
ACTIVE_MARKER_PATH = COWRIE_ETC_DIR / ".active_env.json"
ENVS_DIR = REPO_ROOT / "environments"
BASE_PICKLE_PATH = COWRIE_DIR / "src" / "cowrie" / "data" / "fs.pickle"


@dataclass
class EnvironmentProfile:
    """Represents a self-contained honeypot environment profile."""

    name: str
    description: str
    hostname: str
    pickle_file: Path
    cfg_file: Path
    userdb_file: Path
    honeyfs_dir: Path
    ssh_version: str = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    kernel_version: str = "5.15.0-91-generic"
    default_users: list[str] = field(default_factory=list)


# ============================================================================
# Environment Registry (Library Catalog)
# ============================================================================
ENVIRONMENTS: dict[str, EnvironmentProfile] = {
    "env1": EnvironmentProfile(
        name="env1",
        description="Staging Web API Server (Ubuntu 22.04, dev-user, PHP/SQL/env files in custom_fs1.pickle)",
        hostname="staging-api",
        pickle_file=REPO_ROOT / "custom_fs1.pickle",
        cfg_file=ENVS_DIR / "env1" / "cowrie.cfg",
        userdb_file=ENVS_DIR / "env1" / "userdb.txt",
        honeyfs_dir=ENVS_DIR / "env1" / "honeyfs",
        ssh_version="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
        kernel_version="5.15.0-91-generic",
        default_users=[
            "dev-user:devpass123",
            "dev-user:welcome123",
            "dev-user:staging2024",
            "root:StagingRoot!2024",
            "admin:admin123",
        ],
    ),
    "env2": EnvironmentProfile(
        name="env2",
        description="Student Lab / Dev Desktop (Debian 12, student/labuser, coursework & scripts in custom_fs2.pickle)",
        hostname="student-lab",
        pickle_file=REPO_ROOT / "custom_fs2.pickle",
        cfg_file=ENVS_DIR / "env2" / "cowrie.cfg",
        userdb_file=ENVS_DIR / "env2" / "userdb.txt",
        honeyfs_dir=ENVS_DIR / "env2" / "honeyfs",
        ssh_version="SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        kernel_version="6.1.0-21-amd64",
        default_users=[
            "student:student",
            "student:cs2743",
            "student:password123",
            "labuser:labuser",
            "root:labadmin2024",
        ],
    ),
    "env3": EnvironmentProfile(
        name="env3",
        description="Cloud Deployment Node (Ubuntu 22.04 AWS kernel, ubuntu user, AWS & Docker files in custom_fs3.pickle)",
        hostname="ip-172-31-18-42",
        pickle_file=REPO_ROOT / "custom_fs3.pickle",
        cfg_file=ENVS_DIR / "env3" / "cowrie.cfg",
        userdb_file=ENVS_DIR / "env3" / "userdb.txt",
        honeyfs_dir=ENVS_DIR / "env3" / "honeyfs",
        ssh_version="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        kernel_version="6.5.0-1016-aws",
        default_users=[
            "ubuntu:ubuntu",
            "ubuntu:deploy2024",
            "ubuntu:aws12345",
            "deploy:deploy",
            "root:CloudAdmin#99",
        ],
    ),
    "env4": EnvironmentProfile(
        name="env4",
        description="Personal Linux Home / Media Server (Ubuntu 22.04, alex/media users, homelab & personal files in custom_fs4.pickle)",
        hostname="home-server",
        pickle_file=REPO_ROOT / "custom_fs4.pickle",
        cfg_file=ENVS_DIR / "env4" / "cowrie.cfg",
        userdb_file=ENVS_DIR / "env4" / "userdb.txt",
        honeyfs_dir=ENVS_DIR / "env4" / "honeyfs",
        ssh_version="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        kernel_version="6.5.0-26-generic",
        default_users=[
            "alex:alex123",
            "alex:plex2024",
            "alex:password123",
            "media:media",
            "media:plex",
            "root:homelab2024",
        ],
    ),
}


def list_environments() -> dict[str, EnvironmentProfile]:
    """Return all registered environment profiles."""
    return dict(ENVIRONMENTS)


def get_environment(name: str) -> EnvironmentProfile:
    """Look up an environment profile by name."""
    if name not in ENVIRONMENTS:
        available = ", ".join(sorted(ENVIRONMENTS.keys()))
        raise KeyError(f"Unknown environment '{name}'. Available: {available}")
    return ENVIRONMENTS[name]


def apply_environment(
    name: str,
    *,
    hostname: str | None = None,
    ssh_port: int | None = None,
    extra_users: list[str] | None = None,
    config_overrides: dict[str, dict[str, str]] | None = None,
) -> dict[str, Any]:
    """
    Activate the given environment profile by writing:
      - cowrie/etc/cowrie.cfg
      - cowrie/etc/userdb.txt
      - cowrie/var/lib/cowrie/<pickle_name>

    Paths written to cowrie.cfg are resolved as absolute paths so Cowrie can be
    started from any working directory on the VM.
    """
    profile = get_environment(name)

    if not profile.cfg_file.is_file():
        raise FileNotFoundError(f"Missing profile config: {profile.cfg_file}")
    if not profile.userdb_file.is_file():
        raise FileNotFoundError(f"Missing profile userdb: {profile.userdb_file}")
    if not profile.pickle_file.is_file():
        raise FileNotFoundError(f"Missing filesystem pickle: {profile.pickle_file}")

    COWRIE_ETC_DIR.mkdir(parents=True, exist_ok=True)
    var_lib_dir = COWRIE_DIR / "var" / "lib" / "cowrie"
    var_lib_dir.mkdir(parents=True, exist_ok=True)

    # Copy pickle into cowrie/var/lib/cowrie/ as well so both locations stay in sync
    target_pickle = var_lib_dir / profile.pickle_file.name
    shutil.copy2(profile.pickle_file, target_pickle)

    # Load and customize cowrie.cfg
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(profile.cfg_file, encoding="utf-8")

    if not parser.has_section("honeypot"):
        parser.add_section("honeypot")
    if not parser.has_section("shell"):
        parser.add_section("shell")
    if not parser.has_section("ssh"):
        parser.add_section("ssh")

    # Resolve filesystem and contents_path to absolute paths so Cowrie works regardless of cwd
    parser.set("shell", "filesystem", str(target_pickle.resolve()))
    if profile.honeyfs_dir.is_dir():
        parser.set("honeypot", "contents_path", str(profile.honeyfs_dir.resolve()))

    if hostname:
        parser.set("honeypot", "hostname", hostname)
    if ssh_port is not None:
        parser.set("ssh", "listen_endpoints", f"tcp:{ssh_port}:interface=0.0.0.0")

    if config_overrides:
        for section, kv in config_overrides.items():
            if not parser.has_section(section):
                parser.add_section(section)
            for k, v in kv.items():
                parser.set(section, k, str(v))

    with open(ACTIVE_CFG_PATH, "w", encoding="utf-8") as f:
        f.write(f"# Auto-generated by env_library.py from profile '{profile.name}'\n")
        f.write(f"# Description: {profile.description}\n\n")
        parser.write(f)

    # Copy userdb.txt and append any extra users
    userdb_text = profile.userdb_file.read_text(encoding="utf-8")
    if extra_users:
        userdb_text = userdb_text.rstrip("\n") + "\n\n# Extra users added at apply time\n"
        for entry in extra_users:
            parts = entry.split(":")
            if len(parts) == 2:
                userdb_text += f"{parts[0]}:x:{parts[1]}\n"
            else:
                userdb_text += f"{entry}\n"
    ACTIVE_USERDB_PATH.write_text(userdb_text, encoding="utf-8")

    status = {
        "active_environment": profile.name,
        "description": profile.description,
        "hostname": parser.get("honeypot", "hostname", fallback=profile.hostname),
        "filesystem_pickle": str(target_pickle.resolve()),
        "contents_path": parser.get("honeypot", "contents_path", fallback=""),
        "ssh_version": parser.get("ssh", "version", fallback=profile.ssh_version),
        "listen_endpoints": parser.get("ssh", "listen_endpoints", fallback="tcp:2222:interface=0.0.0.0"),
        "active_cfg": str(ACTIVE_CFG_PATH),
        "active_userdb": str(ACTIVE_USERDB_PATH),
    }
    ACTIVE_MARKER_PATH.write_text(json.dumps(status, indent=2), encoding="utf-8")
    return status


def get_active_status() -> dict[str, Any] | None:
    """Return metadata about the currently active environment, or None if not set."""
    if ACTIVE_MARKER_PATH.is_file():
        return json.loads(ACTIVE_MARKER_PATH.read_text(encoding="utf-8"))
    return None


def merge_custom_pickle_with_base(custom_pickle_path: Path, output_path: Path | None = None) -> Path:
    """
    Utility to merge a sparse custom createfs pickle onto Cowrie's full base fs.pickle
    so standard Linux directories (/bin, /usr, /etc/passwd, /etc/group) are always present.
    """
    with open(BASE_PICKLE_PATH, "rb") as f:
        base_tree = pickle.load(f)
    with open(custom_pickle_path, "rb") as f:
        overlay_tree = pickle.load(f)

    def _merge(dst: list[Any], src: list[Any]) -> None:
        dst_children = {c[0]: c for c in dst[7]}
        for s_child in src[7]:
            cname = s_child[0]
            if cname in dst_children:
                d_child = dst_children[cname]
                if (
                    d_child[1] == 1
                    and s_child[1] == 1
                    and isinstance(d_child[7], list)
                    and isinstance(s_child[7], list)
                ):
                    _merge(d_child, s_child)
                else:
                    dst[7].remove(d_child)
                    dst[7].append(copy.deepcopy(s_child))
            else:
                dst[7].append(copy.deepcopy(s_child))

    merged = copy.deepcopy(base_tree)
    _merge(merged, overlay_tree)
    out = output_path or custom_pickle_path
    with open(out, "wb") as f:
        pickle.dump(merged, f)
    return out


def _cli() -> None:
    ap = argparse.ArgumentParser(
        description="HP_Exposures Environment Profile Library & Switcher"
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List available environment profiles")

    show_p = sub.add_parser("show", help="Show details of a specific environment profile")
    show_p.add_argument("env", choices=sorted(ENVIRONMENTS.keys()), help="Environment name")

    apply_p = sub.add_parser("apply", help="Activate an environment profile in cowrie/etc/")
    apply_p.add_argument("env", choices=sorted(ENVIRONMENTS.keys()), help="Environment name")
    apply_p.add_argument("--hostname", type=str, default=None, help="Override hostname")
    apply_p.add_argument("--port", type=int, default=None, help="Override SSH listen port")
    apply_p.add_argument(
        "--add-user",
        action="append",
        default=[],
        metavar="USER:PASS",
        help="Add extra user:password credential to userdb.txt (can be passed multiple times)",
    )
    apply_p.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="SECTION.KEY=VALUE",
        help="Override any cowrie.cfg option, e.g. --set ssh.auth_none_enabled=true",
    )

    sub.add_parser("status", help="Show currently active environment")

    args = ap.parse_args()

    if args.cmd == "list":
        active = get_active_status()
        active_name = active["active_environment"] if active else None
        print("Available Honeypot Environments:")
        print("-" * 72)
        for name, prof in ENVIRONMENTS.items():
            marker = " [ACTIVE]" if name == active_name else ""
            print(f"  {name}{marker}")
            print(f"    Description : {prof.description}")
            print(f"    Hostname    : {prof.hostname}")
            print(f"    Pickle FS   : {prof.pickle_file.name}")
            print(f"    SSH Banner  : {prof.ssh_version}")
            print(f"    Users       : {', '.join(prof.default_users)}")
            print()

    elif args.cmd == "show":
        prof = get_environment(args.env)
        print(f"=== Environment: {prof.name} ===")
        print(f"Description : {prof.description}")
        print(f"Config file : {prof.cfg_file}")
        print(f"UserDB file : {prof.userdb_file}")
        print(f"Pickle file : {prof.pickle_file}")
        print(f"Honeyfs dir : {prof.honeyfs_dir}")
        print("\n--- cowrie.cfg ---")
        print(prof.cfg_file.read_text(encoding="utf-8"))
        print("--- userdb.txt ---")
        print(prof.userdb_file.read_text(encoding="utf-8"))

    elif args.cmd == "apply":
        overrides: dict[str, dict[str, str]] = {}
        for item in args.set:
            if "=" not in item or "." not in item.split("=", 1)[0]:
                ap.error(f"Invalid --set format '{item}'. Expected SECTION.KEY=VALUE")
            sec_key, val = item.split("=", 1)
            sec, key = sec_key.split(".", 1)
            overrides.setdefault(sec, {})[key] = val

        status = apply_environment(
            args.env,
            hostname=args.hostname,
            ssh_port=args.port,
            extra_users=args.add_user,
            config_overrides=overrides,
        )
        print(f"Activated environment: {status['active_environment']}")
        print(f"  Hostname         : {status['hostname']}")
        print(f"  SSH Endpoint     : {status['listen_endpoints']}")
        print(f"  SSH Banner       : {status['ssh_version']}")
        print(f"  Filesystem Pickle: {status['filesystem_pickle']}")
        print(f"  Honeyfs Overrides: {status['contents_path']}")
        print(f"  Written Config   : {status['active_cfg']}")
        print(f"  Written UserDB   : {status['active_userdb']}")

    elif args.cmd == "status":
        status = get_active_status()
        if not status:
            print("No environment profile is currently active (using default bundled Cowrie config).")
        else:
            print(json.dumps(status, indent=2))


if __name__ == "__main__":
    _cli()
