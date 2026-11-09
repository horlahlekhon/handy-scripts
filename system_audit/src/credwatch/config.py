"""Frozen config dataclasses, OS-aware defaults, and YAML loading/validation."""
from __future__ import annotations

import copy
import logging
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from credwatch.platform_info import TargetUser, default_data_dir

logger = logging.getLogger(__name__)

CREDENTIAL_KEYS = frozenset({"password", "smtp_password", "smtp_user", "user", "username", "secret", "token"})


class ConfigError(ValueError):
    """Raised as '<dotted.field>: <reason>'. Never includes offending values for credential keys."""


@dataclass(frozen=True)
class EnvScanConfig:
    roots: tuple[Path, ...]
    max_depth: int
    excludes: tuple[str, ...]


@dataclass(frozen=True)
class AllowRule:
    path_pattern: str
    processes: tuple[str, ...]


@dataclass(frozen=True)
class CaptureConfig:
    enabled: bool
    interface: str
    rotate_seconds: int
    retain_files: int
    snaplen: int
    drop_privileges_to: str
    max_total_mb: int = 2048  # all pcaps together; oldest pruned first (newest kept)
    min_free_percent: int = 5  # data_dir filesystem floor: tcpdump paused below either
    min_free_mb: int = 1024


@dataclass(frozen=True)
class EmailConfig:
    smtp_host: str
    smtp_port: int
    from_addr: str
    to_addrs: tuple[str, ...]
    digest_hour: int
    send_immediately: bool
    coalesce_seconds: int


@dataclass(frozen=True)
class ExportConfig:
    interval_minutes: int
    retention_days: int


@dataclass(frozen=True)
class Config:
    target_user: str
    home: Path
    data_dir: Path
    extra_paths: tuple[Path, ...]
    env_scan: EnvScanConfig
    allowlist: tuple[AllowRule, ...]
    allowlist_trusted_dirs: tuple[Path, ...]
    capture: CaptureConfig
    email: EmailConfig
    audit_export: ExportConfig
    os_name: str
    # macOS only: trust an exe found by process-name lookup (spoofable; see docs).
    darwin_trust_name_resolution: bool = False


_TRUSTED_DIRS = {
    "linux": [
        "/usr/bin", "/usr/sbin", "/usr/libexec", "/usr/lib", "/bin", "/sbin",
        "/usr/local/bin", "/opt/pipx", "/snap/bin",
    ],
    "darwin": [
        "/usr/bin", "/usr/sbin", "/usr/libexec", "/bin", "/sbin", "/System",
        "/opt/pipx",
    ],
}


def default_config_dict(os_name: str) -> dict[str, Any]:
    """Defaults as plain data; paths keep a leading '~' to be expanded at load time."""
    return {
        "data_dir": str(default_data_dir(os_name)),
        "extra_paths": [],
        "env_scan": {
            "roots": ["~"],
            "max_depth": 4,
            "excludes": ["node_modules", ".git", "venv", ".venv"],
        },
        "allowlist": [
            {
                "path_pattern": "~/.ssh/**",
                "processes": [
                    "ssh", "git", "seahorse", "nautilus", "gnome-keyring-daemon",
                    "scp", "sftp", "rsync",
                ],
            },
            {
                "path_pattern": "~/.aws/**",
                "processes": ["aws", "python3*", "terraform"],
            },
            {"path_pattern": "~/.config/gh/**", "processes": ["gh", "git"]},
            {"path_pattern": "~/.gnupg/**", "processes": ["gpg", "gpg-agent", "gpgsm"]},
            {
                "path_pattern": "~/.docker/**",
                "processes": ["docker", "docker-credential-*"],
            },
            {"path_pattern": "~/.kube/**", "processes": ["kubectl", "helm", "k9s"]},
        ],
        "allowlist_trusted_dirs": list(_TRUSTED_DIRS.get(os_name, _TRUSTED_DIRS["linux"])),
        "capture": {
            "enabled": True,
            "interface": "any" if os_name == "linux" else "pktap,all",
            "rotate_seconds": 3600,
            "retain_files": 168,
            "snaplen": 0,
            "max_total_mb": 2048,
            "min_free_percent": 5,
            "min_free_mb": 1024,
            # macOS has no standard unprivileged capture user, so it keeps root.
            "drop_privileges_to": "tcpdump" if os_name == "linux" else "root",
        },
        "email": {
            "smtp_host": "smtp.gmail.com",
            "smtp_port": 587,
            "from_addr": "",
            "to_addrs": [],
            "digest_hour": 8,
            "send_immediately": True,
            "coalesce_seconds": 60,
        },
        "audit_export": {"interval_minutes": 60, "retention_days": 30},
        "darwin_trust_name_resolution": False,
    }


def _deep_merge(base: Mapping[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(dict(base))
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _expand(text: str, home: Path) -> str:
    if text == "~":
        return str(home)
    if text.startswith("~/"):
        return str(home / text[2:])
    return text


def _section(raw: Mapping[str, Any], name: str, allowed: set[str]) -> Mapping[str, Any]:
    section = raw[name]
    if not isinstance(section, Mapping):
        raise ConfigError(f"{name}: must be a mapping")
    for key in section:
        if key in CREDENTIAL_KEYS:
            raise ConfigError(
                f"{name}.{key}: credentials must not be set in config; "
                "use CREDWATCH_SMTP_USER / CREDWATCH_SMTP_PASSWORD in the secrets file"
            )
        if key not in allowed:
            raise ConfigError(f"{name}.{key}: unknown key")
    return section


def _int(section: Mapping[str, Any], name: str, key: str, lo: int, hi: int | None = None) -> int:
    value = section[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{name}.{key}: must be an integer")
    if value < lo or (hi is not None and value > hi):
        bound = f"between {lo} and {hi}" if hi is not None else f">= {lo}"
        raise ConfigError(f"{name}.{key}: must be {bound}")
    return value


def _bool(section: Mapping[str, Any], name: str, key: str) -> bool:
    value = section[key]
    if not isinstance(value, bool):
        raise ConfigError(f"{name}.{key}: must be true or false")
    return value


def _str(section: Mapping[str, Any], name: str, key: str) -> str:
    value = section[key]
    if not isinstance(value, str):
        raise ConfigError(f"{name}.{key}: must be a string")
    return value


def _user_name(section: Mapping[str, Any], name: str, key: str) -> str:
    value = _str(section, name, key)
    if not value or any(c.isspace() for c in value):
        raise ConfigError(f"{name}.{key}: must be a non-empty string without whitespace")
    return value


def _str_list(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ConfigError(f"{field}: must be a list")
    for i, item in enumerate(value):
        if not isinstance(item, str):
            raise ConfigError(f"{field}[{i}]: must be a string")
    return tuple(value)


def _build_allowlist(raw: Any, home: Path) -> tuple[AllowRule, ...]:
    if not isinstance(raw, list):
        raise ConfigError("allowlist: must be a list")
    rules: list[AllowRule] = []
    for i, item in enumerate(raw):
        field = f"allowlist[{i}]"
        if not isinstance(item, Mapping):
            raise ConfigError(f"{field}: must be a mapping")
        unknown = set(item) - {"path_pattern", "processes"}
        if unknown:
            raise ConfigError(f"{field}.{sorted(unknown)[0]}: unknown key")
        pattern = item.get("path_pattern")
        if not isinstance(pattern, str) or not pattern:
            raise ConfigError(f"{field}.path_pattern: must be a non-empty string")
        if "processes" not in item:
            raise ConfigError(f"{field}.processes: required")
        procs = _str_list(item["processes"], f"{field}.processes")
        if not procs:
            raise ConfigError(f"{field}.processes: must not be empty")
        rules.append(AllowRule(_expand(pattern, home), procs))
    return tuple(rules)


def _read_yaml(path: Path) -> Mapping[str, Any]:
    try:
        text = path.read_text()
    except FileNotFoundError:
        logger.info("config file %s not found; using defaults", path)
        return {}
    except OSError as exc:
        raise ConfigError(f"{path}: cannot read config ({exc.strerror})") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{path}: config is not valid UTF-8") from exc
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"{path}: invalid YAML") from exc
    if loaded is None:
        return {}
    if not isinstance(loaded, Mapping):
        raise ConfigError(f"{path}: top level must be a mapping")
    return loaded


_TOP_KEYS = {
    "data_dir", "extra_paths", "env_scan", "allowlist", "allowlist_trusted_dirs", "capture",
    "email", "audit_export", "darwin_trust_name_resolution",
}


_CAPTURE_KEYS = {
    "enabled", "interface", "rotate_seconds", "retain_files", "snaplen", "drop_privileges_to",
    "max_total_mb", "min_free_percent", "min_free_mb",
}
MAX_MIN_FREE_PERCENT = 50


def _build_capture(merged: Mapping[str, Any]) -> CaptureConfig:
    cap = _section(merged, "capture", _CAPTURE_KEYS)
    return CaptureConfig(
        enabled=_bool(cap, "capture", "enabled"),
        interface=_str(cap, "capture", "interface"),
        rotate_seconds=_int(cap, "capture", "rotate_seconds", 1),
        retain_files=_int(cap, "capture", "retain_files", 1),
        snaplen=_int(cap, "capture", "snaplen", 0),
        drop_privileges_to=_user_name(cap, "capture", "drop_privileges_to"),
        max_total_mb=_int(cap, "capture", "max_total_mb", 1),
        min_free_percent=_int(cap, "capture", "min_free_percent", 0, MAX_MIN_FREE_PERCENT),
        min_free_mb=_int(cap, "capture", "min_free_mb", 0),
    )


def load_config(path: Path, os_name: str, target: TargetUser) -> Config:
    merged = _deep_merge(default_config_dict(os_name), _read_yaml(path))
    for key in merged:
        if key not in _TOP_KEYS:
            raise ConfigError(f"{key}: unknown key")
    home = target.home

    data_dir_raw = merged["data_dir"]
    if not isinstance(data_dir_raw, str) or not data_dir_raw:
        raise ConfigError("data_dir: must be a non-empty string")
    data_dir = Path(_expand(data_dir_raw, home))

    extra = _str_list(merged["extra_paths"], "extra_paths")

    env = _section(merged, "env_scan", {"roots", "max_depth", "excludes"})
    env_scan = EnvScanConfig(
        roots=tuple(Path(_expand(r, home)) for r in _str_list(env["roots"], "env_scan.roots")),
        max_depth=_int(env, "env_scan", "max_depth", 0),
        excludes=_str_list(env["excludes"], "env_scan.excludes"),
    )

    capture = _build_capture(merged)

    em = _section(
        merged,
        "email",
        {"smtp_host", "smtp_port", "from_addr", "to_addrs", "digest_hour",
         "send_immediately", "coalesce_seconds"},
    )
    email = EmailConfig(
        smtp_host=_str(em, "email", "smtp_host"),
        smtp_port=_int(em, "email", "smtp_port", 1, 65535),
        from_addr=_str(em, "email", "from_addr"),
        to_addrs=_str_list(em["to_addrs"], "email.to_addrs"),
        digest_hour=_int(em, "email", "digest_hour", 0, 23),
        send_immediately=_bool(em, "email", "send_immediately"),
        coalesce_seconds=_int(em, "email", "coalesce_seconds", 0),
    )

    ex = _section(merged, "audit_export", {"interval_minutes", "retention_days"})
    audit_export = ExportConfig(
        interval_minutes=_int(ex, "audit_export", "interval_minutes", 1),
        retention_days=_int(ex, "audit_export", "retention_days", 1),
    )

    trust_names = merged["darwin_trust_name_resolution"]
    if not isinstance(trust_names, bool):
        raise ConfigError("darwin_trust_name_resolution: must be true or false")

    return Config(
        target_user=target.name,
        home=home,
        data_dir=data_dir,
        extra_paths=tuple(Path(_expand(p, home)) for p in extra),
        env_scan=env_scan,
        allowlist=_build_allowlist(merged["allowlist"], home),
        allowlist_trusted_dirs=tuple(
            Path(_expand(d, home))
            for d in _str_list(merged["allowlist_trusted_dirs"], "allowlist_trusted_dirs")
        ),
        capture=capture,
        email=email,
        audit_export=audit_export,
        os_name=os_name,
        darwin_trust_name_resolution=trust_names,
    )
