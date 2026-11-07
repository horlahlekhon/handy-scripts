from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from credwatch.config import AllowRule, ConfigError, default_config_dict, load_config
from credwatch.platform_info import TargetUser


@pytest.fixture
def home(tmp_path) -> Path:
    return tmp_path / "home"


@pytest.fixture
def target(home) -> TargetUser:
    return TargetUser(name="alice", uid=1000, gid=1000, home=home)


def _write(tmp_path, data) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data))
    return p


@pytest.mark.parametrize(
    "os_name,suffix",
    [("linux", ".local/share/credwatch"), ("darwin", "Library/Application Support/credwatch")],
)
def test_defaults_expand_tilde_against_target_home(tmp_path, target, home, os_name, suffix):
    cfg = load_config(_write(tmp_path, {}), os_name, target)
    assert cfg.data_dir == home / suffix
    assert cfg.home == home
    assert cfg.target_user == "alice"
    assert cfg.env_scan.roots == (home,)
    assert cfg.env_scan.max_depth == 4
    assert cfg.capture.interface == ("any" if os_name == "linux" else "pktap,all")
    assert all("~" not in r.path_pattern for r in cfg.allowlist)
    assert AllowRule(str(home / ".gnupg/**"), ("gpg", "gpg-agent", "gpgsm")) in cfg.allowlist


def test_missing_file_uses_defaults(tmp_path, target):
    cfg = load_config(tmp_path / "nope.yaml", "linux", target)
    assert cfg.email.digest_hour == 8


def test_canary_rule_always_appended(tmp_path, target, home):
    cfg = load_config(_write(tmp_path, {"allowlist": []}), "linux", target)
    assert cfg.allowlist[-1] == AllowRule(
        str(home / ".local/share/credwatch/canary"), ("credwatch", "python3*")
    )


def test_yaml_overrides_merge_deeply(tmp_path, target):
    cfg = load_config(_write(tmp_path, {"capture": {"retain_files": 24}}), "linux", target)
    assert cfg.capture.retain_files == 24
    assert cfg.capture.rotate_seconds == 3600


def test_yaml_allowlist_and_extra_paths(tmp_path, target, home):
    data = {
        "extra_paths": ["~/secrets.txt"],
        "allowlist": [{"path_pattern": "~/x/**", "processes": ["foo"]}],
    }
    cfg = load_config(_write(tmp_path, data), "linux", target)
    assert cfg.extra_paths == (home / "secrets.txt",)
    assert cfg.allowlist[0] == AllowRule(str(home / "x/**"), ("foo",))
    assert len(cfg.allowlist) == 2


def test_default_config_dict_does_not_leak_mutation():
    d = default_config_dict("linux")
    d["capture"]["retain_files"] = 1
    assert default_config_dict("linux")["capture"]["retain_files"] == 168


def test_invalid_digest_hour_raises_config_error(tmp_path, target):
    with pytest.raises(ConfigError, match=r"email\.digest_hour"):
        load_config(_write(tmp_path, {"email": {"digest_hour": 25}}), "linux", target)


def test_config_rejects_smtp_password_key(tmp_path, target):
    with pytest.raises(ConfigError, match=r"email\.password"):
        load_config(_write(tmp_path, {"email": {"password": "hunter2"}}), "linux", target)


def test_error_does_not_echo_secret_value(tmp_path, target):
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, {"email": {"password": "hunter2"}}), "linux", target)
    assert "hunter2" not in str(exc.value)


@pytest.mark.parametrize(
    "data,field",
    [
        ({"bogus": 1}, "bogus"),
        ({"capture": {"retain_files": 0}}, "capture.retain_files"),
        ({"capture": {"enabled": "yes"}}, "capture.enabled"),
        ({"env_scan": {"max_depth": -1}}, "env_scan.max_depth"),
        ({"email": {"smtp_port": 70000}}, "email.smtp_port"),
        ({"email": {"to_addrs": "a@b.c"}}, "email.to_addrs"),
        ({"audit_export": {"retention_days": 0}}, "audit_export.retention_days"),
        ({"allowlist": [{"path_pattern": "x"}]}, "allowlist[0].processes"),
        ({"allowlist": "nope"}, "allowlist"),
        ({"extra_paths": [1]}, "extra_paths[0]"),
        ({"capture": 5}, "capture"),
    ],
)
def test_invalid_values_name_the_field(tmp_path, target, data, field):
    with pytest.raises(ConfigError) as exc:
        load_config(_write(tmp_path, data), "linux", target)
    assert field in str(exc.value)


def test_non_mapping_yaml_rejected(tmp_path, target):
    p = tmp_path / "c.yaml"
    p.write_text("- a\n- b\n")
    with pytest.raises(ConfigError):
        load_config(p, "linux", target)


def test_malformed_yaml_rejected(tmp_path, target):
    p = tmp_path / "c.yaml"
    p.write_text("a: [unclosed\n")
    with pytest.raises(ConfigError):
        load_config(p, "linux", target)
