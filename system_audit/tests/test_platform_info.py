from __future__ import annotations

import os
import pwd
from pathlib import Path

import pytest

from credwatch import platform_info
from credwatch.platform_info import (
    UnknownUser,
    UnsupportedPlatform,
    current_os,
    default_data_dir,
    resolve_target_user,
)


def _fake_entry(name: str, uid: int, home: str) -> pwd.struct_passwd:
    return pwd.struct_passwd((name, "x", uid, uid, "", home, "/bin/sh"))


def test_resolve_target_user_prefers_sudo_user(monkeypatch):
    monkeypatch.setattr(
        platform_info.pwd, "getpwnam", lambda n: _fake_entry(n, 1001, f"/home/{n}")
    )
    user = resolve_target_user(None, {"SUDO_USER": "alice"})
    assert (user.name, user.uid, user.home) == ("alice", 1001, Path("/home/alice"))


def test_resolve_target_user_explicit_beats_sudo_user(monkeypatch):
    monkeypatch.setattr(
        platform_info.pwd, "getpwnam", lambda n: _fake_entry(n, 1002, f"/home/{n}")
    )
    assert resolve_target_user("bob", {"SUDO_USER": "alice"}).name == "bob"


def test_resolve_target_user_falls_back_to_current_user():
    user = resolve_target_user(None, {})
    assert user.uid == os.getuid()


def test_resolve_target_user_unknown_raises():
    with pytest.raises(UnknownUser):
        resolve_target_user("no-such-user-xyz", {})


def test_default_data_dir_per_os(tmp_path):
    assert default_data_dir(tmp_path, "linux") == tmp_path / ".local/share/credwatch"
    assert (
        default_data_dir(tmp_path, "darwin")
        == tmp_path / "Library/Application Support/credwatch"
    )


@pytest.mark.parametrize(
    "plat,expected", [("linux", "linux"), ("linux2", "linux"), ("darwin", "darwin")]
)
def test_current_os(monkeypatch, plat, expected):
    monkeypatch.setattr(platform_info.sys, "platform", plat)
    assert current_os() == expected


def test_current_os_unsupported(monkeypatch):
    monkeypatch.setattr(platform_info.sys, "platform", "win32")
    with pytest.raises(UnsupportedPlatform):
        current_os()
