import logging
import os
import stat
from dataclasses import replace
from pathlib import Path

import pytest

from credwatch.config import Config, EnvScanConfig, load_config
from credwatch.paths import (
    DEFAULT_SENSITIVE_PATHS,
    WatchMatcher,
    read_watch_list,
    resolve_watch_paths,
    scan_env_files,
    write_watch_list,
)
from credwatch.platform_info import TargetUser


@pytest.fixture
def home(tmp_path: Path) -> Path:
    h = tmp_path / "home"
    h.mkdir()
    return h


@pytest.fixture
def cfg(home: Path, tmp_path: Path) -> Config:
    base = load_config(tmp_path / "none.yaml", "linux", TargetUser("u", 1000, 1000, home))
    return replace(
        base,
        data_dir=tmp_path / "data",
        env_scan=EnvScanConfig(roots=(home,), max_depth=4, excludes=("node_modules", ".git")),
    )


def test_default_list_is_spec_verbatim():
    assert len(DEFAULT_SENSITIVE_PATHS) == 16
    assert DEFAULT_SENSITIVE_PATHS[0] == "~/.aws/credentials"
    assert DEFAULT_SENSITIVE_PATHS[-1] == "~/.config/doctl"


def test_only_existing_defaults_returned(cfg, home):
    (home / ".aws").mkdir()
    (home / ".aws" / "credentials").write_text("x")
    (home / ".netrc").write_text("x")
    result = resolve_watch_paths(cfg)
    assert home / ".aws" / "credentials" in result
    assert home / ".netrc" in result
    assert home / ".pypirc" not in result
    assert home / ".aws" / "config" not in result


def test_env_scan_respects_excludes_and_depth(home):
    (home / "proj" / "node_modules").mkdir(parents=True)
    (home / "proj" / "node_modules" / ".env").write_text("x")
    (home / "proj" / ".env.local").write_text("x")
    deep = home / "a" / "b" / "c" / "d" / "e"
    deep.mkdir(parents=True)
    (deep / ".env").write_text("x")
    (home / "a" / "b" / "c" / "d" / ".env").write_text("x")  # depth 4: included
    cfg = EnvScanConfig(roots=(home,), max_depth=4, excludes=("node_modules",))
    found = scan_env_files(cfg)
    assert home / "proj" / ".env.local" in found
    assert home / "proj" / "node_modules" / ".env" not in found
    assert deep / ".env" not in found
    assert home / "a" / "b" / "c" / "d" / ".env" in found


def test_env_scan_logs_unreadable_dir(tmp_path, caplog):
    cfg = EnvScanConfig(roots=(tmp_path / "missing",), max_depth=2, excludes=())
    with caplog.at_level(logging.WARNING):
        assert scan_env_files(cfg) == ()
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_symlinked_credential_watches_link_and_target(cfg, home):
    (home / "dotfiles").mkdir()
    target = home / "dotfiles" / "npmrc"
    target.write_text("x")
    (home / ".npmrc").symlink_to(target)
    result = resolve_watch_paths(cfg)
    assert home / ".npmrc" in result
    assert target.resolve() in result


def test_dangling_symlink_kept_with_warning(cfg, home, caplog):
    (home / ".netrc").symlink_to(home / "nowhere")
    with caplog.at_level(logging.WARNING):
        result = resolve_watch_paths(cfg)
    assert home / ".netrc" in result
    assert home / "nowhere" not in result
    assert any("dangling" in r.getMessage() for r in caplog.records)


def test_children_of_watched_dir_collapsed(cfg, home):
    (home / ".ssh").mkdir()
    (home / ".ssh" / "id_ed25519").write_text("x")
    cfg = replace(cfg, extra_paths=(home / ".ssh" / "id_ed25519",))
    result = resolve_watch_paths(cfg)
    assert home / ".ssh" in result
    assert home / ".ssh" / "id_ed25519" not in result


def test_canary_always_included(cfg):
    canary = cfg.data_dir / "canary"
    canary.mkdir(parents=True)
    assert canary in resolve_watch_paths(cfg)


def test_output_sorted_and_deduped(cfg, home):
    (home / ".npmrc").write_text("x")
    cfg = replace(cfg, extra_paths=(home / ".npmrc", home / ".npmrc"))
    result = resolve_watch_paths(cfg)
    assert result == tuple(sorted(set(result)))
    assert result.count(home / ".npmrc") == 1


def test_watch_matcher_does_not_match_sibling_prefix(home):
    m = WatchMatcher([home / ".aws"])
    assert m.matches(str(home / ".aws"))
    assert m.matches(str(home / ".aws" / "credentials"))
    assert not m.matches(str(home / ".aws-old" / "x"))


def test_watch_list_roundtrip_is_0600(tmp_path):
    dest = tmp_path / "sub" / "watch.list"
    paths = (Path("/a/b"), Path("/c"))
    write_watch_list(paths, dest)
    assert read_watch_list(dest) == paths
    assert stat.S_IMODE(os.stat(dest).st_mode) == 0o600
