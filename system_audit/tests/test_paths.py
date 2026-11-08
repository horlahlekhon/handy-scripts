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
    resolve_watch_paths_report,
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
    assert DEFAULT_SENSITIVE_PATHS == (
        "~/.aws/credentials",
        "~/.aws/config",
        "~/.ssh",
        "~/.config/gh/hosts.yml",
        "~/.config/gcloud/credentials.db",
        "~/.config/gcloud/legacy_credentials",
        "~/.docker/config.json",
        "~/.kube/config",
        "~/.npmrc",
        "~/.pypirc",
        "~/.netrc",
        "~/.gnupg",
        "~/.config/op",
        "~/.terraform.d/credentials.tfrc.json",
        "~/.azure/accessTokens.json",
        "~/.config/doctl",
    )


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


def test_symlink_loop_does_not_crash(cfg, home, caplog):
    (home / ".npmrc").symlink_to(home / ".npmrc")
    (home / ".netrc").write_text("x")
    with caplog.at_level(logging.WARNING):
        result = resolve_watch_paths(cfg)
    assert home / ".npmrc" in result
    assert home / ".netrc" in result


def test_env_file_with_newline_skipped(home, caplog):
    (home / ".env\n-D").write_text("x")
    (home / ".env").write_text("x")
    cfg = EnvScanConfig(roots=(home,), max_depth=2, excludes=())
    with caplog.at_level(logging.WARNING):
        found = scan_env_files(cfg)
    assert found == (home / ".env",)
    assert any("control" in r.getMessage() for r in caplog.records)


def test_resolve_skips_control_char_extra_paths(cfg, home):
    bad = home / "x\u2028y"
    bad.write_text("x")
    result = resolve_watch_paths(replace(cfg, extra_paths=(bad,)))
    assert bad not in result


@pytest.mark.parametrize("name", ["a\nb", "a\x00b", "a\x7fb", "a\x85b", "a\u2029b"])
def test_write_watch_list_rejects_control_chars(tmp_path, name):
    dest = tmp_path / "watch.list"
    with pytest.raises(ValueError):
        write_watch_list((Path("/ok"), Path("/bad/" + name)), dest)
    assert not dest.exists()


def test_symlink_to_root_not_watched(cfg, home):
    (home / ".npmrc").symlink_to("/")
    (home / ".netrc").write_text("x")
    result = resolve_watch_paths(cfg)
    assert Path("/") not in result
    assert home / ".netrc" in result
    assert home / ".npmrc" in result


def test_symlink_into_home_dir_resolved(cfg, home):
    (home / "dotfiles" / "config" / "gh").mkdir(parents=True)
    (home / "dotfiles" / "config" / "gh" / "hosts.yml").write_text("x")
    (home / ".config").symlink_to(home / "dotfiles" / "config")
    result = resolve_watch_paths(cfg)
    assert home / ".config" / "gh" / "hosts.yml" in result
    assert home / "dotfiles" / "config" / "gh" / "hosts.yml" in result


def test_home_or_ancestor_never_watched(cfg, home):
    result = resolve_watch_paths(replace(cfg, extra_paths=(home, home.parent)))
    assert home not in result
    assert home.parent not in result


def test_matcher_normalizes_dotdot(home):
    m = WatchMatcher([home / "x" / ".." / ".aws"])
    assert m.matches(str(home / ".aws" / "credentials"))
    assert m.matches(str(home / "tmp" / ".." / ".aws" / "credentials"))
    assert not m.matches(str(home / ".aws" / ".." / ".aws-old" / "x"))


def test_matcher_case_insensitive(home):
    assert not WatchMatcher([home / ".aws"]).matches(str(home / ".AWS" / "c"))
    assert WatchMatcher([home / ".aws"], case_insensitive=True).matches(str(home / ".AWS" / "c"))


def test_report_lists_symlink_targets_outside_home(cfg, home, tmp_path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "netrc").write_text("x")
    (home / ".netrc").symlink_to(outside / "netrc")
    (home / ".npmrc").write_text("x")
    paths, skipped = resolve_watch_paths_report(cfg)
    assert home / ".netrc" in paths
    assert (outside / "netrc").resolve() not in paths
    assert skipped == ((home / ".netrc", (outside / "netrc").resolve()),)
    assert paths == resolve_watch_paths(cfg)


def test_report_has_no_skips_for_inside_home_targets(cfg, home):
    (home / "dotfiles").mkdir()
    (home / "dotfiles" / "npmrc").write_text("x")
    (home / ".npmrc").symlink_to(home / "dotfiles" / "npmrc")
    _, skipped = resolve_watch_paths_report(cfg)
    assert skipped == ()


def test_watch_matcher_normalized_watch_paths_folded():
    m = WatchMatcher([Path("/Users/Alice/.AWS/./credentials"), Path("/x//y")], case_insensitive=True)
    assert m.case_insensitive is True
    assert m.normalized_watch_paths() == ("/users/alice/.aws/credentials", "/x/y")


def test_watch_matcher_normalized_watch_paths_case_sensitive():
    m = WatchMatcher([Path("/B/c"), Path("/A")])
    assert m.case_insensitive is False
    assert m.normalized_watch_paths() == ("/A", "/B/c")
