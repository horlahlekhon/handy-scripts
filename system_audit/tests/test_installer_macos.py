import os
import plistlib
import pwd
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from credwatch.cli import build_parser
from credwatch.installer import InstallError, InstallReport, common, macos, run_install
from credwatch.platform_info import TargetUser

ME = pwd.getpwuid(os.geteuid())
PLIST = "Library/LaunchDaemons/com.credwatch.daemon.plist"
CONFIG_DIR = "private/etc/credwatch"
DATA = "Library/Application Support/credwatch"


def _fake_realpath(path: str) -> str:
    return {"/etc": "/private/etc", "/var": "/private/var", "/tmp": "/private/tmp"}.get(path, path)


class LaunchctlFake:
    def __init__(self, bootout_rc=3, bootstrap_rc=0):
        self.calls: list[tuple[str, ...]] = []
        self.bootout_rc, self.bootstrap_rc = bootout_rc, bootstrap_rc

    def run(self, argv, *, check=False, timeout=60):
        argv = tuple(argv)
        self.calls.append(argv)
        if argv[:2] == ("launchctl", "bootout"):
            return subprocess.CompletedProcess(argv, self.bootout_rc, "", "Boot-out failed: 3: No such process")
        if argv[:2] == ("launchctl", "bootstrap"):
            err = "Bootstrap failed: 5: Input/output error" if self.bootstrap_rc else ""
            return subprocess.CompletedProcess(argv, self.bootstrap_rc, "", err)
        return subprocess.CompletedProcess(argv, 0, "", "")


@pytest.fixture(autouse=True)
def _strict_umask():
    old = os.umask(0o022)
    yield
    os.umask(old)


@pytest.fixture
def env(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "Library/LaunchDaemons").mkdir(parents=True)
    etc = root / CONFIG_DIR
    etc.mkdir(parents=True, mode=0o700)
    (etc / "config.yaml").write_text(
        "env_scan:\n  roots: ['~']\n  max_depth: 3\n  excludes: []\n"
    )
    os.chmod(etc / "config.yaml", 0o600)
    home = tmp_path / "home"
    (home / ".aws").mkdir(parents=True)
    (home / ".aws" / "credentials").write_text("x")
    target = TargetUser(ME.pw_name, ME.pw_uid, ME.pw_gid, home)
    exe = Path("/opt/pipx/bin/credwatch")
    trust_checked: list[Path] = []
    monkeypatch.setattr(
        macos, "assert_root_owned_install", lambda exe, *a, **k: trust_checked.append(exe)
    )
    runner = LaunchctlFake()

    def install(**kw):
        kw.setdefault("executable", exe)
        return macos.install(
            target, runner=runner, root=root, owner_uid=os.geteuid(),
            realpath=_fake_realpath, **kw,
        )

    return SimpleNamespace(root=root, etc=etc, home=home, target=target, exe=exe,
                           runner=runner, install=install, trust_checked=trust_checked,
                           data=root / DATA)


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def _plist(env) -> dict:
    return plistlib.loads((env.root / PLIST).read_bytes())


# --- path mapping -----------------------------------------------------------------


@pytest.mark.parametrize(
    "given,expected",
    [
        ("/etc/credwatch", "/private/etc/credwatch"),
        ("/etc", "/private/etc"),
        ("/var/db/x", "/private/var/db/x"),
        ("/tmp/a", "/private/tmp/a"),
        ("/Library/Application Support/credwatch", "/Library/Application Support/credwatch"),
        ("/etcetera/x", "/etcetera/x"),
    ],
)
def test_resolve_system_path_maps_only_known_prefixes(given, expected):
    assert macos.resolve_system_path(Path(given), realpath=_fake_realpath) == Path(expected)


def test_resolve_system_path_does_not_resolve_other_components():
    seen = []

    def realpath(p):
        seen.append(p)
        return _fake_realpath(p)

    macos.resolve_system_path(Path("/etc/credwatch/link"), realpath=realpath)
    assert seen == ["/etc"]


def test_resolve_system_path_refuses_non_root_prefix_symlink():
    st = SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=501)
    with pytest.raises(InstallError, match="/etc is a symlink not owned by root"):
        macos.resolve_system_path(Path("/etc/credwatch"), realpath=_fake_realpath,
                                  lstat=lambda p: st)


def test_resolve_system_path_accepts_root_prefix_symlink():
    st = SimpleNamespace(st_mode=stat.S_IFLNK | 0o755, st_uid=0)
    got = macos.resolve_system_path(Path("/etc/credwatch"), realpath=_fake_realpath,
                                    lstat=lambda p: st)
    assert got == Path("/private/etc/credwatch")


# --- plist ------------------------------------------------------------------------


def test_plist_has_keepalive_and_secrets_arg():
    data = plistlib.loads(
        macos.render_plist(Path("/opt/pipx/bin/credwatch"), Path("/Library/Application Support/credwatch"))
    )
    assert data["Label"] == "com.credwatch.daemon"
    assert data["KeepAlive"] is True and data["RunAtLoad"] is True
    args = data["ProgramArguments"]
    assert args[0] == "/opt/pipx/bin/credwatch"
    assert args[args.index("--secrets-file") + 1] == "/etc/credwatch/secrets.env"
    assert args[args.index("--config") + 1] == "/etc/credwatch/config.yaml"
    assert data["StandardOutPath"] == "/Library/Application Support/credwatch/logs/launchd.out.log"
    assert data["StandardErrorPath"] == "/Library/Application Support/credwatch/logs/launchd.err.log"


def test_plist_arguments_parse_as_run_command():
    data = plistlib.loads(macos.render_plist(Path("/x/credwatch"), Path("/d")))
    ns = build_parser().parse_args(data["ProgramArguments"][1:])
    assert (ns.command, ns.config, ns.secrets_file) == (
        "run", "/etc/credwatch/config.yaml", "/etc/credwatch/secrets.env",
    )


# --- full flow --------------------------------------------------------------------


def test_first_macos_install_creates_everything(env):
    report = env.install()
    assert isinstance(report, InstallReport)
    assert _mode(env.data) == 0o700
    for sub in ("captures", "audit-exports", "logs"):
        assert _mode(env.data / sub) == 0o700
    assert (env.data / "canary").read_text() == common.CANARY_BODY
    assert _mode(env.etc / "secrets.env") == 0o600
    watch_list = (env.etc / "watched_paths.txt").read_text().splitlines()
    assert str(env.home / ".aws" / "credentials") in watch_list
    assert str(env.data / "canary") in watch_list
    assert report.watched == 2 and report.skipped == ()
    assert _mode(env.root / PLIST) == 0o644
    data = _plist(env)
    assert data["ProgramArguments"][0] == str(env.exe)
    assert data["StandardOutPath"] == "/Library/Application Support/credwatch/logs/launchd.out.log"
    assert env.runner.calls == [
        ("launchctl", "bootout", "system/com.credwatch.daemon"),
        ("launchctl", "bootstrap", "system", str(env.root / PLIST)),
    ]
    assert env.trust_checked == [env.exe]
    assert not (env.root / "etc").exists()  # never written through the /etc symlink path


def test_macos_install_idempotent(env):
    env.install()
    before = (env.root / PLIST).stat().st_mtime_ns
    env.runner.calls.clear()
    report = env.install()
    assert report.created == ()
    assert f"plist {env.root / PLIST}" in report.unchanged
    assert (env.root / PLIST).stat().st_mtime_ns == before
    assert env.runner.calls == [
        ("launchctl", "bootout", "system/com.credwatch.daemon"),
        ("launchctl", "bootstrap", "system", str(env.root / PLIST)),
    ]


def test_changed_plist_is_rewritten(env):
    env.install()
    (env.root / PLIST).write_bytes(b"stale")
    report = env.install()
    assert f"plist {env.root / PLIST}" in report.created
    assert _plist(env)["Label"] == "com.credwatch.daemon"


def test_bootout_not_loaded_logged_at_info(env, caplog):
    caplog.set_level("INFO", logger="credwatch.installer.macos")
    env.install()
    rec = next(r for r in caplog.records if "bootout" in r.getMessage())
    assert rec.levelname == "INFO"


def test_bootstrap_failure_raises(env):
    env.runner.bootstrap_rc = 5
    with pytest.raises(InstallError, match="launchctl bootstrap .* failed.*Input/output error"):
        env.install()


def test_no_start_skips_launchctl(env):
    env.install(start=False)
    assert env.runner.calls == []
    assert (env.root / PLIST).exists()


def test_untrusted_install_explains_homebrew(env, monkeypatch):
    def refuse(*a, **k):
        raise InstallError("unsafe install location: credwatch entry point /usr/local/bin/credwatch")

    monkeypatch.setattr(macos, "assert_root_owned_install", refuse)
    with pytest.raises(InstallError, match="Homebrew") as info:
        env.install()
    assert "PIPX_GLOBAL_BIN_DIR" in str(info.value)
    assert not env.data.exists()


def test_run_install_dispatches_darwin(env, monkeypatch):
    seen = {}

    def fake(target, **kw):
        seen.update(kw, target=target)
        return "report"

    monkeypatch.setattr(macos, "install", fake)
    assert run_install("darwin", env.target, runner=env.runner, root=env.root, start=False) == "report"
    assert seen["target"] == env.target and seen["start"] is False and seen["root"] == env.root


def test_unsupported_os_refused(env):
    with pytest.raises(InstallError, match="unsupported platform: plan9"):
        run_install("plan9", env.target, runner=env.runner)


def test_set_owner_uses_wheel_for_root(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(macos.os, "chown", lambda *a, **k: calls.append((a, k)))
    monkeypatch.setattr(macos.grp, "getgrnam", lambda n: SimpleNamespace(gr_gid=0))
    macos._set_owner(tmp_path / "p", 0)
    assert calls == [((tmp_path / "p", 0, 0), {"follow_symlinks": False})]


def test_set_owner_skipped_for_test_seam(monkeypatch, tmp_path):
    monkeypatch.setattr(macos.os, "chown", lambda *a, **k: pytest.fail("chown called"))
    macos._set_owner(tmp_path / "p", os.geteuid() or 1)
