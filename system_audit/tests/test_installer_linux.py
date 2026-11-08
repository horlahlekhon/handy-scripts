import os
import pwd
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from credwatch import installer
from credwatch.installer import InstallError, InstallReport, common, linux, run_install
from credwatch.platform_info import TargetUser

REPO = Path(__file__).resolve().parents[1]
ME = pwd.getpwuid(os.geteuid())
RULES = "etc/audit/rules.d/credwatch.rules"
UNIT = "etc/systemd/system/credwatch.service"


class AuditFake:
    """Runner that simulates augenrules/auditctl against the rules file under root."""

    def __init__(self, root: Path, enabled: int = 1):
        self.root = root
        self.enabled = enabled
        self.loaded: list[str] = []
        self.calls: list[tuple[str, ...]] = []
        self.fail: dict[tuple[str, ...], str] = {}
        self.need_reload = False

    def run(self, argv, *, check=False, timeout=60):
        argv = tuple(argv)
        self.calls.append(argv)
        for prefix, err in self.fail.items():
            if argv[: len(prefix)] == prefix:
                return subprocess.CompletedProcess(argv, 1, "", err)
        out = ""
        if argv == ("augenrules", "--load"):
            text = (self.root / RULES).read_text()
            self.loaded = [ln for ln in text.splitlines() if ln.startswith("-w ")]
        elif argv == ("auditctl", "-l"):
            out = "\n".join(self.loaded) + "\n" if self.loaded else "No rules\n"
        elif argv == ("auditctl", "-s"):
            out = f"enabled {self.enabled}\n"
        elif argv[:2] == ("systemctl", "show"):
            out = "yes\n" if self.need_reload else "no\n"
        elif argv == ("systemctl", "daemon-reload"):
            self.need_reload = False
        return subprocess.CompletedProcess(argv, 0, out, "")

    def count(self, *prefix):
        return sum(1 for c in self.calls if c[: len(prefix)] == prefix)

    def reset(self):
        self.calls = []


def _config_text(capture_user: str) -> str:
    return (
        "env_scan:\n  roots: ['~']\n  max_depth: 3\n  excludes: []\n"
        f"capture:\n  drop_privileges_to: {capture_user}\n"
    )


@pytest.fixture(autouse=True)
def _strict_umask():
    old = os.umask(0o022)  # dev machines often use 002, which makes test dirs group-writable
    yield
    os.umask(old)


@pytest.fixture
def env(tmp_path, monkeypatch):
    root = tmp_path / "root"
    (root / "etc/audit/rules.d").mkdir(parents=True)
    (root / "etc/systemd/system").mkdir(parents=True)
    etc = root / "etc/credwatch"
    etc.mkdir(mode=0o700)
    (etc / "config.yaml").write_text(_config_text(ME.pw_name))
    os.chmod(etc / "config.yaml", 0o600)
    home = tmp_path / "home"
    (home / ".aws").mkdir(parents=True)
    (home / ".aws" / "credentials").write_text("x")
    target = TargetUser(ME.pw_name, ME.pw_uid, ME.pw_gid, home)
    exe = Path("/opt/pipx/bin/credwatch")
    trust_checked: list[Path] = []
    monkeypatch.setattr(
        linux, "assert_root_owned_install", lambda exe, *a, **k: trust_checked.append(exe)
    )
    runner = AuditFake(root)

    def install(**kw):
        kw.setdefault("executable", exe)
        return run_install(
            "linux", target, runner=runner, root=root, owner_uid=os.geteuid(), **kw
        )

    return SimpleNamespace(root=root, etc=etc, home=home, target=target, exe=exe,
                           runner=runner, install=install, trust_checked=trust_checked,
                           data=root / "var/lib/credwatch")


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.stat().st_mode)


# --- full flow ------------------------------------------------------------------


def test_first_install_creates_everything(env):
    report = env.install()
    assert isinstance(report, InstallReport)
    assert _mode(env.data) == 0o711  # traversable so the capture user can reach captures/
    for sub in ("captures", "audit-exports", "logs"):
        assert _mode(env.data / sub) == 0o700
    assert (env.data / "canary").read_text() == common.CANARY_BODY
    assert _mode(env.data / "canary") == 0o600
    rules = (env.root / RULES).read_text()
    assert f"-w {env.home}/.aws/credentials -p rwa -k credwatch" in rules
    assert f"-w {env.data}/canary -p rwa -k credwatch" in rules
    assert report.watched == 2
    assert env.runner.count("systemctl", "enable", "--now", "auditd") == 1
    assert env.runner.count("augenrules", "--load") == 1
    assert env.runner.calls[-3:] == [
        ("systemctl", "daemon-reload"),
        ("systemctl", "enable", "credwatch"),
        ("systemctl", "restart", "credwatch"),
    ]
    watch_list = (env.etc / "watched_paths.txt").read_text().split()
    assert str(env.data / "canary") in watch_list


def test_install_twice_is_idempotent(env):
    env.install()
    env.runner.reset()
    second = env.install()
    assert second.created == ()
    assert all("placeholders" in w for w in second.warnings)
    assert env.runner.count("augenrules") == 0
    assert env.runner.count("systemctl", "daemon-reload") == 0
    assert env.runner.count("systemctl", "enable", "credwatch") == 1
    assert env.runner.count("systemctl", "restart", "credwatch") == 1


def test_reinstall_repairs_flushed_kernel_rules(env):
    env.install()
    env.runner.loaded = []
    env.runner.reset()
    report = env.install()
    assert env.runner.count("augenrules", "--load") == 1
    assert any("audit rules" in c for c in report.created)


def test_new_env_file_refreshes_rules(env):
    env.install()
    env.runner.reset()
    (env.home / "proj").mkdir()
    (env.home / "proj" / ".env").write_text("K=V")
    report = env.install()
    assert f"-w {env.home}/proj/.env -p rwa -k credwatch" in (env.root / RULES).read_text()
    assert any("audit rules" in c for c in report.created)
    assert any("watched_paths" in c for c in report.created)
    assert env.runner.count("augenrules", "--load") == 1
    assert env.runner.count("systemctl", "restart", "credwatch") == 1
    assert report.watched == 3


def test_no_start_skips_restart(env):
    env.install(start=False)
    assert env.runner.count("systemctl", "restart") == 0
    assert env.runner.count("systemctl", "enable", "credwatch") == 1


def test_unit_renders_executable_path(env):
    env.install()
    unit = (env.root / UNIT).read_text()
    assert f"ExecStart={env.exe} run --config /etc/credwatch/config.yaml\n" in unit
    assert "{executable}" not in unit
    assert "EnvironmentFile=/etc/credwatch/secrets.env" in unit
    assert _mode(env.root / UNIT) == 0o644


def test_changed_executable_rewrites_unit_and_reloads(env):
    env.install()
    env.runner.reset()
    report = env.install(executable=Path("/usr/local/bin/credwatch"))
    assert "ExecStart=/usr/local/bin/credwatch run" in (env.root / UNIT).read_text()
    assert env.runner.count("systemctl", "daemon-reload") == 1
    assert any("credwatch.service" in c for c in report.created)


def test_rerun_after_failed_daemon_reload_reloads(env):
    env.runner.fail[("systemctl", "daemon-reload")] = "Failed to reload"
    with pytest.raises(InstallError, match="daemon-reload"):
        env.install()
    env.runner.need_reload = True  # systemd sees the unit changed on disk
    del env.runner.fail[("systemctl", "daemon-reload")]
    env.runner.reset()
    report = env.install()
    assert any("credwatch.service" in u for u in report.unchanged)
    assert env.runner.count("systemctl", "daemon-reload") == 1


def test_failing_need_reload_query_reloads(env):
    env.install()
    env.runner.fail[("systemctl", "show")] = "bus error"
    env.runner.reset()
    env.install()
    assert env.runner.count("systemctl", "daemon-reload") == 1


def test_executable_with_whitespace_refused(env):
    with pytest.raises(InstallError, match="whitespace"):
        env.install(executable=Path("/opt/my tools/credwatch"))


def test_relative_executable_refused(env):
    with pytest.raises(InstallError, match="absolute"):
        env.install(executable=Path("bin/credwatch"))


def test_secrets_created_0600_with_warning(env):
    report = env.install()
    secrets = env.etc / "secrets.env"
    assert _mode(secrets) == 0o600
    assert "CREDWATCH_SMTP_PASSWORD=REPLACE_ME" in secrets.read_text()
    assert any("placeholders" in w and "secrets.env" in w for w in report.warnings)


def test_existing_secrets_kept_and_tightened(env):
    secrets = env.etc / "secrets.env"
    secrets.write_text("CREDWATCH_SMTP_USER=a\nCREDWATCH_SMTP_PASSWORD=b\n")
    os.chmod(secrets, 0o644)
    report = env.install()
    assert secrets.read_text() == "CREDWATCH_SMTP_USER=a\nCREDWATCH_SMTP_PASSWORD=b\n"
    assert _mode(secrets) == 0o600
    assert not any("placeholders" in w for w in report.warnings)


def test_existing_config_never_overwritten(env):
    before = (env.etc / "config.yaml").read_text()
    report = env.install()
    assert (env.etc / "config.yaml").read_text() == before
    assert any("config.yaml" in u for u in report.unchanged)


def test_capture_dir_owned_by_capture_user(env):
    env.install()
    st = (env.data / "captures").stat()
    assert st.st_uid == ME.pw_uid and stat.S_IMODE(st.st_mode) == 0o700


def test_missing_capture_user_warns_and_keeps_root_owned(env):
    (env.etc / "config.yaml").write_text(_config_text("no-such-user-credwatch"))
    report = env.install()
    assert any("no-such-user-credwatch" in w for w in report.warnings)
    assert _mode(env.data / "captures") == 0o700
    assert _mode(env.data) == 0o700


def test_skipped_symlink_target_and_unruleable_path_reported(env, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "netrc").write_text("x")
    (env.home / ".netrc").symlink_to(outside / "netrc")
    spaced = env.home / "my proj"
    spaced.mkdir()
    (spaced / ".env").write_text("x")
    report = env.install()
    assert any(str(outside / "netrc") in w and "outside" in w for w in report.warnings)
    assert report.skipped == (spaced / ".env",)
    assert "my proj" not in (env.root / RULES).read_text()


def test_immutable_audit_rules_surface_clearly(env):
    env.runner.enabled = 2
    with pytest.raises(InstallError, match=r"immutable \(-e 2\)"):
        env.install()


def test_auditd_enable_failure_surfaces(env):
    env.runner.fail[("systemctl", "enable", "--now", "auditd")] = "Unit auditd.service not found."
    with pytest.raises(InstallError, match="auditd.service not found"):
        env.install()


def test_systemctl_restart_failure_raises(env):
    env.runner.fail[("systemctl", "restart")] = "Job failed"
    with pytest.raises(InstallError, match="restart credwatch.*Job failed"):
        env.install()


def test_invalid_config_raises_install_error(env):
    (env.etc / "config.yaml").write_text("bogus: 1\n")
    with pytest.raises(InstallError, match="bogus"):
        env.install()


def test_symlinked_config_dir_refused(env, tmp_path):
    real = tmp_path / "realetc"
    env.etc.rename(real)
    env.etc.symlink_to(real)
    with pytest.raises(InstallError, match="symlink"):
        env.install()


def test_group_writable_config_dir_refused(env):
    os.chmod(env.etc, 0o770)
    with pytest.raises(InstallError, match="writable"):
        env.install()


def test_symlinked_canary_refused(env, tmp_path):
    env.install()
    (env.data / "canary").unlink()
    (env.data / "canary").symlink_to(tmp_path / "victim")
    with pytest.raises(InstallError, match="canary"):
        env.install()
    assert not (tmp_path / "victim").exists()


def test_symlinked_captures_dir_refused(env, tmp_path):
    env.install()
    (env.data / "captures").rmdir()
    (tmp_path / "victim").mkdir()
    (env.data / "captures").symlink_to(tmp_path / "victim")
    with pytest.raises(InstallError, match="captures.*symlink"):
        env.install()


def _fake_owner(monkeypatch, suffix: str, uid: int = 4242):
    """Report a foreign owner for the fd opened at a path ending with suffix."""
    real = os.fstat

    def fstat(fd):
        st = real(fd)
        if os.readlink(f"/proc/self/fd/{fd}").endswith(suffix):
            return SimpleNamespace(st_uid=uid, st_gid=st.st_gid, st_mode=st.st_mode)
        return st

    monkeypatch.setattr(os, "fstat", fstat)


def test_stranger_owned_captures_dir_refused(env, monkeypatch):
    env.install()
    _fake_owner(monkeypatch, "/var/lib/credwatch/captures")
    with pytest.raises(InstallError, match="captures is owned by uid 4242"):
        env.install()


def test_stranger_owned_existing_file_in_data_dir_refused(env, monkeypatch):
    env.install()
    _fake_owner(monkeypatch, "/var/lib/credwatch/canary")
    with pytest.raises(InstallError, match="canary: owned by uid 4242"):
        env.install()


def test_data_dir_must_be_absolute(env):
    (env.etc / "config.yaml").write_text("data_dir: relative/dir\n")
    with pytest.raises(InstallError, match="data_dir"):
        env.install()


def test_requires_root(env):
    if os.geteuid() == 0:
        pytest.skip("running as root")
    with pytest.raises(InstallError, match="root"):
        run_install("linux", env.target, runner=env.runner, root=env.root, executable=env.exe)


def test_darwin_not_implemented(env):
    with pytest.raises(InstallError, match="macOS installer not implemented yet"):
        run_install("darwin", env.target, runner=env.runner, root=env.root)


def test_install_rejects_unsafe_executable_before_writing(env, monkeypatch):
    def refuse(*a, **k):
        raise InstallError("reinstall with sudo pipx install --global .")

    monkeypatch.setattr(linux, "assert_root_owned_install", refuse)
    with pytest.raises(InstallError, match="pipx"):
        env.install()
    assert not env.data.exists()
    assert not (env.etc / "secrets.env").exists()


def _script(path: Path, shebang: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"#!{shebang}\nimport credwatch\n")
    return path


def test_execstart_is_running_entry_point_not_which(env, monkeypatch, tmp_path):
    real = _script(tmp_path / "venv/bin/credwatch", "/venv/bin/python")
    link = tmp_path / "localbin" / "credwatch"
    link.parent.mkdir()
    link.symlink_to(real)
    monkeypatch.setattr(linux.sys, "argv", [str(link), "install"])
    monkeypatch.setattr(linux.shutil, "which", lambda name: "/usr/bin/some-other-credwatch")
    env.install(executable=None)
    assert f"ExecStart={link} run" in (env.root / UNIT).read_text()
    assert env.trust_checked == [link]


def test_relative_argv0_made_absolute(monkeypatch, tmp_path):
    _script(tmp_path / "credwatch", "/x/python")
    monkeypatch.chdir(tmp_path)
    assert linux.find_executable("credwatch") == tmp_path / "credwatch"


@pytest.mark.parametrize("argv0", ["/v/lib/credwatch/__main__.py", "/v/lib/credwatch/cli.py"])
def test_python_m_invocation_refused(argv0):
    with pytest.raises(InstallError, match="run install via the installed `credwatch` command"):
        linux.find_executable(argv0)


def test_which_fallback_requires_own_interpreter(tmp_path):
    prefix = tmp_path / "venv"
    good = _script(tmp_path / "bin/credwatch", f"{prefix}/bin/python")
    found = linux.find_executable("credwatch", which=lambda n: str(good), prefix=prefix)
    assert found == good


def test_which_fallback_foreign_interpreter_refused(tmp_path):
    other = _script(tmp_path / "bin/credwatch", "/usr/bin/python3")
    with pytest.raises(InstallError, match="does not run this credwatch"):
        linux.find_executable("credwatch", which=lambda n: str(other), prefix=tmp_path / "venv")


def test_which_fallback_without_shebang_refused(tmp_path):
    other = tmp_path / "credwatch"
    other.write_bytes(b"\x7fELF")
    with pytest.raises(InstallError, match="does not run this credwatch"):
        linux.find_executable("credwatch", which=lambda n: str(other), prefix=tmp_path)


def test_no_entry_point_found_refused():
    with pytest.raises(InstallError, match="cannot locate"):
        linux.find_executable("credwatch", which=lambda n: None)


# --- bootstrap ------------------------------------------------------------------


def test_bootstrap_config_from_template_only_if_missing(tmp_path):
    dest = tmp_path / "config.yaml"
    assert common.bootstrap_config(dest, owner_uid=os.geteuid()) is True
    assert dest.read_text() == (REPO / "config.example.yaml").read_text()
    assert _mode(dest) == 0o600
    dest.write_text("mine: 1\n")
    assert common.bootstrap_config(dest, owner_uid=os.geteuid()) is False
    assert dest.read_text() == "mine: 1\n"


def test_refuses_user_owned_config(tmp_path):
    dest = tmp_path / "config.yaml"
    dest.write_text("x: 1\n")
    with pytest.raises(InstallError, match="owned by uid"):
        common.bootstrap_config(dest, owner_uid=os.geteuid() + 1)


def test_refuses_group_writable_config(tmp_path):
    dest = tmp_path / "config.yaml"
    dest.write_text("x: 1\n")
    os.chmod(dest, 0o664)
    with pytest.raises(InstallError, match="writable"):
        common.bootstrap_config(dest, owner_uid=os.geteuid())


def test_refuses_symlinked_config(tmp_path):
    (tmp_path / "victim").write_text("v")
    dest = tmp_path / "config.yaml"
    dest.symlink_to(tmp_path / "victim")
    with pytest.raises(InstallError, match="symlink"):
        common.bootstrap_config(dest, owner_uid=os.geteuid())
    assert (tmp_path / "victim").read_text() == "v"


def test_refuses_directory_in_place_of_config(tmp_path):
    (tmp_path / "config.yaml").mkdir()
    with pytest.raises(InstallError, match="regular file"):
        common.bootstrap_config(tmp_path / "config.yaml", owner_uid=os.geteuid())


def test_packaged_templates_match_repo_examples():
    for name in ("config.example.yaml", "secrets.env.example"):
        assert common.template_text(name) == (REPO / name).read_text()


# --- assert_root_owned_install --------------------------------------------------


def _fake_stat(overrides):
    def stat_fn(path):
        uid, mode = overrides.get(os.path.normpath(str(path)), (0, 0o40755))
        return SimpleNamespace(st_uid=uid, st_gid=0, st_mode=mode)
    return stat_fn


def _check(stat_fn, tmp_path):
    common.assert_root_owned_install(
        Path("/opt/pipx/bin/credwatch"), Path("/opt/pipx/venvs/credwatch"),
        interpreter=Path("/opt/pipx/venvs/credwatch/bin/python"),
        package_dir=Path("/opt/pipx/venvs/credwatch/lib/credwatch"),
        stat_fn=stat_fn,
    )


def test_root_owned_install_passes(tmp_path):
    _check(_fake_stat({}), tmp_path)


def test_refuses_user_writable_executable(tmp_path):
    stat_fn = _fake_stat({"/opt/pipx/bin/credwatch": (1000, 0o100755)})
    with pytest.raises(InstallError, match="sudo pipx install --global"):
        _check(stat_fn, tmp_path)


def test_refuses_other_writable_parent_dir(tmp_path):
    stat_fn = _fake_stat({"/opt": (0, 0o40777)})
    with pytest.raises(InstallError, match="/opt"):
        _check(stat_fn, tmp_path)


def test_refuses_user_owned_interpreter(tmp_path):
    stat_fn = _fake_stat({"/opt/pipx/venvs/credwatch/bin/python": (1000, 0o100755)})
    with pytest.raises(InstallError, match="python"):
        _check(stat_fn, tmp_path)


def test_refuses_user_owned_package_dir(tmp_path):
    stat_fn = _fake_stat({"/opt/pipx/venvs/credwatch/lib/credwatch": (1000, 0o40755)})
    with pytest.raises(InstallError, match="lib/credwatch"):
        _check(stat_fn, tmp_path)


def test_checks_symlink_target_of_executable(tmp_path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "credwatch").write_text("#!")
    link = tmp_path / "credwatch"
    link.symlink_to(real_dir / "credwatch")
    bad = os.path.normpath(str(real_dir))
    stat_fn = _fake_stat({bad: (1000, 0o40755)})
    with pytest.raises(InstallError, match="real"):
        common.assert_root_owned_install(
            link, Path("/opt/p"), interpreter=Path("/usr/bin/python3"),
            package_dir=Path("/opt/p/lib"), stat_fn=stat_fn,
        )


def test_installer_package_exports():
    assert installer.run_install is run_install
