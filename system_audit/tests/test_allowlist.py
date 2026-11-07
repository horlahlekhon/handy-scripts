from collections import namedtuple
from datetime import datetime, timezone

from pathlib import Path

from credwatch.allowlist import Allowlist
from credwatch.config import AllowRule
from credwatch.models import FileAccessEvent, Verdict

HOME = "/home/u"


def make_event(path, exe=None, comm=None):
    return FileAccessEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        path=path, pid=1, ppid=0, exe=exe, comm=comm,
        success=True, backend="test", raw="",
    )


St = namedtuple("St", "st_uid st_gid st_mode")
ROOT_OK = St(0, 0, 0o40755)


def fake_stat(overrides=None):
    overrides = overrides or {}
    calls = []

    def stat(p):
        calls.append(p)
        return overrides.get(p, ROOT_OK)

    stat.calls = calls
    return stat


TRUSTED = ("/usr/bin", "/usr/local/bin")
SSH_RULE = AllowRule(f"{HOME}/.ssh/**", ("ssh", "ssh-*"))


def test_ssh_read_by_ssh_allowed():
    al = Allowlist((SSH_RULE,), TRUSTED, fake_stat())
    v = al.check(make_event(f"{HOME}/.ssh/id_rsa", exe="/usr/bin/ssh", comm="ssh"))
    assert v == Verdict(True, SSH_RULE.path_pattern)


def test_ssh_read_by_curl_flagged():
    al = Allowlist((SSH_RULE,), TRUSTED, fake_stat())
    v = al.check(make_event(f"{HOME}/.ssh/id_rsa", exe="/usr/bin/curl", comm="curl"))
    assert v == Verdict(False, None)


def test_python3_glob_matches_python3_13():
    al = Allowlist((AllowRule(f"{HOME}/.aws/*", ("python3*",)),), TRUSTED, fake_stat())
    v = al.check(make_event(f"{HOME}/.aws/credentials", exe="/usr/bin/python3.13"))
    assert v.allowed


def test_double_star_matches_directory_itself():
    al = Allowlist((SSH_RULE,), TRUSTED, fake_stat())
    assert al.check(make_event(f"{HOME}/.ssh", exe="/usr/bin/ssh")).allowed


def test_double_star_does_not_match_sibling_prefix():
    al = Allowlist((SSH_RULE,), TRUSTED, fake_stat())
    assert not al.check(make_event(f"{HOME}/.ssh-evil/x", exe="/usr/bin/ssh")).allowed


def test_exe_none_always_flagged():
    al = Allowlist((SSH_RULE,), TRUSTED, fake_stat())
    v = al.check(make_event(f"{HOME}/.ssh/id_rsa", exe=None, comm="ssh"))
    assert v == Verdict(False, None)


def test_spoofed_comm_ignored_when_exe_known():
    al = Allowlist((SSH_RULE,), TRUSTED, fake_stat())
    v = al.check(make_event(f"{HOME}/.ssh/id_rsa", exe="/usr/bin/curl", comm="ssh"))
    assert v == Verdict(False, None)


def test_missing_exe_and_comm_is_flagged():
    al = Allowlist((SSH_RULE,), TRUSTED, fake_stat())
    assert al.check(make_event(f"{HOME}/.ssh/id_rsa")) == Verdict(False, None)


def test_rules_union():
    rules = (SSH_RULE, AllowRule(f"{HOME}/.ssh/**", ("rsync",)))
    al = Allowlist(rules, TRUSTED, fake_stat())
    assert al.check(make_event(f"{HOME}/.ssh/k", exe="/usr/bin/rsync")).allowed


def test_basename_match_outside_trusted_dir_flagged():
    al = Allowlist((SSH_RULE,), TRUSTED, fake_stat())
    v = al.check(make_event(f"{HOME}/.ssh/id_rsa", exe=f"{HOME}/.cache/x/ssh"))
    assert v == Verdict(False, None)


def test_absolute_pattern_matches_user_tool():
    rule = AllowRule(f"{HOME}/.aws/**", (f"{HOME}/.local/bin/aws",))
    al = Allowlist((rule,), TRUSTED, fake_stat())
    assert al.check(make_event(f"{HOME}/.aws/credentials", exe=f"{HOME}/.local/bin/aws")).allowed
    assert not al.check(make_event(f"{HOME}/.aws/credentials", exe=f"{HOME}/.cache/aws")).allowed


def test_trusted_dir_prefix_is_segment_aware():
    al = Allowlist((SSH_RULE,), TRUSTED, fake_stat())
    assert not al.check(make_event(f"{HOME}/.ssh/k", exe="/usr/binx/ssh")).allowed
    assert not al.check(make_event(f"{HOME}/.ssh/k", exe="/usr/bin/../../tmp/ssh")).allowed


def test_dotdot_path_normalized():
    aws = Allowlist((AllowRule(f"{HOME}/.aws/**", ("ssh",)),), TRUSTED, fake_stat())
    ssh = Allowlist((SSH_RULE,), TRUSTED, fake_stat())
    ev = make_event(f"{HOME}/.ssh/../.aws/credentials", exe="/usr/bin/ssh")
    assert aws.check(ev).allowed
    assert not ssh.check(ev).allowed


def test_single_star_does_not_cross_slash():
    al = Allowlist((AllowRule(f"{HOME}/.aws/*", ("ssh",)),), TRUSTED, fake_stat())
    assert al.check(make_event(f"{HOME}/.aws/credentials", exe="/usr/bin/ssh")).allowed
    assert not al.check(make_event(f"{HOME}/.aws/a/b", exe="/usr/bin/ssh")).allowed


def _ssh_check(stat_fn, exe="/usr/bin/ssh", os_name="linux"):
    al = Allowlist((SSH_RULE,), TRUSTED, stat_fn, os_name)
    return al.check(make_event(f"{HOME}/.ssh/id_rsa", exe=exe))


def test_basename_in_group_writable_trusted_dir_flagged():
    st = fake_stat({"/usr/bin": St(0, 1000, 0o40775)})
    assert not _ssh_check(st).allowed


def test_basename_in_user_owned_trusted_dir_flagged():
    st = fake_stat({"/usr": St(1000, 1000, 0o40755)})
    assert not _ssh_check(st).allowed


def test_other_writable_ancestor_flagged_even_for_root_group():
    st = fake_stat({"/": St(0, 0, 0o40777)})
    assert not _ssh_check(st).allowed


def test_group_writable_root_group_allowed():
    st = fake_stat({"/usr/bin": St(0, 0, 0o40775)})
    assert _ssh_check(st).allowed


def test_group_writable_wheel_allowed_on_darwin(monkeypatch):
    import grp
    monkeypatch.setattr(grp, "getgrnam", lambda n: type("G", (), {"gr_gid": 80})())
    st = fake_stat({"/usr/bin": St(0, 80, 0o40775)})
    assert _ssh_check(st, os_name="darwin").allowed
    assert not _ssh_check(st, os_name="linux").allowed


def test_wheel_lookup_failure_not_allowed(monkeypatch):
    import grp

    def boom(n):
        raise KeyError(n)

    monkeypatch.setattr(grp, "getgrnam", boom)
    st = fake_stat({"/usr/bin": St(0, 80, 0o40775)})
    assert not _ssh_check(st, os_name="darwin").allowed


def test_stat_failure_flagged():
    def stat(p):
        raise FileNotFoundError(p)

    assert not _ssh_check(stat).allowed


def test_root_owned_chain_allows_basename():
    st = fake_stat()
    assert _ssh_check(st).allowed
    assert st.calls == ["/usr/bin", "/usr", "/"]


def test_dir_check_cached():
    st = fake_stat()
    al = Allowlist((SSH_RULE,), TRUSTED, st)
    ev = make_event(f"{HOME}/.ssh/id_rsa", exe="/usr/bin/ssh")
    assert al.check(ev).allowed and al.check(ev).allowed
    assert st.calls.count("/usr/bin") == 1


def test_trusted_dirs_accepts_path_objects():
    al = Allowlist((SSH_RULE,), (Path("/usr/bin"),), fake_stat())
    assert al.check(make_event(f"{HOME}/.ssh/k", exe="/usr/bin/ssh")).allowed


def test_rule_patterns_normalized_at_construction():
    rule = AllowRule(f"{HOME}/x/../.ssh//**", ("ssh",))
    al = Allowlist((rule,), TRUSTED, fake_stat())
    assert al.rules[0].path_pattern == f"{HOME}/.ssh/**"
    assert al.check(make_event(f"{HOME}/.ssh/k", exe="/usr/bin/ssh")).allowed
