from datetime import datetime, timezone

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


TRUSTED = ("/usr/bin", "/usr/local/bin")
SSH_RULE = AllowRule(f"{HOME}/.ssh/**", ("ssh", "ssh-*"))


def test_ssh_read_by_ssh_allowed():
    al = Allowlist((SSH_RULE,), TRUSTED)
    v = al.check(make_event(f"{HOME}/.ssh/id_rsa", exe="/usr/bin/ssh", comm="ssh"))
    assert v == Verdict(True, SSH_RULE.path_pattern)


def test_ssh_read_by_curl_flagged():
    al = Allowlist((SSH_RULE,), TRUSTED)
    v = al.check(make_event(f"{HOME}/.ssh/id_rsa", exe="/usr/bin/curl", comm="curl"))
    assert v == Verdict(False, None)


def test_python3_glob_matches_python3_13():
    al = Allowlist((AllowRule(f"{HOME}/.aws/*", ("python3*",)),), TRUSTED)
    v = al.check(make_event(f"{HOME}/.aws/credentials", exe="/usr/bin/python3.13"))
    assert v.allowed


def test_double_star_matches_directory_itself():
    al = Allowlist((SSH_RULE,), TRUSTED)
    assert al.check(make_event(f"{HOME}/.ssh", exe="/usr/bin/ssh")).allowed


def test_double_star_does_not_match_sibling_prefix():
    al = Allowlist((SSH_RULE,), TRUSTED)
    assert not al.check(make_event(f"{HOME}/.ssh-evil/x", exe="/usr/bin/ssh")).allowed


def test_exe_none_always_flagged():
    al = Allowlist((SSH_RULE,), TRUSTED)
    v = al.check(make_event(f"{HOME}/.ssh/id_rsa", exe=None, comm="ssh"))
    assert v == Verdict(False, None)


def test_spoofed_comm_ignored_when_exe_known():
    al = Allowlist((SSH_RULE,), TRUSTED)
    v = al.check(make_event(f"{HOME}/.ssh/id_rsa", exe="/usr/bin/curl", comm="ssh"))
    assert v == Verdict(False, None)


def test_missing_exe_and_comm_is_flagged():
    al = Allowlist((SSH_RULE,), TRUSTED)
    assert al.check(make_event(f"{HOME}/.ssh/id_rsa")) == Verdict(False, None)


def test_rules_union():
    rules = (SSH_RULE, AllowRule(f"{HOME}/.ssh/**", ("rsync",)))
    al = Allowlist(rules, TRUSTED)
    assert al.check(make_event(f"{HOME}/.ssh/k", exe="/usr/bin/rsync")).allowed


def test_basename_match_outside_trusted_dir_flagged():
    al = Allowlist((SSH_RULE,), TRUSTED)
    v = al.check(make_event(f"{HOME}/.ssh/id_rsa", exe=f"{HOME}/.cache/x/ssh"))
    assert v == Verdict(False, None)


def test_absolute_pattern_matches_user_tool():
    rule = AllowRule(f"{HOME}/.aws/**", (f"{HOME}/.local/bin/aws",))
    al = Allowlist((rule,), TRUSTED)
    assert al.check(make_event(f"{HOME}/.aws/credentials", exe=f"{HOME}/.local/bin/aws")).allowed
    assert not al.check(make_event(f"{HOME}/.aws/credentials", exe=f"{HOME}/.cache/aws")).allowed


def test_trusted_dir_prefix_is_segment_aware():
    al = Allowlist((SSH_RULE,), TRUSTED)
    assert not al.check(make_event(f"{HOME}/.ssh/k", exe="/usr/binx/ssh")).allowed
    assert not al.check(make_event(f"{HOME}/.ssh/k", exe="/usr/bin/../../tmp/ssh")).allowed


def test_dotdot_path_normalized():
    aws = Allowlist((AllowRule(f"{HOME}/.aws/**", ("ssh",)),), TRUSTED)
    ssh = Allowlist((SSH_RULE,), TRUSTED)
    ev = make_event(f"{HOME}/.ssh/../.aws/credentials", exe="/usr/bin/ssh")
    assert aws.check(ev).allowed
    assert not ssh.check(ev).allowed


def test_single_star_does_not_cross_slash():
    al = Allowlist((AllowRule(f"{HOME}/.aws/*", ("ssh",)),), TRUSTED)
    assert al.check(make_event(f"{HOME}/.aws/credentials", exe="/usr/bin/ssh")).allowed
    assert not al.check(make_event(f"{HOME}/.aws/a/b", exe="/usr/bin/ssh")).allowed
