import logging
import os
import random
import string
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from credwatch.backends.linux_audit import AuditAssembler, parse_record

FIXTURES = Path(__file__).parent / "fixtures"


def lines(name):
    return (FIXTURES / name).read_text().rstrip("\n").split("\n")  # not splitlines(): it splits on 0x1d


def run(assembler, ls, now=0.0):
    out = []
    for line in ls:
        out.extend(assembler.feed(line, now))
    return out


def test_enriched_line_parses_fields_before_gs():
    line = next(l for l in lines("audit_enriched.log") if l.startswith("type=SYSCALL"))
    rec = parse_record(line)
    assert rec is not None
    assert rec.type == "SYSCALL"
    assert rec.serial == "4567"
    assert rec.epoch == 1731000000.123
    assert rec.fields["comm"] == "cat"
    assert rec.fields["exe"] == "/usr/bin/cat"
    assert rec.fields["key"] == "credwatch"
    assert rec.fields["pid"] == "5678"
    assert "ARCH" not in rec.fields and "AUID" not in rec.fields


def test_hex_name_decoded_to_path_with_space():
    line = next(l for l in lines("audit_hex.log") if l.startswith("type=PATH"))
    rec = parse_record(line)
    assert rec.fields["name"] == "/home/u/my env/.env"


def test_null_value_becomes_none():
    line = next(l for l in lines("audit_enriched.log") if "key=(null)" in l)
    assert parse_record(line).fields["key"] is None


def test_invalid_hex_utf8_never_raises():
    rec = parse_record('type=PATH msg=audit(1.0:1): item=0 name=FF00 nametype=NORMAL')
    assert rec is not None
    assert isinstance(rec.fields["name"], str)


def test_control_chars_in_hex_name_preserved():
    rec = parse_record('type=PATH msg=audit(1.0:1): item=0 name=2F612F620A63 nametype=NORMAL')
    assert rec.fields["name"] == "/a/b\nc"


def test_group_emits_one_event_per_non_parent_path():
    events = run(AuditAssembler(), lines("audit_enriched.log"))
    assert [e.path for e in events] == [
        "/home/u/.aws/credentials",
        "/home/u/.ssh/id_new",
    ]
    first = events[0]
    assert first.timestamp == datetime.fromtimestamp(1731000000.123, tz=timezone.utc)
    assert (first.pid, first.ppid) == (5678, 1234)
    assert first.exe == "/usr/bin/cat" and first.comm == "cat"
    assert first.success is True
    assert first.backend == "linux-audit"


def test_relative_name_joined_with_cwd():
    events = run(AuditAssembler(), lines("audit_enriched.log"))
    assert events[1].path == "/home/u/.ssh/id_new"


def test_raw_is_group_lines_joined():
    events = run(AuditAssembler(), lines("audit_enriched.log"))
    raw = events[0].raw.split("\n")
    assert raw[0].startswith("type=SYSCALL") and raw[-1].startswith("type=EOE")
    assert len(raw) == 5


def test_other_keys_ignored():
    events = run(AuditAssembler(), lines("audit_enriched.log"))
    assert all(e.path != "/etc/hosts" and e.path != "/home/u" for e in events)


def test_custom_key_selects_other_group():
    events = run(AuditAssembler(key="other-key"), lines("audit_enriched.log"))
    assert [e.path for e in events] == ["/etc/hosts"]


def test_failed_syscall_sets_success_false():
    ls = [l.replace("success=yes", "success=no") for l in lines("audit_enriched.log")[2:8]]
    events = run(AuditAssembler(), ls)
    assert events[0].success is False


def test_group_without_eoe_flushed_after_timeout():
    ls = [l for l in lines("audit_enriched.log")[2:7] if not l.startswith("type=EOE")]
    a = AuditAssembler(flush_after=2.0)
    assert run(a, ls, now=100.0) == []
    flushed = a.feed("garbage", now=102.5)
    assert [e.path for e in flushed] == ["/home/u/.aws/credentials"]
    assert a.feed("garbage", now=110.0) == []


def test_interleaved_serials_assembled_independently():
    ls = lines("audit_enriched.log")
    g1 = [l for l in ls if "(1731000000.123:4567)" in l]
    g2 = [l for l in ls if "(1731000001.456:4568)" in l]
    mixed = [x for pair in zip(g1, g2) for x in pair] + g1[len(g2):] + g2[len(g1):]
    events = run(AuditAssembler(), mixed)
    assert sorted(e.path for e in events) == [
        "/home/u/.aws/credentials",
        "/home/u/.ssh/id_new",
    ]


def test_hex_fixture_yields_event_with_space_path():
    events = run(AuditAssembler(), lines("audit_hex.log"))
    assert [e.path for e in events] == ["/home/u/my env/.env"]


def test_newline_path_reported_faithfully():
    ls = [
        'type=SYSCALL msg=audit(5.0:7): success=yes pid=1 ppid=2 comm="x" exe="/x" key="credwatch"',
        'type=PATH msg=audit(5.0:7): item=0 name=2F612F620A63 nametype=NORMAL',
        'type=EOE msg=audit(5.0:7): ',
    ]
    events = run(AuditAssembler(), ls)
    assert [e.path for e in events] == ["/a/b\nc"]


def test_multiple_keys_joined_by_soh_match():
    ls = [
        'type=SYSCALL msg=audit(5.0:7): success=yes pid=1 ppid=2 comm="x" exe="/x" key=637265647761746368016F74686572',
        'type=PATH msg=audit(5.0:7): item=0 name="/p" nametype=NORMAL',
        'type=EOE msg=audit(5.0:7): ',
    ]
    assert [e.path for e in run(AuditAssembler(), ls)] == ["/p"]


def test_garbage_line_returns_none_and_does_not_raise():
    for junk in ["", "garbage", "type=SYSCALL", "type=X msg=audit(abc:1): a=b", "\x1d\x1d", "# comment"]:
        assert parse_record(junk) is None
    assert AuditAssembler().feed("garbage", 0.0) == []


@pytest.mark.parametrize("epoch", ["9" * 20, "9" * 400, "99999999999999"])
def test_huge_epoch_does_not_raise(epoch):
    line = f"type=SYSCALL msg=audit({epoch}:1): success=yes key=\"credwatch\""
    assert parse_record(line) is None
    assert AuditAssembler().feed(line, 0.0) == []


def test_feed_never_raises_on_fuzzed_lines():
    rng = random.Random(1234)
    alphabet = string.printable + "\x1d\x00\x01\x7f"
    a = AuditAssembler()
    for i in range(400):
        junk = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 80)))
        prefix = rng.choice(["", "type=PATH msg=audit(1.5:%d): " % (i % 7), "type=EOE msg=audit(%d:3): " % rng.randint(0, 10**9)])
        a.feed(prefix + junk, float(i))


def test_build_failure_drops_group_with_warning(caplog, monkeypatch):
    import credwatch.backends.linux_audit as mod

    def boom(group, key):
        raise OverflowError("x")

    monkeypatch.setattr(mod, "_build_events", boom)
    with caplog.at_level(logging.WARNING):
        assert run(AuditAssembler(), lines("audit_enriched.log")) == []
    assert "serial=4567" in caplog.text


def test_null_path_name_logged_at_debug(caplog):
    ls = [
        'type=SYSCALL msg=audit(5.0:7): success=yes pid=1 ppid=2 key="credwatch"',
        'type=PATH msg=audit(5.0:7): item=0 name=(null) nametype=UNKNOWN',
        'type=EOE msg=audit(5.0:7): ',
    ]
    with caplog.at_level(logging.DEBUG):
        assert run(AuditAssembler(), ls) == []
    assert "null name" in caplog.text


def test_group_without_syscall_logged_at_debug(caplog):
    ls = ['type=PATH msg=audit(5.0:7): item=0 name="/p"', 'type=EOE msg=audit(5.0:7): ']
    with caplog.at_level(logging.DEBUG):
        assert run(AuditAssembler(), ls) == []
    assert "no SYSCALL" in caplog.text


def test_long_token_line_is_fast():
    line = "type=PATH msg=audit(1.0:1): " + "a" * 20000
    start = time.perf_counter()
    parse_record(line)
    assert time.perf_counter() - start < 0.05


def test_empty_tick_flushes_stale_group():
    ls = [l for l in lines("audit_enriched.log")[2:7] if not l.startswith("type=EOE")]
    a = AuditAssembler(flush_after=2.0)
    run(a, ls, now=10.0)
    assert [e.path for e in a.feed("", 12.0)] == ["/home/u/.aws/credentials"]


def test_path_inode_and_dev_parsed():
    events = run(AuditAssembler(), lines("audit_enriched.log"))
    assert events[0].inode == 131077
    assert events[0].dev == os.makedev(0xFD, 0x01)
    assert events[1].inode == 131099


def _single_path_event(path_fields):
    ls = [
        'type=SYSCALL msg=audit(5.0:7): success=yes pid=1 ppid=2 key="credwatch"',
        f'type=PATH msg=audit(5.0:7): item=0 name="/p" {path_fields}',
        'type=EOE msg=audit(5.0:7): ',
    ]
    return run(AuditAssembler(), ls)[0]


@pytest.mark.parametrize("fields", ["dev=zz:01", "dev=fd", "dev=:", "dev=fd:", "dev=-1:2", "", "dev=ffffffffffffffffffff:0"])
def test_malformed_dev_is_none(fields):
    assert _single_path_event(fields + " inode=abc").dev is None
    assert _single_path_event(fields).inode is None


# --- parent-directory identity (short-lived files, R54) ---------------------------------

def _group(*paths, serial="9"):
    return [
        f'type=SYSCALL msg=audit(6.0:{serial}): success=yes pid=1 ppid=2 comm="gpg" '
        f'exe="/usr/bin/gpg" key="credwatch"',
        *(f"type=PATH msg=audit(6.0:{serial}): item={i} {p}" for i, p in enumerate(paths)),
        f"type=EOE msg=audit(6.0:{serial}): ",
    ]


def test_fixture_create_event_carries_parent_identity_and_nametype():
    events = run(AuditAssembler(), lines("audit_enriched.log"))
    created = next(e for e in events if e.path == "/home/u/.ssh/id_new")
    assert created.nametype == "CREATE"
    assert (created.parent_inode, created.parent_dev) == (131080, os.makedev(0xFD, 0x01))


def test_normal_open_has_no_parent_identity():
    events = run(AuditAssembler(), lines("audit_enriched.log"))
    read = next(e for e in events if e.path == "/home/u/.aws/credentials")
    assert read.nametype == "NORMAL"
    assert read.parent_inode is None and read.parent_dev is None


def test_rename_within_one_dir_shares_parent_identity():
    ls = _group(
        'name="/h/.gnupg/" inode=50 dev=fd:01 nametype=PARENT',
        'name="/h/.gnupg/" inode=50 dev=fd:01 nametype=PARENT',
        'name="/h/.gnupg/pubring.kbx.tmp" inode=60 dev=fd:01 nametype=DELETE',
        'name="/h/.gnupg/pubring.kbx" inode=61 dev=fd:01 nametype=CREATE',
    )
    events = run(AuditAssembler(), ls)
    assert [(e.nametype, e.parent_inode) for e in events] == [("DELETE", 50), ("CREATE", 50)]


def test_parents_in_different_dirs_give_no_parent_identity():
    ls = _group(
        'name="/a/" inode=50 dev=fd:01 nametype=PARENT',
        'name="/b/" inode=51 dev=fd:01 nametype=PARENT',
        'name="/a/x" inode=60 dev=fd:01 nametype=DELETE',
        'name="/b/x" inode=60 dev=fd:01 nametype=CREATE',
    )
    events = run(AuditAssembler(), ls)
    assert [(e.parent_inode, e.parent_dev) for e in events] == [(None, None), (None, None)]


def test_parent_with_unparseable_dev_gives_no_parent_identity():
    ls = _group(
        'name="/a/" inode=50 dev=zz nametype=PARENT',
        'name="/a/x" inode=60 dev=fd:01 nametype=CREATE',
    )
    (event,) = run(AuditAssembler(), ls)
    assert event.parent_inode is None and event.parent_dev is None


# --- O_PATH opens (location-only handles, R55) -------------------------------------------

def _open_group(arch="c000003e", syscall="257", args="a0=ffffff9c a1=7ffd1000 a2=280000 a3=0"):
    return [
        f'type=SYSCALL msg=audit(7.0:11): arch={arch} syscall={syscall} success=yes {args} '
        f'pid=1 ppid=2 comm="x" exe="/x" key="credwatch"',
        'type=PATH msg=audit(7.0:11): item=0 name="/h/.ssh" inode=5 dev=fd:01 nametype=NORMAL',
        "type=EOE msg=audit(7.0:11): ",
    ]


@pytest.mark.parametrize("arch,syscall,args", [
    ("c000003e", "257", "a0=ffffff9c a1=7ffd1000 a2=280000 a3=0"),   # x86_64 openat
    ("c000003e", "2", "a0=7ffd1000 a1=200000 a2=0 a3=0"),            # x86_64 open
    ("c00000b7", "56", "a0=ffffff9c a1=7ffd1000 a2=200000 a3=0"),    # aarch64 openat
])
def test_o_path_open_marks_event_path_only(arch, syscall, args):
    (event,) = run(AuditAssembler(), _open_group(arch, syscall, args))
    assert event.path_only is True


@pytest.mark.parametrize("arch,syscall,args", [
    ("c000003e", "257", "a0=ffffff9c a1=7ffd1000 a2=80000 a3=0"),    # O_RDONLY|O_CLOEXEC
    ("c000003e", "2", "a0=7ffd1000 a1=0 a2=200000 a3=0"),            # flag in the wrong arg
    ("c000003e", "437", "a0=ffffff9c a1=7ffd1000 a2=7ffd2000 a3=18"),  # openat2: flags hidden
    ("40000003", "295", "a0=ffffff9c a1=7ffd1000 a2=200000 a3=0"),   # i386: unknown table
    ("c000003e", "257", "a0=ffffff9c a1=7ffd1000 a2=zz a3=0"),       # unparseable flags
    ("c000003e", "257", "a0=ffffff9c a1=7ffd1000 a3=0"),             # flags missing
])
def test_non_o_path_or_unknown_open_is_judged_normally(arch, syscall, args):
    (event,) = run(AuditAssembler(), _open_group(arch, syscall, args))
    assert event.path_only is False


def test_fixture_events_are_not_path_only():
    assert not any(e.path_only for e in run(AuditAssembler(), lines("audit_enriched.log")))
