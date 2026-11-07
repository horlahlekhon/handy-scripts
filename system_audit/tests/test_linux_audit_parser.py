from datetime import datetime, timezone
from pathlib import Path

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
