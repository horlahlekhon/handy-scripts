"""fs_usage line parsing: strict/loose path extraction, normalization, attribution."""
import collections
import threading
import unicodedata
from datetime import date, datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from credwatch.backends.macos_fsusage import UNKNOWN_PROC, FsUsageHit, parse_fs_usage_hits
from credwatch.paths import WatchMatcher
from _fsusage_support import (
    TZ,
    TODAY,
    NOW,
    WATCHED,
    JOSE_NETRC,
    _line,
    matcher,
    _parse,
    _hits,
    _random_lines,
    _covered,
    _TAIL_OK,
    _JCARON,
    _CAFE_NFD,
)


# --- parser -----------------------------------------------------------------------


def test_open_of_watched_path_parsed(matcher):
    line = _line("open              F=3        (R_____)  /Users/alice/.aws/credentials")
    hit = _parse(line, matcher)
    assert hit == FsUsageHit(
        timestamp=datetime(2026, 11, 8, 23, 59, 58, 102100, tzinfo=TZ).astimezone(timezone.utc),
        op="open", path="/Users/alice/.aws/credentials", proc_name="cat", tid=2004211,
        raw=line, errno=None,
    )


def test_unwatched_path_ignored(matcher):
    assert _parse(_line("/Users/alice/Documents/notes.txt"), matcher) is None
    assert _parse(_line("/usr/lib/libSystem.B.dylib"), matcher) is None


def test_sibling_with_watched_prefix_ignored(matcher):
    assert _parse(_line("/Users/alice/.aws/credentials-backup/x"), matcher) is None


def test_fd_only_read_line_ignored(matcher):
    read = _line("read              F=3    B=0x74")
    assert _parse(read, matcher) is None
    assert _parse(_line("close             F=3                 "), matcher) is None


def test_non_access_op_on_watched_path_ignored(matcher):
    assert _parse(_line("stat64                               /Users/alice/.aws"), matcher) is None
    assert _parse(_line("getattrlist"), matcher) is None


@pytest.mark.parametrize(
    "fragment,op,path",
    [
        ("open_nocancel", "open_nocancel", "/Users/alice/.aws/config"),
        ("openat ", "openat", "/Users/alice/.ssh/id_ed25519"),
        ("rename ", "rename", "/Users/alice/.kube/config.tmp"),
        ("unlink ", "unlink", "/Users/alice/.kube/config.lock"),
        ("open_dprotected_np", "open_dprotected_np", "/Users/alice/.docker/config.json"),
    ],
)
def test_relevant_ops_parsed(matcher, fragment, op, path):
    m = WatchMatcher((*WATCHED, Path("/Users/alice/.kube")), case_insensitive=True)
    hit = _parse(_line(fragment), m)
    assert hit is not None and (hit.op, hit.path) == (op, path)


def test_wait_marker_before_process_name(matcher):
    hit = _parse(_line("/Users/alice/.ssh/id_ed25519"), matcher)
    assert (hit.proc_name, hit.tid) == ("ssh", 2004500)


def test_path_with_spaces_and_dotted_process_name(matcher):
    hit = _parse(_line("credwatch/canary"), matcher)
    assert hit.path == "/Library/Application Support/credwatch/canary"
    assert (hit.proc_name, hit.tid) == ("python3.12", 2004800)


def test_process_name_with_spaces(matcher):
    hit = _parse(_line("Google Chrome He"), matcher)
    assert hit.proc_name == "Google Chrome He"


def test_case_insensitive_match_keeps_reported_path(matcher):
    hit = _parse(_line("/Users/alice/.AWS/Credentials"), matcher)
    assert hit is not None and hit.path == "/Users/alice/.AWS/Credentials"


def test_failed_open_records_errno(matcher):
    hit = _parse(_line("/Users/alice/.netrc"), matcher)
    assert hit.errno == 2


def test_midnight_rollover_uses_previous_day(matcher):
    now = datetime(2026, 11, 9, 0, 0, 1, tzinfo=TZ)
    hit = _parse(_line("open_nocancel"), matcher, now=now)  # 23:59:58 seen just after midnight
    assert hit.timestamp == datetime(2026, 11, 8, 23, 59, 58, 110100, tzinfo=TZ).astimezone(
        timezone.utc
    )
    after = _parse(_line("cat.2005400"), matcher, now=now)
    assert after.timestamp.astimezone(TZ).date() == date(2026, 11, 9)


def test_small_clock_skew_keeps_today(matcher):
    now = datetime(2026, 11, 8, 23, 59, 30, tzinfo=TZ)  # line is 28 s "in the future"
    hit = _parse(_line("open_nocancel"), matcher, now=now)
    assert hit.timestamp.astimezone(TZ).date() == TODAY


@pytest.mark.parametrize(
    "line",
    ["", "garbage",
     "23:59:58.1  open  F=3 (R_____)  relative/.netrc  0.1  cat.1",
     "23:59:58.1  open  F=3 (R_____)  /Users/alice/.netrc-old  0.1  noTid",
     "23:59:58.1  stat64  /Users/alice/.netrc  0.1  noTid"],
)
def test_malformed_lines_ignored(matcher, line):
    assert _parse(line, matcher) is None


def test_path_containing_float_token_parsed_from_the_right():
    m = WatchMatcher([Path("/Users/alice/v 1.5 x")], case_insensitive=True)
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/v 1.5 x/creds"
            "      0.000010   cat.4242")
    hit = _parse(line, m)
    assert (hit.path, hit.proc_name, hit.tid) == ("/Users/alice/v 1.5 x/creds", "cat", 4242)


def test_process_name_longer_than_maxcomlen_falls_back_to_unknown(matcher):
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc"
            "      0.000010   averyveryverylongname.4242")
    hit = _parse(line, matcher)
    assert (hit.path, hit.proc_name, hit.tid) == ("/Users/alice/.netrc", "?", None)


def test_watched_line_without_tid_still_flagged(matcher):
    line = "23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc      0.000010   cat"
    (hit,), miss = parse_fs_usage_hits(line, matcher, TODAY, NOW)
    assert (hit.path, hit.proc_name, hit.tid) == ("/Users/alice/.netrc", "?", None)
    assert miss is not None
    bare = "23:59:58.100000  open  F=3  (R_____)  /Users/alice/.ssh/id_rsa"
    assert _parse(bare, matcher).path == "/Users/alice/.ssh/id_rsa"


def test_unparseable_timestamp_on_watched_path_uses_read_time(matcher):
    line = "99:99:99.000000  open  F=3 (R_____)  /Users/alice/.netrc  0.1  cat.1"
    (hit,), miss = parse_fs_usage_hits(line, matcher, TODAY, NOW)
    assert hit.path == "/Users/alice/.netrc" and hit.timestamp == NOW.astimezone(timezone.utc)
    assert miss == "unparseable timestamp; used read time"


def test_float_token_in_process_name_still_flagged(matcher):
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc"
            "   0.000010   a 1.1 b.4242")
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name, h.tid) for h in hits] == [("/Users/alice/.netrc", "?", None)]
    assert miss is not None


def test_name_with_W_and_float_still_flagged(matcher):
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc"
            "   0.000010   x 0.5 W cat.4242")
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [("/Users/alice/.netrc", "?")]
    assert miss is not None


def test_rename_with_watched_source_flagged(matcher):
    line = ("23:59:58.100000  rename  /Users/alice/.netrc /tmp/stolen"
            "      0.000040   mv.4242")
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name, h.op) for h in hits] == [("/Users/alice/.netrc", "?", "rename")]
    assert miss is not None


def test_rename_with_watched_destination_flagged(matcher):
    line = ("23:59:58.100000  renameat  /tmp/evil /Users/alice/.aws/credentials"
            "      0.000040   mv.4242")
    hits, _ = _hits(line, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [("/Users/alice/.aws/credentials", "?")]


def test_rename_between_two_watched_paths_gives_one_hit_each(matcher):
    line = ("23:59:58.100000  rename  /Users/alice/.netrc /Users/alice/.ssh/netrc"
            "      0.000040   mv.4242")
    hits, _ = _hits(line, matcher)
    assert {h.path for h in hits} == {"/Users/alice/.netrc", "/Users/alice/.ssh/netrc"}
    assert all(h.proc_name == "?" for h in hits)


def test_directory_watch_missplit_reports_real_path(matcher):
    # Greedy tail puts "   0.000010   evil" into the path; still "inside" ~/.ssh.
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.ssh/id_rsa"
            "   0.000010   evil 2.5 x.4242")
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [("/Users/alice/.ssh/id_rsa", "?")]
    assert "disagrees" in miss


def test_directory_watch_path_with_spaces_parsed_strictly(matcher):
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.ssh/my key"
            "      0.000010   ssh.4242")
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name, h.tid) for h in hits] == [
        ("/Users/alice/.ssh/my key", "ssh", 4242)
    ]
    assert miss is None


def test_sibling_after_full_parse_is_silently_ignored(matcher):
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc-old"
            "      0.000010   cat.4242")
    assert _hits(line, matcher) == ((), None)


def test_watched_path_inside_longer_path_not_reported(matcher):
    line = ("23:59:58.100000  open  F=3  (R_____)  /private/Users/alice/.netrc"
            "      0.000010   cat.4242")
    assert _hits(line, matcher) == ((), None)


@pytest.mark.parametrize("seed", range(5))
def test_random_attacker_names_never_hide_watched_path(matcher, seed):
    for line, target in _random_lines(seed):
        hits, _ = _hits(line, matcher)
        assert hits, line
        assert all(matcher.matches(h.path) for h in hits), line
        assert _covered(target, [(h.path, h.proc_name) for h in hits]), line
        assert all(h.raw == line for h in hits), line


def test_loose_extension_stops_when_no_longer_watched(matcher):
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc x"
            "      0.000010   cat.42")
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [("/Users/alice/.netrc", "?")]
    assert "disagrees" in miss


@pytest.mark.parametrize("ch", ["ß", "ﬁ", "İ"])
def test_casefold_length_change_in_name_with_clean_tail(matcher, ch):
    # The name changes length under casefold; the folded search must still align.
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc"
            f"      0.000010   stra{ch}e.42")
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name, h.tid) for h in hits] == [("/Users/alice/.netrc", f"stra{ch}e", 42)]
    assert miss is None


@pytest.mark.parametrize("ch", ["ß", "ﬁ", "İ"])
def test_casefold_length_change_with_float_in_name_flagged(matcher, ch):
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc"
            f"      0.000010   a 1.1 stra{ch}e.42")
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name, h.tid) for h in hits] == [("/Users/alice/.netrc", "?", None)]
    assert miss is not None


@pytest.mark.parametrize("ch", ["ß", "ﬁ", "İ"])
def test_casefold_length_change_dir_watch_not_attributed(matcher, ch):
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.ssh/id_rsa"
            f"      0.000010   {ch} 2.5 ssh.42")
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name, h.tid) for h in hits] == [("/Users/alice/.ssh/id_rsa", "?", None)]
    assert "disagrees" in miss


@pytest.mark.parametrize("ch", ["ß", "ﬁ", "İ"])
def test_casefold_length_change_without_tid_flagged(matcher, ch):
    line = f"23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc      0.000010   {ch}x"
    hits, _ = _hits(line, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [("/Users/alice/.netrc", "?")]


def test_non_ascii_before_path_keeps_offsets(matcher):
    # Folded text is longer than the original before the path: offsets must map back.
    line = ("23:59:58.100000  open  F=3 ßßﬁİ (R_____)  /USERS/alice/.NETRC"
            "      0.000010   cat.42")
    hits, _ = _hits(line, matcher)
    assert [h.path for h in hits] == ["/USERS/alice/.NETRC"]


@pytest.mark.parametrize("printed,expected", [
    ("/Users/alice/.aws/./credentials", "/Users/alice/.aws/credentials"),
    ("//Users/alice/.netrc", "/Users/alice/.netrc"),
    ("/Users/alice//.ssh/id_rsa", "/Users/alice/.ssh/id_rsa"),
])
def test_path_variants_normalized_and_matched(matcher, printed, expected):
    line = f"23:59:58.100000  open  F=3  (R_____)  {printed}      0.000010   cat.42"
    hits, _ = _hits(line, matcher)
    assert [h.path for h in hits] == [expected]


def test_errno_bracket_without_space_before_path(matcher):
    line = "23:59:58.100000  open  [  2]/Users/alice/.netrc      0.000010   cat.42"
    hits, _ = _hits(line, matcher)
    assert [(h.path, h.errno) for h in hits] == [("/Users/alice/.netrc", 2)]


def test_watched_path_glued_after_mode_found_by_needle(matcher):
    line = "23:59:58.100000  open  F=3  (R_____)/Users/alice/.netrc      0.000010   cat.42"
    hits, _ = _hits(line, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [("/Users/alice/.netrc", "?")]


def test_stderr_closed_during_teardown_is_not_a_warning(caplog):
    from credwatch.backends.macos_fsusage import _drain_stderr

    class Closed:
        def __iter__(self):
            raise ValueError("I/O operation on closed file")

    done = threading.Event()
    done.set()
    _drain_stderr(SimpleNamespace(stderr=Closed()), collections.deque(), done)
    assert "could not read" not in caplog.text
    _drain_stderr(SimpleNamespace(stderr=Closed()), collections.deque(),
                  threading.Event())
    assert "could not read fs_usage stderr" in caplog.text


def test_case_sensitive_matcher_needle_search():
    m = WatchMatcher([Path("/Users/alice/.netrc")])
    glued = "23:59:58.100000  open  F=3  (R_____)/Users/alice/.netrc      0.000010   cat.42"
    assert [h.path for h in _hits(glued, m)[0]] == ["/Users/alice/.netrc"]
    other_case = "23:59:58.100000  open  F=3  (R_____)/USERS/alice/.netrc      0.000010   cat.42"
    assert _hits(other_case, m) == ((), None)


def test_nfd_line_matches_nfc_watched_path(matcher):
    nfd = unicodedata.normalize("NFD", JOSE_NETRC)
    line = f"23:59:58.100000  open  F=3  (R_____)  {nfd}{_TAIL_OK}"
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name, h.tid) for h in hits] == [(JOSE_NETRC, "cat", 42)]
    assert hits[0].raw == line
    assert miss is None


def test_errno_bracket_glued_path_parsed_strictly(matcher):
    line = f"23:59:58.100000  open  [  2]/Users/alice/.netrc{_TAIL_OK}"
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name, h.tid, h.errno) for h in hits] == [
        ("/Users/alice/.netrc", "cat", 42, 2)
    ]
    assert miss is None


def test_single_space_before_elapsed_is_ambiguous_under_watched_dir(matcher):
    """Documented limit (runbook): safety relies on >= 2 spaces before the elapsed column.

    With one space, a process named `1.5 ssh` reading ~/.ssh/id cannot be told apart
    from `ssh` reading a file named `id 0.000010`, so it is attributed. With two
    spaces the split disagrees with the watched-path search and is flagged.
    """
    one = "23:59:58.100000  open  F=3  (R_____)  /Users/alice/.ssh/id 0.000010   1.5 ssh.42"
    hits, _ = _hits(one, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [("/Users/alice/.ssh/id 0.000010", "ssh")]
    two = "23:59:58.100000  open  F=3  (R_____)  /Users/alice/.ssh/id  0.000010  1.5 ssh.42"
    hits, miss = _hits(two, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [("/Users/alice/.ssh/id", "?")]
    assert "disagrees" in miss


def test_dotdot_fallback_keeps_watched_path_spelling():
    m = WatchMatcher([Path("/Users/Alice/.NetRC")], case_insensitive=True)
    line = f"23:59:58.100000  unlink  /Users/alice/x  y/../.netrc{_TAIL_OK}"
    hits, _ = _hits(line, m)
    assert [(h.path, h.op) for h in hits] == [("/Users/Alice/.NetRC", "unlink")]


def test_dotdot_without_watched_component_is_ignored(matcher):
    line = f"23:59:58.100000  open  F=3  (R_____)  /Users/alice/x  y/../notes.txt{_TAIL_OK}"
    assert _hits(line, matcher) == ((), None)


def test_dotdot_fallback_only_when_nothing_else_found(matcher):
    line = f"23:59:58.100000  open  F=3  (R_____)  /Users/alice/x/../.netrc{_TAIL_OK}"
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [("/Users/alice/.netrc", "cat")]
    assert miss is None


@pytest.mark.parametrize("printed", [
    _JCARON,
    unicodedata.normalize("NFD", _JCARON),
    "/USERS/J̌ANE/.NETRC",  # no precomposed capital: stays decomposed under NFC
])
def test_needle_search_finds_jcaron_in_glued_layout(printed):
    m = WatchMatcher([Path(_JCARON)], case_insensitive=True)
    line = f"23:59:58.100000  open  F=3  (R_____){printed}{_TAIL_OK}"
    hits, _ = _hits(line, m)
    assert [(h.path, h.proc_name) for h in hits] == [
        (unicodedata.normalize("NFC", printed), UNKNOWN_PROC)
    ]


def test_proc_name_taken_from_original_line(matcher):
    line = f"23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc      0.000010   {_CAFE_NFD}.42"
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name, h.tid) for h in hits] == [("/Users/alice/.netrc", _CAFE_NFD, 42)]
    assert miss is None
