"""fs_usage fail-closed paths: `/..` merging (I3) and canonical caseless matching (queued b)."""
import random
import unicodedata
from pathlib import Path

import pytest

from credwatch.backends.macos_fsusage import UNKNOWN_PROC, fold_line, prefilter_keys
from credwatch.paths import WatchMatcher
from _fsusage_support import (
    WATCHED,
    _TAIL_OK,
    _WS_COMPONENTS,
    _covered,
    _hits,
    _variant,
    matcher,
)

ALICE = "/Users/alice"
OPEN = "23:59:58.100000  open  F=3  (R_____)  "


def _flagged(hits):
    return all((h.proc_name, h.tid) == (UNKNOWN_PROC, None) for h in hits)


# --- I3: `/..` always merges the component-name fallback ----------------------------


@pytest.mark.parametrize("line,decoy,real", [
    # a watched path that `..` removes again, in front of the real target
    (f"{OPEN}{ALICE}/.aws/config  x/../../.ssh/id_rsa{_TAIL_OK}",
     f"{ALICE}/.aws/config", f"{ALICE}/.ssh"),
    (f"{OPEN}{ALICE}/.netrc x  y/../.ssh/id{_TAIL_OK}",
     f"{ALICE}/.netrc", f"{ALICE}/.ssh"),
    # rename: watched source, destination hidden behind a whitespace component and `..`
    (f"23:59:58.100000  rename  {ALICE}/.aws/config  {ALICE}/x  y/../.ssh/id_rsa{_TAIL_OK}",
     f"{ALICE}/.aws/config", f"{ALICE}/.ssh"),
])
def test_dotdot_fallback_merged_with_found_hits(matcher, line, decoy, real):
    hits, miss = _hits(line, matcher)
    paths = {h.path for h in hits}
    assert decoy in paths
    assert any(p == real or p.startswith(real + "/") for p in paths), paths
    assert _flagged(hits)
    assert miss is not None


@pytest.mark.parametrize("trusted_line", [
    f"{OPEN}{ALICE}/.aws/config  x/../../.ssh/id_rsa{_TAIL_OK}",
])
def test_dotdot_strict_path_reported_when_it_differs(matcher, trusted_line):
    """The strict parse resolves `..` itself: its watched target is named exactly."""
    hits, _ = _hits(trusted_line, matcher)
    assert f"{ALICE}/.ssh/id_rsa" in {h.path for h in hits}
    assert _flagged(hits)


def test_dotdot_merge_dedupes_found_path(matcher):
    line = f"{OPEN}{ALICE}/x/../.netrc{_TAIL_OK}"
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [(f"{ALICE}/.netrc", "cat")]
    assert miss is None


_FILES = (f"{ALICE}/.aws/credentials", f"{ALICE}/.aws/config", f"{ALICE}/.netrc",
          f"{ALICE}/.kube/config", f"{ALICE}/.docker/config.json")
_HIDDEN = (f"{ALICE}/.ssh/id_x", f"{ALICE}/.netrc", f"{ALICE}/.aws/credentials",
           unicodedata.normalize("NFC", "/Users/josé/.netrc"))


@pytest.mark.parametrize("seed", range(5))
def test_random_decoy_above_dotdot_never_hides_target(matcher, seed):
    """A watched decoy whose last component is glued to whitespace that `..` removes,
    with the real target below: the target (or its watched root) is reported, and
    an attributed hit (single-space glue resolves exactly) is exactly the target."""
    rng = random.Random(seed)
    for _ in range(300):
        decoy, target = rng.choice(_FILES), rng.choice(_HIDDEN)
        if decoy == target:
            continue
        glue = rng.choice(_WS_COMPONENTS)
        ups = "/.." * (decoy.count("/"))
        printed = f"{decoy}{glue}x{ups}/{_variant(rng, target).lstrip('/')}"
        line = f"{OPEN}{printed}{' ' * rng.randint(2, 6)}0.000010   cat.42"
        hits, _ = _hits(line, matcher)
        reported = [(h.path, h.proc_name) for h in hits]
        assert _covered(target, reported), line
        assert all(p == UNKNOWN_PROC for path, p in reported if path == decoy), line


# --- queued b: canonical caseless matching (NFD(casefold(NFD))) ---------------------

_IOTA = "ΐ"     # ΐ  small iota with dialytika and tonos
_UPSILON = "ΰ"  # ΰ  small upsilon with dialytika and tonos
_SPELLINGS = {
    _IOTA: ("ΐ", "ΐ", "ΐ", "Ϊ́", "Ϊ́"),
    _UPSILON: ("ΰ", "ΰ", "ΰ", "Ϋ́", "Ϋ́"),
}


@pytest.mark.parametrize("letter,spelling", [
    (letter, s) for letter, spellings in _SPELLINGS.items() for s in spellings
])
@pytest.mark.parametrize("glued", [True, False])
def test_greek_dialytika_tonos_spellings_match(letter, spelling, glued):
    watched = f"/Users/{letter}na/.netrc"
    m = WatchMatcher([Path(watched)], case_insensitive=True)
    printed = f"/USERS/{spelling}NA/.NETRC"
    assert m.matches(printed)
    lead = "F=3  (R_____)" if glued else "F=3  (R_____)  "
    line = f"23:59:58.100000  open  {lead}{printed}{_TAIL_OK}"
    hits, _ = _hits(line, m)
    assert len(hits) == 1 and m.matches(hits[0].path), line
    assert any(k in fold_line(line, m) for k in prefilter_keys(m))


@pytest.mark.parametrize("spelling", _SPELLINGS[_IOTA])
def test_greek_component_prefilter_key_survives_case_spelling(spelling):
    m = WatchMatcher([Path(f"/Users/alice/.{_IOTA}")], case_insensitive=True)
    line = f"23:59:58.100000  open  F=3  (R_____)/Users/alice/.{spelling.upper()}{_TAIL_OK}"
    assert any(k in fold_line(line, m) for k in prefilter_keys(m))
    hits, _ = _hits(line, m)
    assert hits, line


def test_non_ascii_line_without_exact_hit_uses_component_fallback():
    """Canonical reordering can still defeat the offset-mapped search: fail closed."""
    m = WatchMatcher([Path("/Users/aĺ̨ice/.netrc")], case_insensitive=True)
    # marks in the other canonical order, glued so only the needle search could find it
    line = f"23:59:58.100000  open  F=3  (R_____)/Users/aĺ̨ice/.netrc{_TAIL_OK}"
    hits, miss = _hits(line, m)
    assert [h.path for h in hits] and _flagged(hits)
    assert miss is not None


def test_non_ascii_line_without_watched_component_still_ignored(matcher):
    line = f"23:59:58.100000  open  F=3  (R_____)  /Users/josé/notes.txt{_TAIL_OK}"
    assert _hits(line, matcher) == ((), None)


def test_watch_matcher_folds_with_nfd_casefold_nfd():
    m = WatchMatcher([Path(f"/Users/{_IOTA}/.netrc")], case_insensitive=True)
    nfd = unicodedata.normalize
    assert m.normalize("/Users/Ϊ́/.NETRC") == nfd("NFD", nfd("NFD", f"/Users/{_IOTA}/.netrc").casefold())


def test_non_ascii_reordered_target_beside_found_decoy_is_reported():
    """The fallback must not be skipped just because an ASCII decoy was found."""
    target = f"/Users/{_IOTA}̨na/.ssh"
    m = WatchMatcher([Path(target), Path(f"{ALICE}/.netrc")], case_insensitive=True)
    line = (f"23:59:58.100000  rename  {ALICE}/.netrc  "
            f"(R_____)/USERS/{_IOTA}̨NA/.SSH/id{_TAIL_OK}")
    hits, miss = _hits(line, m)
    assert {f"{ALICE}/.netrc", target} <= {h.path for h in hits}
    assert _flagged(hits) and miss is not None


def test_non_ascii_line_with_exact_hit_is_still_attributed(matcher):
    line = f"{OPEN}/Users/josé/.netrc{_TAIL_OK}"
    hits, miss = _hits(line, matcher)
    assert [(h.path, h.proc_name) for h in hits] == [("/Users/josé/.netrc", "cat")]
    assert miss is None
