"""Shared fixtures, fakes and generators for the macOS fs_usage tests."""
import io
import os
import random
import string
import threading
import unicodedata
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import psutil
import pytest

from credwatch.backends.base import BackendError
from credwatch.backends.macos_fsusage import (
    RELEVANT_OPS,
    UNKNOWN_PROC,
    MacFsUsageBackend,
    parse_fs_usage_line,
    parse_fs_usage_hits,
)
from credwatch.paths import WatchMatcher


FIXTURE = Path(__file__).parent / "fixtures" / "fs_usage_sample.txt"
TZ = timezone(timedelta(hours=2))
TODAY = date(2026, 11, 8)
NOW = datetime(2026, 11, 8, 23, 59, 59, 500000, tzinfo=TZ)
WATCHED = (
    Path("/Users/alice/.aws/credentials"),
    Path("/Users/alice/.aws/config"),
    Path("/Users/alice/.ssh"),
    Path("/Users/alice/.netrc"),
    Path("/Users/alice/.kube/config"),
    Path("/Users/alice/.docker/config.json"),
    Path("/Library/Application Support/credwatch/canary"),
    Path(unicodedata.normalize("NFC", "/Users/josé/.netrc")),
)
JOSE_NETRC = unicodedata.normalize("NFC", "/Users/josé/.netrc")


def _lines() -> list[str]:
    return [ln for ln in FIXTURE.read_text().splitlines() if ln and not ln.startswith("#")]


def _line(fragment: str) -> str:
    return next(ln for ln in _lines() if fragment in ln)


@pytest.fixture
def matcher():
    return WatchMatcher(WATCHED, case_insensitive=True)


def _parse(line, matcher, now=NOW):
    return parse_fs_usage_line(line, matcher, now.date(), now)


def _hits(line, matcher):
    return parse_fs_usage_hits(line, matcher, TODAY, NOW)


_NAME_ALPHABET = (
    string.ascii_letters + string.digits + string.punctuation + "      ./]"
    + "ßﬁİŉǰéü"
)
_NAME_PIECES = (
    " W ", " 0.5 ", " 1.000010 ", "..", ".123", " ", "W", "9.9", "[ 2]", "/", "ßß",
    "e\u0301", "\u0301", unicodedata.normalize("NFD", "É"),
)
_TARGETS = (
    "/Users/alice/.netrc", "/Users/alice/.aws/credentials", "/Users/alice/.ssh/id_x",
    "/Library/Application Support/credwatch/canary", "/Users/alice/.ssh/a b", JOSE_NETRC,
)


def _variant(rng, path):
    """A path that normalizes to `path`: ./ and x/.. segments, doubled slashes,
    case changes, NFD spellings."""
    parts = path.split("/")[1:]
    out = []
    for part in parts:
        if rng.random() < 0.2:
            out.append(".")
        if rng.random() < 0.1:
            out.extend(("bob", ".."))
        if rng.random() < 0.1:  # whitespace in a component that `..` removes
            out.extend((rng.choice(_WS_COMPONENTS), ".."))
        cased = "".join(c.upper() if rng.random() < 0.3 else c for c in part)
        out.append(unicodedata.normalize("NFD", cased) if rng.random() < 0.3 else cased)
    sep = lambda: "//" if rng.random() < 0.15 else "/"  # noqa: E731
    return "".join(sep() + p for p in out)


_WS_COMPONENTS = ("x  y", "x ", "a\tb", "  ", " z", "q\t", " ")


def _key(path):
    nfc = unicodedata.normalize("NFC", os.path.normpath("/" + path.lstrip("/")))
    return unicodedata.normalize("NFC", nfc.casefold())


def _random_lines(seed, count=500):
    """(line, target) pairs: a relevant op on a watched target, attacker-chosen name."""
    rng = random.Random(seed)
    for _ in range(count):
        target = rng.choice(_TARGETS)
        printed = _variant(rng, target)
        name = "".join(
            rng.choice(_NAME_PIECES) if rng.random() < 0.3 else rng.choice(_NAME_ALPHABET)
            for _ in range(rng.randint(1, 24))
        )
        op = rng.choice(sorted(RELEVANT_OPS))
        gap = " " * rng.randint(2, 8)
        lead = rng.choice(["F=3  (R_____)  ", "[  2]  (R_____)  ", "[ 2]", "  "])
        tid = rng.choice([f".{rng.randint(1, 10**7)}", ""])
        line = f"23:59:58.{rng.randint(0, 999999):06d}  {op}  {lead}{printed}{gap}0.000010   {name}{tid}"
        yield line, target


def _under(key, root):
    return key == root or key.startswith(root + "/")


def _covered(target, reported):
    """Invariant check over (path, proc) pairs reported for one line.

    The target itself is reported, or (an unresolvable `..` or a whitespace
    component split it) a flagged UNKNOWN_PROC hit names a path in the same
    watched root. An attributed hit must be exactly the target.
    """
    t = _key(target)
    roots = [r for r in (_key(str(w)) for w in WATCHED) if _under(t, r)]
    for path, proc in reported:
        if proc != UNKNOWN_PROC and _key(path) != t:
            return False
    return any(
        _key(path) == t or (proc == UNKNOWN_PROC and any(_under(_key(path), r) for r in roots))
        for path, proc in reported
    )


class FakeProc:
    def __init__(self, pid, name, exe="/usr/bin/x", ppid=1, deny=False):
        self.pid, self._name, self._exe, self._ppid, self._deny = pid, name, exe, ppid, deny
        self.info = {"pid": pid, "name": name}

    def name(self):
        if self._deny:
            raise psutil.AccessDenied(self.pid)
        return self._name

    def exe(self):
        if self._deny:
            raise psutil.AccessDenied(self.pid)
        return self._exe

    def ppid(self):
        return self._ppid


class FakePsutil:
    NoSuchProcess = psutil.NoSuchProcess
    AccessDenied = psutil.AccessDenied
    ZombieProcess = psutil.ZombieProcess
    Error = psutil.Error

    def __init__(self, procs, iter_error=None):
        self.procs = {p.pid: p for p in procs}
        self.iter_error = iter_error

    def Process(self, pid):
        if pid not in self.procs:
            raise psutil.NoSuchProcess(pid)
        return self.procs[pid]

    def process_iter(self, attrs=None):
        if self.iter_error:
            raise self.iter_error
        return iter(list(self.procs.values()))


class FakePopen:
    """Popen stand-in fed from a list of stdout lines, then exits with `rc`."""

    instances: list["FakePopen"] = []

    def __init__(self, lines, rc=0, stderr="", block=None):
        self._lines, self._rc, self._stderr, self._block = lines, rc, stderr, block
        self.argv = None
        self.kwargs = None
        self.returncode = None
        self.terminated = False
        self.killed = False

    def __call__(self, argv, **kwargs):
        self.argv, self.kwargs = argv, kwargs
        self.stdout = _BlockingLines(self._lines, self._block)
        self.stderr = io.StringIO(self._stderr)
        return self

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = self._rc
        return self.returncode

    def terminate(self):
        self.terminated = True
        if self._block is not None:
            self._block.set()
        self.returncode = -15

    def kill(self):
        self.killed = True


class _BlockingLines:
    def __init__(self, lines, block):
        self._it = iter([ln + "\n" for ln in lines])
        self._block = block

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self._it)
        except StopIteration:
            if self._block is not None:
                self._block.wait(5)
            raise

    closed = False

    def close(self):
        self.closed = True


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _backend(tmp_path, popen, mod=None, clock=None, now=NOW, trust=False):
    export = tmp_path / "audit-exports"
    export.mkdir(exist_ok=True)
    return MacFsUsageBackend(
        WATCHED, runner_popen=popen, export_dir=export,
        psutil_mod=mod or FakePsutil([FakeProc(2004211, "cat", exe="/bin/cat", ppid=42)]),
        clock=clock or Clock(), now_fn=lambda: now, trust_name_resolution=trust,
    )


def _drain(backend, stop=None):
    out = []
    with pytest.raises(BackendError):
        for ev in backend.events(stop or threading.Event()):
            out.append(ev)
    return out


_TAIL_OK = "      0.000010   cat.42"
_NETRCS = {"/Users/alice/.netrc", JOSE_NETRC}  # both watched paths end in `.netrc`
_JCARON = "/Users/ǰane/.netrc"  # U+01F0: casefolds to j + U+030C (decomposed)
_CAFE_NFC = unicodedata.normalize("NFC", "café")
_CAFE_NFD = unicodedata.normalize("NFD", "café")
