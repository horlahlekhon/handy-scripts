import threading
import os
import subprocess
import types

from credwatch.capture import CaptureSupervisor, build_tcpdump_argv, prune_captures
from credwatch.config import CaptureConfig


def _cfg(enabled=True, rotate=60, keep=3, user="root"):
    return CaptureConfig(
        enabled=enabled, interface="eth0", rotate_seconds=rotate, retain_files=keep, snaplen=128,
        drop_privileges_to=user,
    )


def test_argv_has_no_W_and_drops_privileges(tmp_path):
    argv = build_tcpdump_argv(_cfg(user="tcpdump"), tmp_path)
    assert "-W" not in argv
    assert argv[argv.index("-Z") + 1] == "tcpdump"
    assert argv == [
        "tcpdump", "-i", "eth0", "-n", "-s", "128", "-G", "60", "-Z", "tcpdump",
        "-w", str(tmp_path / "credwatch-%Y%m%d-%H%M%S.pcap"),
    ]


def _touch(d, *names):
    for n in names:
        (d / n).write_text("x")


def test_prune_keeps_newest_n(tmp_path):
    names = [f"credwatch-20260101-00000{i}.pcap" for i in range(5)]
    _touch(tmp_path, *names, "other.pcap")
    deleted = prune_captures(tmp_path, 2)
    assert deleted == tuple(tmp_path / n for n in names[:3])
    assert sorted(p.name for p in tmp_path.iterdir()) == [*names[3:], "other.pcap"]


def test_prune_keep_zero_never_deletes_newest(tmp_path):
    names = ["credwatch-20260101-000001.pcap", "credwatch-20260101-000002.pcap"]
    _touch(tmp_path, *names)
    prune_captures(tmp_path, 0)
    assert [p.name for p in tmp_path.iterdir()] == [names[1]]


def test_prune_skips_symlinks_and_missing_dir(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("x")
    link = tmp_path / "credwatch-20260101-000001.pcap"
    link.symlink_to(target)
    _touch(tmp_path, "credwatch-20260101-000002.pcap", "credwatch-20260101-000003.pcap")
    deleted = prune_captures(tmp_path, 1)
    assert deleted == (tmp_path / "credwatch-20260101-000002.pcap",)
    assert link.is_symlink() and target.exists()
    assert prune_captures(tmp_path / "nope", 1) == ()


class FakeProc:
    def __init__(self, code, stderr_text, stderr_file, blocker=None, ignore_term=False):
        self._code = code
        self._blocker = blocker
        self.ignore_term = ignore_term
        self.terminated = False
        self.killed = False
        if stderr_text and stderr_file is not None:
            stderr_file.write(stderr_text)
            stderr_file.flush()

    def poll(self):
        if self._blocker is not None:
            return 0 if (self.killed or (self.terminated and not self.ignore_term)) else None
        return self._code

    def wait(self, timeout=None):
        if self.poll() is None:
            raise subprocess.TimeoutExpired("tcpdump", timeout)
        return self.poll()

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class FakePopen:
    def __init__(self, fail_times=2, ignore_term=False, spawn_error_times=0, on_spawn=None):
        self.fail_times = fail_times
        self.ignore_term = ignore_term
        self.spawn_error_times = spawn_error_times
        self.on_spawn = on_spawn
        self.calls = []
        self.procs = []
        self.blocked = threading.Event()

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if len(self.calls) <= self.spawn_error_times:
            raise FileNotFoundError("tcpdump")
        if len(self.calls) <= self.fail_times + self.spawn_error_times:
            proc = FakeProc(1, b"boom " + b"x" * 5000 + b"END", kwargs.get("stderr"))
        else:
            proc = FakeProc(0, b"", None, blocker=True, ignore_term=self.ignore_term)
        self.procs.append(proc)
        if self.on_spawn:
            self.on_spawn()
        if proc._blocker:
            self.blocked.set()
        return proc


def _wait(cond, timeout=2.0):
    done = threading.Event()
    for _ in range(int(timeout / 0.005)):
        if cond():
            return True
        done.wait(0.005)
    return False


def test_supervisor_restarts_and_reports_failure(tmp_path):
    popen = FakePopen()
    failures, sleeps = [], []
    sup = CaptureSupervisor(
        _cfg(), tmp_path, popen=popen, on_failure=failures.append,
        sleep=lambda s: sleeps.append(s), clock=lambda: 0.0,
    )
    sup.start()
    assert popen.blocked.wait(2)
    assert _wait(lambda: sup.status().running)
    st = sup.status()
    sup.stop(timeout=2)
    assert st.restarts == 2
    assert len(failures) == 2
    assert all(f.endswith("END") and len(f) <= 2048 for f in failures)
    assert st.last_error == failures[-1]
    assert sum(sleeps) == 1 + 2
    assert not sup.status().running
    assert popen.calls[0][1]["umask"] == 0o077
    assert "preexec_fn" not in popen.calls[0][1]
    assert popen.calls[0][1]["stdin"] == subprocess.DEVNULL
    assert popen.procs[-1].terminated


def test_backoff_caps_and_resets_after_uptime(tmp_path):
    ticks = iter(range(0, 10**6, 700))  # each reading advances 700 s -> uptime > 600
    popen = FakePopen(fail_times=3)
    sleeps = []
    sup = CaptureSupervisor(
        _cfg(), tmp_path, popen=popen, on_failure=lambda _: None,
        sleep=sleeps.append, clock=lambda: next(ticks),
    )
    sup.start()
    assert popen.blocked.wait(2)
    sup.stop(timeout=2)
    assert sum(sleeps) == 3


def test_backoff_capped_at_300(tmp_path):
    popen = FakePopen(fail_times=12)
    sleeps = []
    sup = CaptureSupervisor(
        _cfg(), tmp_path, popen=popen, on_failure=lambda _: None,
        sleep=sleeps.append, clock=lambda: 0.0,
    )
    sup.start()
    assert popen.blocked.wait(2)
    sup.stop(timeout=2)
    assert sum(sleeps) == sum(2**i for i in range(9)) + 3 * 300


def test_supervisor_prunes_at_start(tmp_path):
    _touch(tmp_path, *(f"credwatch-20260101-00000{i}.pcap" for i in range(4)))
    popen = FakePopen(fail_times=0)
    sup = CaptureSupervisor(
        _cfg(keep=1), tmp_path, popen=popen, on_failure=lambda _: None,
        sleep=lambda s: None, clock=lambda: 0.0,
    )
    sup.start()
    assert popen.blocked.wait(2)
    assert sup.status().newest_file == tmp_path / "credwatch-20260101-000003.pcap"
    sup.stop(timeout=2)
    assert len(list(tmp_path.glob("credwatch-*.pcap"))) == 1


def test_disabled_capture_never_spawns(tmp_path):
    popen = FakePopen()
    sup = CaptureSupervisor(
        _cfg(enabled=False), tmp_path, popen=popen, on_failure=lambda _: None
    )
    sup.start()
    sup.stop()
    assert popen.calls == []
    assert not sup.status().running


def _sup(tmp_path, popen, failures=None, sleep=lambda s: None, **kw):
    return CaptureSupervisor(
        _cfg(), tmp_path, popen=popen,
        on_failure=(failures.append if failures is not None else (lambda _: None)),
        sleep=sleep, clock=lambda: 0.0, **kw,
    )


def test_stop_before_proc_registered_still_terminates_child(tmp_path):
    holder = {}
    popen = FakePopen(fail_times=0, on_spawn=lambda: holder["sup"]._stop.set())
    sup = holder["sup"] = _sup(tmp_path, popen)
    sup.start()
    assert popen.blocked.wait(2)
    sup.stop(timeout=2)
    assert len(popen.procs) == 1
    assert popen.procs[0].terminated
    assert not sup.status().running


def test_sigterm_ignoring_child_is_killed(tmp_path, monkeypatch):
    monkeypatch.setattr("credwatch.capture.TERMINATE_WAIT_SECONDS", 0.01)
    popen = FakePopen(fail_times=0, ignore_term=True)
    sup = _sup(tmp_path, popen)
    sup.start()
    assert popen.blocked.wait(2)
    assert sup.status().running
    sup.stop(timeout=2)
    assert popen.procs[0].terminated and popen.procs[0].killed
    assert not sup.status().running


def test_spawn_oserror_is_reported_and_retried(tmp_path):
    popen = FakePopen(fail_times=0, spawn_error_times=2)
    failures = []
    sup = _sup(tmp_path, popen, failures)
    sup.start()
    assert popen.blocked.wait(2)
    sup.stop(timeout=2)
    assert len(failures) == 2
    assert all(f.startswith("spawn failed") for f in failures)
    assert sup.status().restarts == 2


def test_on_failure_raising_does_not_kill_supervisor(tmp_path, caplog):
    popen = FakePopen(fail_times=1)

    def boom(_):
        raise RuntimeError("mail down")

    sup = CaptureSupervisor(
        _cfg(), tmp_path, popen=popen, on_failure=boom, sleep=lambda s: None, clock=lambda: 0.0
    )
    sup.start()
    assert popen.blocked.wait(2)
    sup.stop(timeout=2)
    assert "on_failure callback raised" in caplog.text


def test_unexpected_exception_in_loop_is_logged_and_retried(tmp_path, caplog):
    calls = []

    def flaky_popen(argv, **kw):
        calls.append(1)
        if len(calls) == 1:
            raise ValueError("bad args")
        return FakeProc(0, b"", None, blocker=True)

    failures = []
    sup = _sup(tmp_path, flaky_popen, failures)
    sup.start()
    assert _wait(lambda: sup.status().running)
    sup.stop(timeout=2)
    assert failures and failures[0].startswith("supervisor error")
    assert "iteration failed" in caplog.text


def test_stop_during_backoff_exits_without_respawn(tmp_path):
    popen = FakePopen(fail_times=100)
    holder = {}
    slept = []

    def sleep(s):
        slept.append(s)
        holder["sup"]._stop.set()  # stop() would self-join from the worker thread

    sup = holder["sup"] = _sup(tmp_path, popen, sleep=sleep)
    sup.start()
    assert _wait(lambda: not sup._thread.is_alive())
    assert len(popen.procs) == 1
    assert slept == [1]
    assert sup.status().restarts == 0


def test_restarts_counts_respawns_not_failures(tmp_path):
    popen = FakePopen(fail_times=1)
    sup = _sup(tmp_path, popen)
    sup.start()
    assert popen.blocked.wait(2)
    assert _wait(lambda: sup.status().running)
    assert sup.status().restarts == 1
    sup.stop(timeout=2)


def _stat_for(uid, mode):
    return lambda p: types.SimpleNamespace(st_uid=uid, st_mode=0o40000 | mode)


def test_unprivileged_user_requires_owned_0700_dir(tmp_path):
    for stat_fn in (_stat_for(0, 0o700), _stat_for(105, 0o755)):
        popen = FakePopen(fail_times=0)
        failures = []
        sup = CaptureSupervisor(
            _cfg(user="tcpdump"), tmp_path, popen=popen, on_failure=failures.append,
            getpwnam=lambda n: types.SimpleNamespace(pw_uid=105), stat_fn=stat_fn,
        )
        sup.start()
        assert popen.calls == []
        assert failures == ["captures dir must be owned by tcpdump mode 0700; re-run credwatch install"]
        assert not sup.status().running


def test_missing_capture_user_blocks_spawn(tmp_path):
    def nouser(name):
        raise KeyError(name)

    popen = FakePopen(fail_times=0)
    failures = []
    sup = CaptureSupervisor(
        _cfg(user="tcpdump"), tmp_path, popen=popen, on_failure=failures.append, getpwnam=nouser
    )
    sup.start()
    assert popen.calls == [] and "does not exist" in failures[0]


def test_stat_failure_blocks_spawn(tmp_path):
    def bad_stat(p):
        raise FileNotFoundError(p)

    popen = FakePopen(fail_times=0)
    failures = []
    sup = CaptureSupervisor(
        _cfg(user="tcpdump"), tmp_path, popen=popen, on_failure=failures.append,
        getpwnam=lambda n: types.SimpleNamespace(pw_uid=1), stat_fn=bad_stat,
    )
    sup.start()
    assert popen.calls == [] and "cannot stat" in failures[0]


def test_unprivileged_user_with_correct_dir_spawns(tmp_path):
    popen = FakePopen(fail_times=0)
    sup = CaptureSupervisor(
        _cfg(user="tcpdump"), tmp_path, popen=popen, on_failure=lambda _: None,
        sleep=lambda s: None, clock=lambda: 0.0,
        getpwnam=lambda n: types.SimpleNamespace(pw_uid=105), stat_fn=_stat_for(105, 0o700),
    )
    sup.start()
    assert popen.blocked.wait(2)
    sup.stop(timeout=2)
    assert os.path.basename(popen.calls[0][0][popen.calls[0][0].index("-Z") + 1]) == "tcpdump"
