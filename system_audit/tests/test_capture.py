import threading
from pathlib import Path

from credwatch.capture import CaptureSupervisor, build_tcpdump_argv, prune_captures
from credwatch.config import CaptureConfig


def _cfg(enabled=True, rotate=60, keep=3):
    return CaptureConfig(
        enabled=enabled, interface="eth0", rotate_seconds=rotate, retain_files=keep, snaplen=128
    )


def test_argv_has_no_W_and_drops_to_root(tmp_path):
    argv = build_tcpdump_argv(_cfg(), tmp_path)
    assert "-W" not in argv
    assert argv[argv.index("-Z") + 1] == "root"
    assert argv == [
        "tcpdump", "-i", "eth0", "-n", "-s", "128", "-G", "60", "-Z", "root",
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
    def __init__(self, code, stderr_text, stderr_file, blocker=None):
        self._code = code
        self._blocker = blocker
        self.terminated = False
        if stderr_text and stderr_file is not None:
            stderr_file.write(stderr_text)
            stderr_file.flush()

    def poll(self):
        if self._blocker is not None:
            return 0 if self.terminated else None
        return self._code

    def wait(self, timeout=None):
        return self.poll()

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True


class FakePopen:
    def __init__(self, fail_times=2):
        self.fail_times = fail_times
        self.calls = []
        self.blocked = threading.Event()

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if len(self.calls) <= self.fail_times:
            return FakeProc(1, b"boom " + b"x" * 5000 + b"END", kwargs.get("stderr"))
        self.blocked.set()
        return FakeProc(0, b"", None, blocker=True)


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
    assert popen.calls[0][1]["preexec_fn"] is not None


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
    assert isinstance(tmp_path, Path)
