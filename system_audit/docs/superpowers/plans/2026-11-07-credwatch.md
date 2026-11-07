# credwatch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A persistent, root-run daemon on Debian (auditd) and macOS (fs_usage) that records every access to credential files, flags non-allowlisted processes, snapshots their network connections, keeps a rolling pcap buffer, and emails alerts and daily digests.

**Architecture:** `src/credwatch/` package of small modules. A backend thread yields `FileAccessEvent`s → allowlist check and (if flagged) a psutil snapshot happen *in that thread* so the snapshot races the process exit as little as possible → a queue → the main loop writes SQLite and hands flagged events to an alert worker thread. tcpdump runs under a supervisor thread. Scheduled jobs (heartbeat, canary probe, audit export, retention, digest) run from the main loop.

**Tech Stack:** Python ≥3.11, psutil ≥6.0, PyYAML ≥6.0, stdlib (sqlite3, smtplib, argparse, logging, threading, subprocess). pytest + pytest-cov for dev. systemd system service / launchd LaunchDaemon.

**Spec:** `system_audit/prmpt.txt`

## Decisions this plan makes (not dictated by the spec)

| Decision | Why |
|---|---|
| **systemd *system* service and launchd *LaunchDaemon* (root)**, not user agents | auditd rules, `/var/log/audit/audit.log`, `tcpdump`, and `fs_usage` all need root. A user service can't do any of it. |
| Config + secrets live in **`/etc/credwatch/`** (root, 0700 dir / 0600 files). The repo has only `config.example.yaml` and `secrets.env.example`, and `.gitignore` lists `secrets.env` | Malware running as the user could otherwise read the Gmail app password or add itself to the allowlist. This also meets "never a new leak vector." |
| Data dir stays at the spec's location (`~/.local/share/credwatch`, `~/Library/Application Support/credwatch`) of the **target user** (from `SUDO_USER` / `--user`, not root's home), but is **root-owned 0700** | Keeps the evidence tamper-resistant against user-level malware. `report` and `status` need `sudo`. |
| Install the package with **`sudo pipx install --global .`** (pipx ≥1.5 → `/opt/pipx`, `/usr/local/bin/credwatch`) | A root service that executes a binary from the user's `~/.local` lets user-level malware escalate to root. `install` refuses to run if its own executable or venv is writable by a non-root user. |
| `install` writes **`/etc/credwatch/watched_paths.txt`**, and the daemon reads it | One source of truth for audit rules and the macOS filter. Re-running `install` refreshes coverage and restarts the service. |
| A **canary file** `<data_dir>/canary` is always watched. The daemon reads it hourly and alerts if no matching event arrives within 60 s. `status --probe` does the same on demand | Catches the most dangerous failure, a monitor that is "running" but blind, right away instead of in hindsight. |
| **Health alerts** by email when the backend dies, tcpdump crashes, audit rules disappear, or the canary fails | Implements the spec's "fail loudly." |
| **Alert coalescing:** the first flagged event for a given exe is emailed immediately, and further hits within `coalesce_seconds` (default 60) go out as one batched email | An infostealer sweeps dozens of files in one go, and Gmail rate-limits. |
| tcpdump runs with `-G` and **no `-W`**, and credwatch prunes old files itself. It also runs with **`-Z root`** | With `-G` alone, `-W N` makes tcpdump *exit* after N files. Debian's tcpdump also drops privileges to user `tcpdump`, which can't write into a root-0700 dir. |
| Parent process chain (up to 5 levels: exe + cmdline) is added to the snapshot | Infostealers are often spawned by a dropper. Cheap to grab while the pid is alive. |

## Global Constraints

- Python `>=3.11`. Runtime deps **only** `psutil>=6.0` and `PyYAML>=6.0`. Dev extras: `pytest`, `pytest-cov`.
- Coverage ≥ 80% line (`pytest --cov=credwatch --cov-fail-under=80`).
- All value types are `@dataclass(frozen=True)`, and collections in them are tuples. No mutation of inputs.
- SMTP credentials are read **only** from `CREDWATCH_SMTP_USER` / `CREDWATCH_SMTP_PASSWORD` (env, or the secrets file via `--secrets-file`). They are never logged, never echoed, and never written into config or DB.
- Every `psutil` call that takes a pid catches `NoSuchProcess`, `AccessDenied`, and `ZombieProcess`, and records the outcome instead of raising.
- Every swallowed exception is logged with `logger.exception` or at WARNING or higher. No bare `except: pass`.
- Every external command goes through an injectable `Runner` (`credwatch.proc.Runner`) so tests never need root.
- Audit key is exactly `credwatch`. Rule line format is exactly `-w <path> -p rwa -k credwatch`.
- Default sensitive paths are copied verbatim from the spec, section 1.
- Data dir subfolders are exactly `captures/`, `audit-exports/`, `logs/`, plus `events.db`.
- Project root is `system_audit/` (inside the `handy-scripts` repo). Work on branch `feat/credwatch`. Commit only `system_audit/` files. The parent repo has unrelated dirty files.

## Review Focus

1. **Debian's `log_format = ENRICHED` audit lines and hex-encoded paths.** Fields after `\x1d` (UID=, AUID=…) and hex-encoded `name=` values (paths with spaces or non-ASCII) must parse to the correct path. This is pinned in Task 5.
2. **audit.log rotation by auditd** (`max_log_file_action = ROTATE`). The tailer must reopen the new file without losing or duplicating lines. Pinned in Task 6.
3. **A stealer sweeping 40 files in 2 seconds.** That should produce one immediate email and one batched follow-up, not 40 emails, and every event must still be in the DB. Pinned in Task 10.
4. **Symlinked credential files** (dotfiles are symlinked into `~` by this repo's `init.sh`). Both the link and its target get watched. Pinned in Task 3.
5. **Root daemon running a user-writable binary or reading a user-writable config.** `install` must refuse with a clear message. Pinned in Task 13.

---

## File Structure

```
system_audit/
  pyproject.toml  .gitignore  README.md  CLAUDE.md
  config.example.yaml  secrets.env.example
  src/credwatch/
    __init__.py
    proc.py            # Runner protocol + SubprocessRunner
    platform_info.py   # OS detection, target user/home, default dirs, CONFIG_DIR
    config.py          # frozen config dataclasses, load_config, defaults
    models.py          # FileAccessEvent, NetworkSnapshot, Verdict, ProcessedEvent
    allowlist.py
    paths.py           # default paths, .env scan, WatchMatcher, watch-list file io
    store.py
    tail.py            # rotation-aware file follower
    correlate.py
    capture.py
    retention.py       # prune_old_files
    alert.py           # credentials, Mailer, AlertCoalescer, AlertDispatcher
    messages.py        # format_flagged_alert, format_digest, format_health_alert
    daemon.py
    logging_setup.py
    cli.py
    backends/
      __init__.py      # get_backend(os_name, config)
      base.py
      linux_audit.py   # parser, rules render/install, LinuxAuditBackend
      macos_fsusage.py # parser, pid resolution, MacFsUsageBackend
    installer/
      __init__.py      # run_install(...)
      common.py
      linux.py
      macos.py
    templates/
      credwatch.service
      com.credwatch.daemon.plist
  tests/
    fixtures/ audit_enriched.log, audit_hex.log, fs_usage_sample.txt
    test_<module>.py  (one per module)
    test_e2e_linux.py  (opt-in, CREDWATCH_E2E=1, root)
```

Dev loop (record in CLAUDE.md in Task 16):
```bash
cd system_audit && python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
.venv/bin/pytest                                   # all
.venv/bin/pytest tests/test_allowlist.py::test_name -v   # single
.venv/bin/pytest --cov=credwatch --cov-fail-under=80
```

---

### Task 0: Branch

- [ ] `cd /home/olalekan/workspace/personal/handy-scripts && git switch -c feat/credwatch`. Expected: on the new branch, with the unrelated dirty files left unstaged.

### Task 1: Package scaffold, platform info, config

**Files:** Create `pyproject.toml`, `.gitignore`, `config.example.yaml`, `secrets.env.example`, `src/credwatch/{__init__,proc,platform_info,config}.py`, `tests/test_config.py`, `tests/test_platform_info.py`

**Interfaces — Produces:**
- `proc.Runner` (Protocol): `run(argv: Sequence[str], *, check: bool = False, timeout: float | None = 60) -> subprocess.CompletedProcess[str]`. `proc.SubprocessRunner` implements it with `text=True, capture_output=True` and logs argv + returncode at DEBUG.
- `platform_info.current_os() -> Literal["linux", "darwin"]` (raises `UnsupportedPlatform` otherwise). `CONFIG_DIR = Path("/etc/credwatch")`, `CONFIG_PATH`, `SECRETS_PATH = CONFIG_DIR / "secrets.env"`, `WATCH_LIST_PATH = CONFIG_DIR / "watched_paths.txt"`.
- `platform_info.resolve_target_user(explicit: str | None, environ: Mapping[str,str]) -> TargetUser(name: str, uid: int, gid: int, home: Path)`. Order: explicit, then `SUDO_USER`, then the current user. Uses `pwd`.
- `platform_info.default_data_dir(home: Path, os_name) -> Path`.
- `config.Config` with nested frozen dataclasses `EnvScanConfig(roots, max_depth, excludes)`, `AllowRule(path_pattern: str, processes: tuple[str, ...])`, `CaptureConfig(enabled, interface, rotate_seconds, retain_files, snaplen)`, `EmailConfig(smtp_host, smtp_port, from_addr, to_addrs, digest_hour, send_immediately, coalesce_seconds)`, `ExportConfig(interval_minutes, retention_days)`, plus `Config(target_user: str, home: Path, data_dir: Path, extra_paths: tuple[Path,...], env_scan, allowlist: tuple[AllowRule,...], capture, email, audit_export, os_name)`.
- `config.load_config(path: Path, os_name: str, target: TargetUser) -> Config`. It deep-merges the YAML over `default_config_dict(os_name)`. `~` expands against `target.home` (never `Path.home()`). Raises `ConfigError("<dotted.field>: <reason>")`.

**Defaults pinned:** `env_scan.roots=[~]`, `max_depth=4`, `excludes=[node_modules,.git,venv,.venv]`. `capture`: enabled, interface `any` (Linux) / `pktap,all` (macOS; verify in Task 15), `rotate_seconds=3600`, `retain_files=168`, `snaplen=0`. `email`: `smtp.gmail.com`, `587`, `digest_hour=8`, `send_immediately=true`, `coalesce_seconds=60`. `audit_export`: `interval_minutes=60`, `retention_days=30`. Allowlist defaults are the spec's §6 examples, plus `~/.gnupg/** -> gpg, gpg-agent, gpgsm`; `~/.docker/** -> docker, docker-credential-*`; `~/.kube/** -> kubectl, helm, k9s`; and the built-in canary rule.

- [ ] **Step 1: Write failing tests**: `test_defaults_expand_tilde_against_target_home` (asserts `cfg.data_dir == tmp_home/".local/share/credwatch"` on linux and `.../Library/Application Support/credwatch` on darwin), `test_yaml_overrides_merge_deeply` (overriding `capture.retain_files: 24` keeps `capture.rotate_seconds == 3600`), `test_invalid_digest_hour_raises_config_error` (`digest_hour: 25` → `ConfigError` whose message contains `email.digest_hour`), `test_config_rejects_smtp_password_key` (an `email.password` key → `ConfigError`, so credentials can't drift into the config), `test_resolve_target_user_prefers_sudo_user`.
- [ ] **Step 2:** `pytest tests/test_config.py tests/test_platform_info.py -v` → FAIL (import errors).
- [ ] **Step 3:** Implement. `pyproject.toml`: setuptools, src layout, `[project.scripts] credwatch = "credwatch.cli:main"`, package-data `templates/*`, `[tool.pytest.ini_options] testpaths=["tests"]`. `.gitignore`: `secrets.env`, `*.db`, `*.db-*`, `captures/`, `logs/`, `audit-exports/`, `.venv/`, `__pycache__/`, `*.egg-info/`. `secrets.env.example` holds the two vars with `REPLACE_ME` values and a comment saying the real file lives at `/etc/credwatch/secrets.env` (0600 root).
- [ ] **Step 4:** Tests pass.
- [ ] **Step 5:** `git add system_audit && git commit -m "feat(credwatch): scaffold package, config loading, platform info"`

### Task 2: Event models + allowlist

**Files:** Create `src/credwatch/{models,allowlist}.py`, `tests/test_allowlist.py`

**Interfaces — Produces:**
- `FileAccessEvent(timestamp: datetime  # tz-aware UTC, path: str, pid: int | None, ppid: int | None, exe: str | None, comm: str | None, success: bool | None, backend: str, raw: str)`
- `Connection(family: str, type: str, laddr: str, raddr: str | None, status: str)`. `ProcessInfo(pid: int, exe: str | None, cmdline: tuple[str, ...])`
- `NetworkSnapshot(pid: int | None, taken_at: datetime, alive: bool, connections: tuple[Connection, ...], ancestry: tuple[ProcessInfo, ...], error: str | None)`
- `Verdict(allowed: bool, matched_rule: str | None)`. `ProcessedEvent(event, verdict, snapshot: NetworkSnapshot | None)`
- `Allowlist(rules: tuple[AllowRule, ...])` with `.check(event: FileAccessEvent) -> Verdict`. Path patterns are absolute (already expanded). `X/**` matches `X` itself and anything below it. Other patterns use `fnmatch`. Candidate process names are `basename(exe)` and `comm`. A process pattern matches a candidate by `fnmatch`, or by a 15-character prefix match against `comm` (Linux truncates comm to 15 characters). Rules union.

- [ ] **Step 1: Failing tests:** `test_ssh_read_by_ssh_allowed`, `test_ssh_read_by_curl_flagged` (`Verdict(False, None)`), `test_python3_glob_matches_python3_13` (`processes=("python3*",)`, exe `/usr/bin/python3.13`), `test_double_star_matches_directory_itself`, `test_truncated_comm_matches_long_name` (comm `gnome-keyring-d` vs `gnome-keyring-daemon`), `test_missing_exe_and_comm_is_flagged`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(credwatch): event models and allowlist matching`.

### Task 3: Watched paths

**Files:** Create `src/credwatch/paths.py`, `tests/test_paths.py`

**Interfaces — Produces:**
- `DEFAULT_SENSITIVE_PATHS: tuple[str, ...]`, the spec §1 list verbatim (with `~`).
- `scan_env_files(cfg: EnvScanConfig) -> tuple[Path, ...]`. Uses `os.walk(followlinks=False)` and prunes `excludes` in place on `dirnames` (this local list is the one sanctioned mutation; it's how `os.walk` works). Depth is counted from each root. It matches files whose name starts with `.env`. `onerror` logs a WARNING per unreadable directory.
- `resolve_watch_paths(cfg: Config) -> tuple[Path, ...]`. Inputs are defaults + `extra_paths` + env scan + `cfg.data_dir / "canary"`. It keeps only paths that exist. For each symlink it adds both the link path and `resolve()`. It drops any path under a directory already in the set (auditd dir watches are recursive). Output is sorted and deduped.
- `WatchMatcher(paths: Iterable[Path])` with `.matches(path: str) -> bool` (equal to a watched path or under it). Uses a prefix check on `str(p) + os.sep`.
- `write_watch_list(paths, dest: Path) -> None` writes atomically (temp file + `os.replace`, mode 0600). `read_watch_list(src: Path) -> tuple[Path, ...]`.

- [ ] **Step 1: Failing tests** (build a fake home under `tmp_path`): `test_only_existing_defaults_returned`, `test_env_scan_respects_excludes_and_depth` (`.env` in `proj/node_modules/` and at depth 5 are both excluded; `proj/.env.local` is included), `test_symlinked_credential_watches_link_and_target` (`~/.npmrc -> dotfiles/npmrc` yields both paths), `test_children_of_watched_dir_collapsed` (`~/.ssh` and `~/.ssh/id_ed25519` → only `~/.ssh`), `test_canary_always_included`, `test_watch_matcher_does_not_match_sibling_prefix` (watching `~/.aws` must not match `~/.aws-old/x`), `test_watch_list_roundtrip_is_0600`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(credwatch): sensitive path discovery and env scan`.

### Task 4: SQLite store

**Files:** Create `src/credwatch/store.py`, `tests/test_store.py`

**Interfaces — Produces:**
- `Store(db_path: Path)` opens with WAL, sets `PRAGMA user_version = 1`, and creates its schema idempotently. It is used from a single thread (the main loop). Also `close()`.
- Tables: `events(id, ts TEXT UTC ISO, path, pid, ppid, exe, comm, success, backend, allowed INT, matched_rule, raw)` with indexes on `ts`, `allowed`, and `exe`. `net_snapshots(id, event_id FK, taken_at, alive, error, connections_json, ancestry_json)`. `daily_summaries(day TEXT PK, total, flagged, by_process_json, by_path_json)`. `meta(key PK, value)`.
- `record(pe: ProcessedEvent) -> int` writes the event and its snapshot in one transaction.
- `EventRow` (frozen; event columns + `snapshot: NetworkSnapshot | None`). `events_since(since: datetime) -> list[EventRow]`, `events_by_process(name: str, since: datetime | None = None) -> list[EventRow]` (matches exe basename or comm), `flagged_events(since: datetime | None = None) -> list[EventRow]`.
- `DailySummary(day: date, total: int, flagged: int, by_process: tuple[tuple[str,int],...], by_path: tuple[tuple[str,int],...])`. `compute_daily_summary(day: date, tz: tzinfo) -> DailySummary` (local-day bounds) and `save_daily_summary(s)` (upsert).
- `set_meta(key, value: str)` and `get_meta(key) -> str | None`.

- [ ] **Step 1: Failing tests:** `test_record_and_query_since`, `test_flagged_events_excludes_allowed`, `test_events_by_process_matches_comm_when_exe_missing`, `test_snapshot_roundtrip` (connections and ancestry come back equal), `test_daily_summary_uses_local_day_bounds`, `test_save_daily_summary_is_idempotent`, `test_reopen_existing_db_keeps_data`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(credwatch): sqlite event store`.

### Task 5: Linux audit record parser

**Files:** Create `src/credwatch/backends/{__init__,base}.py`, `src/credwatch/backends/linux_audit.py` (parser half), `tests/fixtures/audit_enriched.log`, `tests/fixtures/audit_hex.log`, `tests/test_linux_audit_parser.py`

**Interfaces — Produces:**
- `backends.base.Backend` (ABC): `name: str`; `events(self, stop: threading.Event) -> Iterator[FileAccessEvent]`; `export_native_log(self, dest_dir: Path) -> Path | None`; `health(self) -> tuple[str, ...]` (problem descriptions, empty when healthy). Also `BackendError(Exception)`.
- `parse_record(line: str) -> AuditRecord | None` where `AuditRecord(type: str, serial: str, epoch: float, fields: Mapping[str, str])`. It splits on `\x1d` and **ignores** the enriched suffix. Quoted values are unquoted. Unquoted values that are even-length hex are decoded for `name`, `cwd`, `exe`, `comm`, `proctitle`, and `key`. `(null)` becomes `None`.
- `AuditAssembler(key: str = "credwatch", flush_after: float = 2.0)` with `.feed(line: str, now: float) -> list[FileAccessEvent]`. It groups by serial and emits when it sees `EOE`, or when a group is older than `flush_after` (some records arrive without EOE). It emits only groups whose SYSCALL `key` equals the configured key, one event per PATH record with `nametype` not in {`PARENT`}. Relative `name` is joined with `CWD.cwd`. `raw` is the group's lines joined with `\n`. `success` is `fields["success"] == "yes"`.

- [ ] **Step 1: Fixtures.** Capture real lines on the Debian box: `sudo auditctl -w /tmp/cw-probe -p rwa -k credwatch; cat /tmp/cw-probe; sudo ausearch -k credwatch --raw`. Save the output as `audit_enriched.log`. Hand-write `audit_hex.log` with `name=2F686F6D652F752F6D7920656E762F2E656E76` (`/home/u/my env/.env`).
- [ ] **Step 2: Failing tests:** `test_enriched_line_parses_fields_before_gs`, `test_hex_name_decoded_to_path_with_space`, `test_group_emits_one_event_per_non_parent_path`, `test_relative_name_joined_with_cwd`, `test_other_keys_ignored`, `test_group_without_eoe_flushed_after_timeout`, `test_interleaved_serials_assembled_independently`, `test_garbage_line_returns_none_and_does_not_raise`.
- [ ] **Step 3–4:** Run → FAIL. Implement → PASS.
- [ ] **Step 5:** Commit `feat(credwatch): auditd record parser`.

### Task 6: Linux backend: rules management, tailing, health, export

**Files:** Create `src/credwatch/tail.py`, `src/credwatch/retention.py`. Modify `src/credwatch/backends/linux_audit.py`. Create `tests/test_tail.py`, `tests/test_linux_audit_backend.py`

**Interfaces — Produces:**
- `tail.follow(path: Path, stop: threading.Event, *, poll: float = 0.25, from_end: bool = True) -> Iterator[str]`. It detects rotation (inode changed) and truncation (size < offset). On rotation it drains the old handle to EOF, then opens the new file from the start. A missing file is retried with a WARNING log every 30 s.
- `render_rules(paths: Iterable[Path], key="credwatch") -> str`: a header comment plus one `-w <path> -p rwa -k credwatch` line per path. Paths containing whitespace are skipped with a WARNING (auditctl can't take them) and are returned in a `skipped` tuple: `render_rules(...) -> RenderedRules(text: str, skipped: tuple[Path, ...])`.
- `install_rules(paths, rules_file: Path = Path("/etc/audit/rules.d/credwatch.rules"), runner: Runner) -> bool`. It writes only when the content differs, then runs `augenrules --load`. It returns whether anything changed. If `auditctl -s` shows `enabled 2` (immutable), it raises `BackendError("audit rules are immutable (-e 2); reboot required to load credwatch rules")`.
- `ensure_auditd(runner) -> None`: `systemctl enable --now auditd`, and raises `BackendError` with stderr on failure.
- `count_loaded_rules(runner, key="credwatch") -> int`, from `auditctl -l`.
- `LinuxAuditBackend(audit_log: Path, expected_rule_count: int, runner: Runner, export_checkpoint: Path)`. `events()` = `follow` + `AuditAssembler`. `health()` reports `"loaded credwatch audit rules: N, expected M"` when they differ. `export_native_log(dest_dir)` runs `ausearch -k credwatch -i --checkpoint <export_checkpoint> -ts checkpoint` (`-ts today` when the checkpoint file is missing; on exit codes 10–12 it retries once with `-ts today` and logs WARNING). Exit code 1 + `<no matches>` is treated as an empty export (returns `None`). Output goes to `dest_dir/ausearch-YYYYmmddTHHMMSS.txt`.
- `retention.prune_old_files(directory: Path, pattern: str, older_than: timedelta, now: datetime) -> tuple[Path, ...]` (based on mtime; logs each deletion).

- [ ] **Step 1: Failing tests:** `test_follow_survives_rotation_without_loss_or_dupes` (write 3 lines, rename the file, create a new one with 2 lines → exactly 5 lines in order), `test_follow_handles_truncation`, `test_render_rules_skips_whitespace_paths`, `test_install_rules_idempotent` (second call → `False`, and `augenrules` is called once in total), `test_install_rules_immutable_raises`, `test_health_reports_missing_rules`, `test_export_no_matches_returns_none`, `test_export_falls_back_when_checkpoint_invalid`, `test_prune_old_files_keeps_recent`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(credwatch): linux audit backend with rule install and tailing`.

### Task 7: Correlation

**Files:** Create `src/credwatch/correlate.py`, `tests/test_correlate.py`

**Interfaces — Consumes:** `Allowlist.check`. **Produces:**
- `snapshot_process(pid: int | None, now: datetime, *, psutil_mod=psutil) -> NetworkSnapshot`. It **never raises**. For a `None` pid it returns `alive=False, error="pid unknown"`. It uses `Process(pid).net_connections(kind="inet")`. Ancestry walks `.parent()` up to 5 levels, and each step is guarded individually. If the process has gone away, the result is `alive=False, error="process exited before snapshot"`. On `AccessDenied` it keeps whatever it already gathered and records `error="access denied: <field>"`.
- `Correlator(allowlist: Allowlist, snapshot=snapshot_process, clock=lambda: datetime.now(UTC))` with `.process(event) -> ProcessedEvent`. Allowed events get `snapshot=None`.

- [ ] **Step 1: Failing tests** (fake `psutil_mod`): `test_allowed_event_has_no_snapshot`, `test_flagged_event_snapshots_connections`, `test_process_exited_returns_dead_snapshot`, `test_zombie_and_access_denied_do_not_raise`, `test_ancestry_stops_at_vanished_parent`, `test_none_pid_handled`. Also one real-psutil test: `test_snapshot_of_own_pid_is_alive`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(credwatch): flagged-event network correlation`.

### Task 8: Packet capture supervisor

**Files:** Create `src/credwatch/capture.py`, `tests/test_capture.py`

**Interfaces — Produces:**
- `build_tcpdump_argv(cfg: CaptureConfig, out_dir: Path) -> list[str]`, which returns `["tcpdump", "-i", cfg.interface, "-n", "-s", str(cfg.snaplen), "-G", str(cfg.rotate_seconds), "-Z", "root", "-w", str(out_dir / "credwatch-%Y%m%d-%H%M%S.pcap")]`.
- `prune_captures(out_dir: Path, keep: int) -> tuple[Path, ...]` deletes the oldest `credwatch-*.pcap` by name (the names sort chronologically) beyond `keep`.
- `CaptureSupervisor(cfg, out_dir, *, popen=subprocess.Popen, on_failure: Callable[[str], None], sleep=time.sleep)` with `.start()`, `.stop(timeout=10)`, and `.status() -> CaptureStatus(running: bool, restarts: int, last_error: str | None, newest_file: Path | None)`. It runs one thread. When tcpdump exits unexpectedly it reads the last 2 KB of stderr, calls `on_failure`, and restarts with backoff of 1, 2, 4 … capped at 300 s. Backoff resets after 10 minutes of uptime. It prunes after each `rotate_seconds` and at start. When `cfg.enabled` is false, `start()` logs INFO and does nothing.

- [ ] **Step 1: Failing tests:** `test_argv_has_no_W_and_drops_to_root` (`"-W" not in argv`, and `argv[argv.index("-Z")+1] == "root"`), `test_prune_keeps_newest_n`, `test_supervisor_restarts_and_reports_failure` (a fake Popen that exits with code 1 twice → `on_failure` is called twice and `restarts == 2`), `test_disabled_capture_never_spawns`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(credwatch): rotating tcpdump capture supervisor`.

### Task 9: Messages (pure formatting)

**Files:** Create `src/credwatch/messages.py`, `tests/test_messages.py`

**Interfaces — Produces** (each returns `(subject: str, body: str)`, plain text):
- `format_flagged_alert(events: Sequence[ProcessedEvent], hostname: str) -> tuple[str, str]`. Subject: `[credwatch][{hostname}] FLAGGED: {exe or comm} accessed {n} credential path(s)`. The body lists, per event: UTC + local time, path, pid/ppid, exe, success, connections (or the snapshot error), and ancestry. It ends with a "Where to look" section giving the data-dir paths and the pcap whose name covers the event time.
- `format_digest(summary: DailySummary, flagged: Sequence[EventRow], health: Sequence[str], hostname: str) -> tuple[str, str]`. Subject: `[credwatch][{hostname}] Daily digest {day}: {flagged} flagged / {total} total`.
- `format_health_alert(problems: Sequence[str], hostname: str) -> tuple[str, str]`. Subject: `[credwatch][{hostname}] DEGRADED: {problems[0]}`.

- [ ] **Step 1: Failing tests:** `test_flagged_subject_names_process_and_count`, `test_body_shows_snapshot_error_when_process_gone`, `test_digest_zero_events_still_renders` (the digest's absence would itself be a signal, so it always sends), `test_health_subject`.
- [ ] **Step 2–4:** FAIL → implement → PASS. **Step 5:** Commit `feat(credwatch): alert and digest message formatting`.

### Task 10: Email delivery, credentials, coalescing

**Files:** Create `src/credwatch/alert.py`, `tests/test_alert.py`

**Interfaces — Produces:**
- `SmtpCredentials(user: str, password: str)`, whose `__repr__` masks the password.
- `parse_env_file(text: str) -> dict[str, str]`: `KEY=VALUE`, optional quotes, skips `#` lines and blank lines.
- `load_credentials(environ: Mapping[str,str], secrets_file: Path | None) -> SmtpCredentials`. Env wins over the file. If the secrets file is group- or world-readable it logs a WARNING. If either var is missing or still `REPLACE_ME`, it raises `CredentialsError` naming the variable, never its value.
- `Mailer(cfg: EmailConfig, creds: SmtpCredentials, smtp_factory=smtplib.SMTP)` with `.send(subject, body) -> None`: STARTTLS, `timeout=30`, `EmailMessage`, and `to_addrs` taken from config.
- `AlertCoalescer(window_seconds: int)` with `.add(pe: ProcessedEvent, now: float) -> list[ProcessedEvent] | None` (returns `[pe]` when this is the first flagged event for this exe/comm key in the window, meaning send now) and `.drain_due(now: float) -> list[list[ProcessedEvent]]` (batches whose window has closed). Its state is internal and private to the instance. It is not a value object.
- `AlertDispatcher(mailer_factory: Callable[[], Mailer], hostname: str, on_error: Callable[[str], None])` with `.start()`, `.stop()`, `.submit(subject, body)`. It has a worker thread and a queue, makes 3 attempts with 5/30/120 s backoff, and logs each failure. On final failure it calls `on_error(message)`, which the daemon stores as meta `last_alert_error`.

- [ ] **Step 1: Failing tests:** `test_env_overrides_secrets_file`, `test_missing_password_error_names_var_not_value`, `test_placeholder_value_rejected`, `test_credentials_repr_masks_password`, `test_mailer_uses_starttls_and_login` (fake SMTP records calls), `test_sweep_of_40_files_yields_one_immediate_and_one_batch` (40 `add`s within 2 s → the first returns `[pe]` and the rest return `None`; `drain_due(now+61)` returns one batch of 39), `test_dispatcher_retries_then_reports_error`.
- [ ] **Step 2–4:** FAIL → implement → PASS. **Step 5:** Commit `feat(credwatch): smtp alerts with coalescing and retry`.

### Task 11: Daemon loop

**Files:** Create `src/credwatch/{daemon,logging_setup}.py`, `tests/test_daemon.py`

**Interfaces — Consumes:** `Backend`, `Correlator`, `Store`, `AlertCoalescer`, `AlertDispatcher`, `CaptureSupervisor`, `messages.*`, `retention.prune_old_files`. **Produces:**
- `logging_setup.configure(log_dir: Path, level=logging.INFO) -> None`: a `RotatingFileHandler(log_dir/"credwatch.log", maxBytes=10 MiB, backupCount=5)` plus stderr, which ends up in the journal / launchd log.
- `Daemon(config: Config, backend: Backend, store: Store, correlator: Correlator, dispatcher: AlertDispatcher, capture: CaptureSupervisor, *, clock=time.time, hostname=socket.gethostname())` with `.run(stop: threading.Event) -> None`.
  - A backend reader thread runs `for ev in backend.events(stop): queue.put(correlator.process(ev))`. If it raises or ends, it logs CRITICAL, sends a health alert, and restarts after backoff (5 s up to 300 s).
  - The main loop runs `queue.get(timeout=1)`, then `store.record`. If an event is flagged and `send_immediately` is on, it goes to the coalescer and then the dispatcher. After each iteration the loop runs the due jobs.
  - Jobs and their meta keys: heartbeat every 60 s (`heartbeat`). Canary probe every 3600 s: read `<data_dir>/canary`, and if no event with that path is recorded within 60 s, send a health alert (`last_canary_ok`). `backend.health()` + `capture.status()` every 300 s (health alerts are de-duplicated: the same problem set isn't re-sent within 6 h). Native export every `audit_export.interval_minutes`, plus pruning of `audit-exports/` older than `retention_days`. Daily: at the first loop tick where local hour ≥ `digest_hour` and `last_digest_day` ≠ today, it computes and saves yesterday's summary and sends the digest.
  - `SIGTERM`/`SIGINT` set `stop`. Shutdown stops capture, drains the queue into the store, and stops the dispatcher.

- [ ] **Step 1: Failing tests** (fake backend yields a list, fake clock, real `Store` on tmp, fake dispatcher): `test_every_event_stored_allowed_and_flagged`, `test_flagged_event_dispatched_once_per_window`, `test_backend_crash_triggers_health_alert_and_restart`, `test_canary_timeout_sends_health_alert`, `test_digest_sent_once_per_day_across_restart` (`last_digest_day` persisted), `test_shutdown_drains_queue`.
- [ ] **Step 2–4:** FAIL → implement → PASS. **Step 5:** Commit `feat(credwatch): daemon loop with health checks and digest`.

### Task 12: CLI: run, status, report, test-email

**Files:** Create `src/credwatch/cli.py`, `src/credwatch/backends/__init__.py` (`get_backend(config: Config, runner: Runner) -> Backend`, which picks by `config.os_name` and imports the macOS backend lazily), `tests/test_cli.py`

**Interfaces — Produces:**
- `main(argv: Sequence[str] | None = None) -> int`. Global options: `--config PATH` (default `CONFIG_PATH`), `--user NAME`, `--secrets-file PATH` (default `SECRETS_PATH` if it exists), `-v`.
- `parse_duration(s: str) -> timedelta` for `30m|12h|7d|2w`. Otherwise `argparse.ArgumentTypeError`.
- `run`: requires root (otherwise exit 2 with `"credwatch run must be run as root"`). Loads the config and the watch list, wires the daemon, and blocks.
- `status [--probe]`: shows the service state (`systemctl is-active credwatch` / `launchctl print system/com.credwatch.daemon`), `backend.health()`, heartbeat age, last event time, total/flagged counts for 24 h and 7 d, capture file count + newest file age, `last_alert_error`, and `last_canary_ok`. `--probe` reads the canary and polls the DB for 15 s. Exit code 0 when healthy, 1 when degraded (heartbeat older than 180 s, health problems, or a failed probe).
- `report --last DURATION [--flagged] [--process NAME] [--format table|json|csv] [--output PATH]`: rows from `Store`. JSON includes snapshots.
- `test-email`: loads credentials and sends `"[credwatch][host] test email"`. On error it prints the error class and message (never the creds) and exits 1.
- `install [--user NAME] [--no-start]`: delegates to `installer.run_install` (Task 13).

- [ ] **Step 1: Failing tests:** `test_parse_duration_units`, `test_parse_duration_rejects_garbage`, `test_report_flagged_json` (seeded tmp DB → JSON list where every `allowed` is false), `test_report_csv_header`, `test_status_degraded_when_heartbeat_stale` (exit 1), `test_run_requires_root` (monkeypatch `os.geteuid` → 1000 → exit 2), `test_test_email_failure_does_not_print_password`.
- [ ] **Step 2–4:** FAIL → implement → PASS. **Step 5:** Commit `feat(credwatch): cli commands`.

### Task 13: Linux install + systemd unit

**Files:** Create `src/credwatch/installer/{__init__,common,linux}.py`, `src/credwatch/templates/credwatch.service`, `tests/test_installer_linux.py`

**Interfaces — Produces:**
- `installer.run_install(os_name, target: TargetUser, *, runner: Runner, root: Path = Path("/"), start: bool = True) -> InstallReport(created: tuple[str,...], unchanged: tuple[str,...], warnings: tuple[str,...], watched: int, skipped: tuple[Path,...])`. `root` lets tests install into `tmp_path`.
- `common.assert_root_owned_install(executable: Path, prefix: Path) -> None` raises `InstallError` when either path, or any parent up to `/`, is writable by a non-root uid. The message tells the user to reinstall with `sudo pipx install --global`.
- `common.ensure_dirs(config)` creates the data dir plus its 3 subdirs and `/etc/credwatch`, all `root:root 0700`. It creates `canary` with a fixed text body.
- `common.bootstrap_config(dest)` writes `config.example.yaml` **only if the file is missing**. `common.bootstrap_secrets(dest)` copies the template only if missing, sets it to 0600, and adds a warning that the placeholders must be filled in. Both refuse an existing file whose owner isn't root or that is group/other-writable.
- Linux steps, in order: assert root → assert root-owned install → ensure dirs → bootstrap config + secrets → load config → `resolve_watch_paths` → `write_watch_list` → `ensure_auditd` → `install_rules` → write `/etc/systemd/system/credwatch.service` (only if changed) → `systemctl daemon-reload` → `systemctl enable credwatch` → `systemctl restart credwatch` (unless `--no-start`). Prints the report.
- Unit template (`ExecStart` is filled with the absolute path of the running executable):
  ```ini
  [Unit]
  Description=credwatch credential-file access monitor
  After=auditd.service network-online.target
  Wants=auditd.service network-online.target
  [Service]
  Type=simple
  ExecStart={executable} run --config /etc/credwatch/config.yaml
  EnvironmentFile=/etc/credwatch/secrets.env
  Restart=on-failure
  RestartSec=5
  NoNewPrivileges=yes
  PrivateTmp=yes
  [Install]
  WantedBy=multi-user.target
  ```

- [ ] **Step 1: Failing tests** (`root=tmp_path`, fake runner, ownership checks monkeypatched): `test_install_twice_is_idempotent` (second report: nothing created, `augenrules` and `daemon-reload` not re-run), `test_existing_config_never_overwritten`, `test_secrets_created_0600_with_warning`, `test_refuses_user_writable_executable`, `test_refuses_user_owned_config`, `test_new_env_file_refreshes_rules` (add `~/proj/.env`, reinstall → rules changed, service restarted), `test_unit_renders_executable_path`.
- [ ] **Step 2–4:** FAIL → implement → PASS.
- [ ] **Step 5:** Commit `feat(credwatch): idempotent linux installer and systemd unit`.

### Task 14: Linux end-to-end on the Debian box

**Files:** Create `tests/test_e2e_linux.py` (skipped unless `CREDWATCH_E2E=1` and euid 0)

- [ ] **Step 1:** Write the test `test_curl_reading_canary_is_flagged_and_stored`. It runs `install --no-start`, starts `credwatch run` as a subprocess, runs `/usr/bin/curl -s file://<canary-sibling>` against a temp file added through `extra_paths`, waits up to 15 s, then asserts that the store has a flagged event with `exe` ending in `curl` and a snapshot row. Teardown removes the rules file, runs `augenrules --load`, and deletes the tmp config.
- [ ] **Step 2:** `sudo pipx install --global ./system_audit && sudo CREDWATCH_E2E=1 .venv/bin/pytest tests/test_e2e_linux.py -v` → PASS.
- [ ] **Step 3:** Real install: `sudo credwatch install`. Fill in `/etc/credwatch/secrets.env`. Then `sudo credwatch test-email` (email arrives), `sudo credwatch status --probe` (exit 0), `ls ~/.local/share/credwatch/captures` (a pcap is growing), and `cat ~/.aws/credentials > /dev/null` with `/bin/cat` (expect a flagged alert email). Write down anything noisy, such as GNOME daemons touching `~/.ssh` or `.gnupg`, and add those processes to the default allowlist.
- [ ] **Step 4:** If Debian's AppArmor tcpdump profile blocks writing to `captures/`, the supervisor's health alert should fire. Fix this by documenting the AppArmor override in the README (Task 16). Do not disable AppArmor.
- [ ] **Step 5:** Commit `test(credwatch): opt-in linux end-to-end test` along with any allowlist adjustments. **Linux milestone: open PR 1 here** (`git push -u origin feat/credwatch`).

### Task 15: macOS fs_usage backend + launchd

**Files:** Create `src/credwatch/backends/macos_fsusage.py`, `src/credwatch/installer/macos.py`, `src/credwatch/templates/com.credwatch.daemon.plist`, `tests/fixtures/fs_usage_sample.txt`, `tests/test_macos_fsusage.py`, `tests/test_installer_macos.py`

**Interfaces — Produces:**
- `parse_fs_usage_line(line: str, matcher: WatchMatcher, today: date, now: datetime) -> FsUsageHit | None`, where `FsUsageHit(timestamp: datetime, op: str, path: str, proc_name: str, tid: int | None, raw: str)`. Relevant ops: `open`, `open_nocancel`, `openat`, `openat_nocancel`, `open_dprotected_np`, `rename`, `renameat`, `unlink`, `unlinkat`. Lines whose ops have no path (read/write on `F=`) are ignored. The path is the token starting with `/`. The last token is `name.tid`. Midnight rollover: if the parsed time is more than 60 s after `now`, use yesterday's date.
- `resolve_pid(proc_name: str, tid: int | None, psutil_mod=psutil) -> tuple[int | None, tuple[int, ...]]` returns `(pid, candidates)`. The fs_usage suffix is a **thread id, not a pid**. If it happens to equal the pid of a live process with a matching name, that pid is used. Otherwise, if exactly one live process has that name, it's used. Otherwise `(None, candidates)`, and the candidates are recorded in `raw`.
- `MacFsUsageBackend(watch_paths, runner_popen=subprocess.Popen, export_dir: Path)`. It spawns `fs_usage -w -f filesys`. Before full parsing it pre-filters each line with a substring check against the watched prefixes (fs_usage output is very high volume). Each match is appended to `export_dir/fs_usage-YYYYmmdd.log`. `export_native_log` returns that day's file. `health()` reports when fs_usage exited or when no line at all was read in the last 60 s.
- macOS installer: the same `common` steps, then the plist goes to `/Library/LaunchDaemons/com.credwatch.daemon.plist` (root:wheel 0644), then `launchctl bootout system/com.credwatch.daemon` (a "not loaded" result is OK), then `launchctl bootstrap system <plist>`. The plist has `Label=com.credwatch.daemon`, `ProgramArguments=[{executable}, run, --config, /etc/credwatch/config.yaml, --secrets-file, /etc/credwatch/secrets.env]`, `RunAtLoad`, and `KeepAlive=true`, with `StandardOutPath` / `StandardErrorPath` pointing at `<data_dir>/logs/launchd.{out,err}.log`. launchd has no EnvironmentFile, so `--secrets-file` (Task 10's `load_credentials`) does the same job.

- [ ] **Step 1:** Capture the fixture on the Mac: `sudo fs_usage -w -f filesys > fs.txt` while running `cat ~/.aws/credentials`. Trim it to about 50 lines. **Verify** two things on the Mac and note them in the fixture header: (a) whether the trailing number is a tid, and (b) whether `tcpdump -i any` works or `pktap,all` is needed. Adjust the Task 1 default if (b) differs.
- [ ] **Step 2: Failing tests:** `test_open_of_watched_path_parsed`, `test_unwatched_path_ignored`, `test_fd_only_read_line_ignored`, `test_midnight_rollover_uses_previous_day`, `test_resolve_pid_unique_name`, `test_resolve_pid_ambiguous_returns_candidates`, `test_fs_usage_exit_reported_in_health`, `test_plist_has_keepalive_and_secrets_arg` (parse with `plistlib`), `test_macos_install_idempotent`.
- [ ] **Step 3–4:** FAIL → implement → PASS (on Linux, using fixtures).
- [ ] **Step 5:** On the Mac: `sudo pipx install --global ./system_audit && sudo credwatch install && sudo credwatch status --probe`. If the probe fails, grant Full Disk Access (see the README) and repeat. Record the actual outcome for the README.
- [ ] **Step 6:** Commit `feat(credwatch): macOS fs_usage backend and launchd daemon`. **PR 2.**

### Task 16: README + project CLAUDE.md

**Files:** Create `README.md`. Modify `system_audit/CLAUDE.md` (replace the "Planned" content with the real commands and layout). Modify the parent `CLAUDE.md` (add a `system_audit/` row, but only after the user approves).

README sections, in this order:
1. What and why (the incident in one paragraph).
2. Threat model and its limits. A root-level attacker can blind this tool (`auditctl -D`, stopping the service). The rule-count health check and the canary make that *visible*, but they don't prevent it. Credentials stay out of the repo, and the reason is the secrets-file separation.
3. Gmail app password (2FA → myaccount.google.com/apppasswords).
4. Install per OS: `sudo pipx install --global`, and why the install has to be root-owned.
5. Config walkthrough (`/etc/credwatch/config.yaml`), the secrets file, and re-running `install` after new `.env` files appear.
6. Verifying: `status --probe`, `test-email`.
7. Data layout tree with one line per folder, plus a "triage a flagged alert" recipe: `report --flagged --last 2d --format json`, then the pcap covering that timestamp opened with `tshark -r … -Y 'ip.addr==X'`, then the matching `audit-exports/` file.
8. systemd system vs user service trade-off.
9. macOS limitations, stated plainly: needs root and Full Disk Access; reports thread ids, not pids, so attribution is best-effort; very high event volume; future macOS releases may restrict it further; less reliable than auditd. EndpointSecurity would be the robust alternative, but it needs a signed, entitled binary, which is out of scope.
10. The Debian AppArmor note, if Task 14 needed it.

- [ ] **Step 1:** Write both docs. **Step 2:** Check that every command in the README works on Debian. **Step 3:** `.venv/bin/pytest --cov=credwatch --cov-fail-under=80` → PASS. **Step 4:** Commit `docs(credwatch): README and CLAUDE.md`. Final PR, or fold it into PR 2.

---

## Spec coverage check

| Spec item | Task |
|---|---|
| §1 paths, env scan, configurable, re-runnable | 3, 13 |
| §2 backend ABC, Linux auditd (rules.d, augenrules, auditd enabled, multi-line parse) | 5, 6 |
| §2 macOS fs_usage | 15 |
| §3 correlate with psutil, exit race | 7 |
| §4 tcpdump rotation, capped retention | 8 |
| §5 SQLite events, snapshots, rollups, the 3 queries | 4 |
| §6 allowlist | 2 |
| §7 Gmail SMTP from env only, immediate alert, daily digest | 9, 10, 11 |
| §8 CLI install/run/status/report/test-email | 12, 13 |
| Data layout + audit-exports retention | 6, 11, 13 |
| Config YAML (everything but creds) | 1 |
| pyproject/pipx, systemd unit, launchd plist, README, .gitignore, examples | 1, 13, 15, 16 |
| Idempotent install, no silent failure, no new leak vector | 13, 11, 10, decisions table |
