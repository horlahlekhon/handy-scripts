# credwatch: macOS verification runbook

**Status: none of this has been run on a Mac.** The macOS backend and installer were
built on Linux against a hand-written fixture (`tests/fixtures/fs_usage_sample.txt`) and
fakes. Each step below is for a human on a Mac. Record what actually happens, and fix
the code or this file where reality differs.

## Known gaps (read first)

The fs_usage backend is a stop-gap and much weaker than the Linux auditd backend:

- **Matching is lexical.** An access is caught only when fs_usage prints a path that
  string-matches a watched path, case-insensitively.
- **Aliases are not detected.** Relative-path opens (`cd ~/.aws && cat credentials`, if
  fs_usage prints the relative name), symlink aliases (`ln -s ~/.aws/credentials /tmp/x`)
  and hard links (`ln ~/.aws/credentials /tmp/x; cat /tmp/x`) all read the secret under a
  path credwatch does not watch.
- **No inode verification.** fs_usage reports no inode/dev, so the correlator cannot
  confirm which file was actually opened.
- **Process identity is weak.** See "Process attribution" below.

The recommended future backend is **eslogger** (macOS 13+, Endpoint Security). It reports
the real pid, audit token, executable and resolved file paths for each open.

## 1. Capture a real fs_usage fixture

```bash
sudo fs_usage -w -f filesys > /tmp/fs.txt &      # in terminal A
cat ~/.aws/credentials > /dev/null               # in terminal B (any watched file)
cat "/Library/Application Support/credwatch/canary" 2>/dev/null
sudo kill %1
grep -E 'aws/credentials|credwatch/canary' /tmp/fs.txt | head
```

Trim `/tmp/fs.txt` to about 50 lines around those accesses, keeping some `read`/`close`
lines on `F=` and some unrelated paths. Anonymise the user name. Replace
`tests/fixtures/fs_usage_sample.txt` with it, keep the `#` header (update it to "captured
on macOS <version>, <date>"), and run `pytest tests/test_macos_fsusage.py`. Fix the
parser where the real format differs from these assumptions:

- columns: `HH:MM:SS.ffffff  op  F=fd|[errno]  (mode)  /path  elapsed  [W]  name.NNNN`;
- failed calls print `[ errno]` before the path. Check whether a space follows the
  closing bracket (`[ 13]  /path` or `[ 13]/path`): make a watched file unreadable and
  read it as your user (`chmod 000 ~/.netrc; cat ~/.netrc; chmod 600 ~/.netrc`). The
  parser accepts both forms; record which one fs_usage uses;
- paths with spaces are printed unquoted;
- long process names arrive truncated to 16 characters (the parser bounds the name to
  16 characters; a longer name makes the line fall back to "process unknown", flagged);
- `rename`/`renameat` print one path or two (old and new). Rename a watched file and look
  at the line. Two-path lines are handled: credwatch searches the line for every watched
  path and emits **one flagged event per watched path** (source and/or destination), with
  the process marked unknown, because the column split cannot be trusted. Check that a
  real rename produces these events;
- attacker-chosen process names: a name containing a float, ` W `, or characters that
  change length under casefold (`ß`, `ﬁ`, `İ`) can shift the column split. credwatch
  cross-checks the parsed path against its own search for watched paths, and on
  disagreement reports the watched path as a flagged "process unknown" event. Confirm
  with binaries named like `a 1.1 b` and `ß 2.5 ssh` reading a watched file;
- control characters in process names: run a process whose name contains a newline or CR
  (`cp /bin/cat "/tmp/a$(printf '\r')b"` and run it on a watched file). Check whether
  fs_usage escapes the character or prints it raw. A raw CR/LF splits the line; credwatch
  then flags the access as "process unknown" and logs `fs_usage parse miss` at WARNING.

## 2. Thread id vs pid

While step 1 runs, note the pid of the reading process (`cat` exits too fast; use
`python3 -c 'import os,time; print(os.getpid()); open(os.path.expanduser("~/.aws/credentials")).read(); time.sleep(30)'`).
Compare that pid with the trailing number on its fs_usage line.

- If they differ, the number is a thread id (the assumption in `resolve_pid`). Pid
  resolution then falls back to a name lookup.
- If they are equal, `resolve_pid` already prefers it. Note this in the fixture header.

## 3. Backpressure

Events are processed inline on the thread that reads fs_usage's stdout: each match does a
psutil process scan and then a correlation. If that work falls behind fs_usage's output
rate (for example `find ~ -name '*.env'` or an IDE indexing your home directory),
fs_usage's pipe fills and fs_usage itself may stall or drop events. Run such a workload
with credwatch active and watch:

- `sudo credwatch status` (heartbeat, "no fs_usage output for 60 s");
- whether fs_usage prints dropped-event warnings to stderr (they show up in the
  `fs_usage exited` health message and in `launchd.err.log`);
- whether the canary probe still passes during the load.

If it falls behind, move the matching off the reader thread (bounded queue) before relying
on macOS.

## 4. `tcpdump -i any` vs `pktap,all`

```bash
sudo tcpdump -i any -c 5 -n
sudo tcpdump -i pktap,all -c 5 -n
```

The darwin default is `capture.interface: pktap,all`. If only `any` works on your macOS
version, change the darwin default in `config.py` and record the result here.

## 5. Install and Full Disk Access

`pipx install --global` puts the entry point in `/usr/local/bin`. On Intel Macs Homebrew
makes that directory user-owned, so `credwatch install` refuses it (a non-root user could
swap the code the root daemon runs). Install into root-owned dirs:

```bash
sudo PIPX_GLOBAL_HOME=/opt/pipx PIPX_GLOBAL_BIN_DIR=/opt/pipx/bin \
     pipx install --global ./system_audit
sudo /opt/pipx/bin/credwatch install
```

Expected: `created:` lines for `/private/etc/credwatch`, the config and secrets files,
`/Library/Application Support/credwatch` and its subdirectories, the canary, the watch
list, and `plist /Library/LaunchDaemons/com.credwatch.daemon.plist`. Run it a second time:
everything should show `unchanged:`, and the daemon is reloaded (bootout, then bootstrap).

If `launchctl bootstrap` returns `5: Input/output error` right after the bootout, the
installer retries once after 1 s (launchd may not have finished removing the old job).
If the retry fails too, re-run the install.

Grant **Full Disk Access** to the credwatch executable and to `/usr/bin/fs_usage`. Without
it, reads under `~/Library` and other TCC-protected paths may not be reported. Use System
Settings → Privacy & Security → Full Disk Access → `+`, and press ⌘⇧G to type the path.
Then `sudo launchctl kickstart -k system/com.credwatch.daemon`.

## 6. Probe

```bash
sudo /opt/pipx/bin/credwatch status --probe
```

Expected: `service: running`, `probe: ok (canary access recorded)`, exit code 0. If the
probe fails, check `/Library/Application Support/credwatch/logs/launchd.err.log` and the
Full Disk Access grants, then repeat. Record the actual outcome here.

## Known macOS limitations (by design)

- **Process attribution; macOS flags nearly everything by default.** fs_usage gives only
  a process name and a thread id. `exe` is trusted only when the thread id is itself a
  live pid whose name matches, which is rare. Otherwise credwatch can only look the pid up
  by name, and a name is spoofable: a malicious process named `ssh` that exits quickly
  while a real `/usr/bin/ssh` runs would be attributed to the real binary. So by default a
  name-only exe is recorded in the event's `raw` (`exe resolved by name only: ...`), but
  `exe` stays unknown and the allowlist **fails closed**: the event is flagged. Expect
  most macOS events to be flagged.
  - Set `darwin_trust_name_resolution: true` in the config to accept name-only exes.
    Alerts get quieter, but an attacker who can pick a process name can get allowed.
  - Ambiguous names (several live processes) and processes that have already exited
    always leave `exe` unknown. The candidate pids are recorded in `raw`.
- **Unparseable lines fail closed.** For a relevant op (open, rename, unlink, ...),
  credwatch searches the whole line twice: for every `/`-starting path (at the start,
  after whitespace, or after `]`), normalised (`./`, `//`) and case-folded, and for every
  watched path as a substring (case-folded with an offset map, so non-ASCII names cannot
  misalign it). Any watched path found produces an event; the line is ignored only when
  neither search finds one. The process name and tid are trusted only when the strict
  column parse yields exactly that watched path; otherwise the event is "process unknown"
  and flagged, and a rate-limited WARNING `fs_usage parse miss` is logged. Limits:
  - a path printed in a form neither search recognises (relative, or glued to a preceding
    path character) is still missed. See "Known gaps";
  - a path under a watched directory that holds two consecutive spaces is reported only
    up to the double space.
- **No inode/dev.** fs_usage reports no inode, so the correlator verifies by lexical path
  (canonicalised with `realpath`) only, which is weaker than the Linux inode check.
- **Case-insensitive matching.** APFS is case-insensitive by default, so watched paths
  match case-insensitively. The reported path keeps the caller's spelling. An access via
  `~/.AWS/Credentials` is caught but does not match the lower-case allowlist patterns, so
  it is flagged.
- **`status` backend health.** fs_usage runs inside the daemon, so the `status` command
  cannot see it directly. It relies on the daemon heartbeat and `--probe`. Inside the
  daemon, health reports `fs_usage exited (rc=N)` and `no fs_usage output for 60 s`.
- **data_dir under /etc, /var or /tmp is refused.** These are symlinks into `/private`,
  and the installer refuses symlinked ancestors. Keep the default
  `/Library/Application Support/credwatch`. Only the config dir is mapped to
  `/private/etc/credwatch`.
- **Native export.** Matched raw fs_usage lines are appended to
  `<data_dir>/audit-exports/fs_usage-YYYYmmdd.log` (0600, symlinks refused) as events
  arrive. The export job reports that day's file.
