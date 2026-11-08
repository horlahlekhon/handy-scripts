# credwatch: macOS verification runbook

**Status: none of this has been run on a Mac.** The macOS backend and installer were
built on Linux against a hand-written fixture (`tests/fixtures/fs_usage_sample.txt`) and
fakes. Each step below is for a human on a Mac. Record what actually happens, and fix
the code or this file where reality differs.

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
- failed calls print `[ errno]` before the path;
- paths with spaces are printed unquoted;
- long process names arrive truncated to 16 characters.

## 2. Thread id vs pid

While step 1 runs, note the pid of the reading process (`cat` exits too fast; use
`python3 -c 'import os,time; print(os.getpid()); open(os.path.expanduser("~/.aws/credentials")).read(); time.sleep(30)'`).
Compare that pid with the trailing number on its fs_usage line.

- If they differ, the number is a thread id (the assumption in `resolve_pid`). Pid
  resolution then falls back to a name lookup.
- If they are equal, `resolve_pid` already prefers it. Note this in the fixture header.

## 3. `tcpdump -i any` vs `pktap,all`

```bash
sudo tcpdump -i any -c 5 -n
sudo tcpdump -i pktap,all -c 5 -n
```

The darwin default is `capture.interface: pktap,all`. If only `any` works on your macOS
version, change the darwin default in `config.py` and record the result here.

## 4. Install and Full Disk Access

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

If `launchctl bootstrap` fails with `5: Input/output error` right after the bootout,
re-run the install (launchd may not have finished removing the old job).

Grant **Full Disk Access** to the credwatch executable and to `/usr/bin/fs_usage`. Without
it, reads under `~/Library` and other TCC-protected paths may not be reported. Use System
Settings → Privacy & Security → Full Disk Access → `+`, and press ⌘⇧G to type the path.
Then `sudo launchctl kickstart -k system/com.credwatch.daemon`.

## 5. Probe

```bash
sudo /opt/pipx/bin/credwatch status --probe
```

Expected: `service: running`, `probe: ok (canary access recorded)`, exit code 0. If the
probe fails, check `/Library/Application Support/credwatch/logs/launchd.err.log` and the
Full Disk Access grants, then repeat. Record the actual outcome here.

## Known macOS limitations (by design)

- **Noisier alerts.** fs_usage gives only a process name and a thread id. credwatch fills
  `exe` through psutil only when it can resolve a single pid. Short-lived readers (`cat`)
  usually exit first, so `exe` is unknown and the allowlist **fails closed**: those events
  are flagged. Expect more flagged events than on Linux.
- **Name-based pid resolution can be wrong.** When the thread id is not a pid,
  credwatch picks the only live process with the same name. A malicious process named
  like an allowlisted tool (`ssh`) that exits quickly, while a real `/usr/bin/ssh` runs,
  can be attributed to the real one and be allowed. The candidates are recorded in the
  event's `raw` when the pick is ambiguous. Treat macOS verdicts as weaker than Linux ones.
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
