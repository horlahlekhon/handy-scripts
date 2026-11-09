# credwatch: macOS verification runbook

**Status: none of this has been run on a Mac.** The macOS backend and installer were
built on Linux against a hand-written fixture (`tests/fixtures/fs_usage_sample.txt`) and
fakes. Each step below is for a human on a Mac. Record what actually happens, and fix
the code or this file where reality differs.

**What has been verified, and how.** Every parser and pipeline claim in this file is
covered by unit tests on Linux (`tests/test_macos_fsusage_*.py`) against the hand-written
fixture and synthetic lines. The daemon-path claims (prefilter → parser → events →
export) are tested by feeding lines through `MacFsUsageBackend.events()` with a fake
`Popen`, including a randomized test of attacker-chosen process names and path
spellings (`./`, `//`, `x/..`, case, NFD). **Not verified:** the real fs_usage column
layout and spacing, how it prints errno, renames, control characters and non-ASCII
names, tid vs pid, backpressure, and anything involving launchd, TCC or tcpdump. Those
are the checks below.

## Known gaps (read first)

The fs_usage backend is a stop-gap and much weaker than the Linux auditd backend:

- **Matching is lexical.** An access is caught only when fs_usage prints a path that
  matches a watched path after lexical normalisation: `./` and `x/..` segments and
  repeated slashes are removed (`os.path.normpath`, plus a leading `//`), the text is
  Unicode-normalised to NFC (APFS treats NFC and NFD spellings as one name), and case is
  ignored by Unicode canonical caseless matching (`NFD(casefold(NFD(...)))`). Nothing is
  resolved on disk at this stage. A line with a `/..` segment or non-ASCII text also gets
  the component-name fallback (see "Unparseable lines fail closed"), flagged.
- **Aliases are not detected.** Relative-path opens (`cd ~/.aws && cat credentials`, if
  fs_usage prints the relative name), symlink aliases (`ln -s ~/.aws/credentials /tmp/x`)
  and hard links (`ln ~/.aws/credentials /tmp/x; cat /tmp/x`) all read the secret under a
  path credwatch does not watch.
- **No inode verification.** fs_usage reports no inode/dev, so the correlator cannot
  confirm which file was actually opened, and the allowlist judges the lexical path (see
  "No inode/dev" below).
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
on macOS <version>, <date>"), and run `pytest tests/test_macos_fsusage_*.py`. Fix the
parser where the real format differs from these assumptions:

- columns: `HH:MM:SS.ffffff  op  F=fd|[errno]  (mode)  /path  elapsed  [W]  name.NNNN`;
- failed calls print `[ errno]` before the path. Check whether a space follows the
  closing bracket (`[ 13]  /path` or `[ 13]/path`): make a watched file unreadable and
  read it as your user (`chmod 000 ~/.netrc; cat ~/.netrc; chmod 600 ~/.netrc`). The
  parser accepts both forms; record which one fs_usage uses;
- paths with spaces are printed unquoted;
- long process names arrive truncated to 16 characters (the parser bounds the name to
  16 characters; a longer name makes the line fall back to "process unknown", flagged);
- the separator between the path and the elapsed-time column is **always at least two
  spaces**. This matters for attribution (see "Single-space ambiguity" below). Check it
  on the whole capture, including a very long path, which is where a padded column would
  shrink:

  ```bash
  cat "$HOME/$(printf './%.0s' $(seq 60)).netrc" > /dev/null   # long path to a watched file
  grep -nE '[^ ] [0-9]+\.[0-9]+( W)? +.*\.[0-9]+ *$' /tmp/fs.txt | head
  ```

  The grep lists lines where only one space precedes the elapsed column. It should print
  nothing (a path that itself contains ` <float> ` can show up; inspect any hit). If real
  lines appear, record it here: the single-space ambiguity is then real on your macOS;
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
swap the code the root daemon runs). Install into root-owned dirs, from a root-owned copy of the source (pip runs the build as
root; a user-writable tree would let a non-root user get code run as root):

```bash
sudo install -d -o root -g wheel -m 0755 /opt/credwatch-src \
  && sudo cp -a ./system_audit/. /opt/credwatch-src/ \
  && sudo chown -R root:wheel /opt/credwatch-src
sudo PIPX_GLOBAL_HOME=/opt/pipx PIPX_GLOBAL_BIN_DIR=/opt/pipx/bin \
     pipx install --global /opt/credwatch-src
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

Check that the daemon watches you, not root:

```bash
sudo plutil -p /Library/LaunchDaemons/com.credwatch.daemon.plist | grep -A1 '"--user"'  # your short name
```

With `darwin_trust_name_resolution: true`, also prove an allowed access is recorded as
`ok`: `ssh -T git@github.com`, then `sudo /opt/pipx/bin/credwatch report --last 5m
--process ssh`. Under the default (untrusted name resolution) it is expected to show
`FLAGGED`; see the limitations below.

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
  - Names are compared in NFC on both sides, using the name as fs_usage printed it. Two
    processes whose names are canonically equivalent (`café` in NFC and in NFD) are both
    candidates, so the lookup is ambiguous rather than a false unique match.
- **Prefilter.** fs_usage output is high-volume, so the daemon first drops every line
  that does not contain, in canonical caseless form `NFD(casefold(NFD(...)))`, the final
  component of some watched path (`.netrc`, `credentials`, `.ssh`, ...; for a watched
  directory its own name). Any spelling the parser below accepts (`./`, `//`, `x/..`,
  case, NFC/NFD, every case and composition spelling of Greek `ΐ`/`ΰ`) still contains
  that component, and the component fallback below keys on exactly those components, so
  the prefilter never drops a line the parser would report (tested by pushing randomized
  lines through the daemon's stream). Common names such as `config` let many unrelated
  lines through to the full parse; that costs CPU, not correctness (see "Backpressure").
- **Unparseable lines fail closed.** For a relevant op (open, rename, unlink, ...),
  credwatch NFC-normalises the line and searches it twice: for every `/`-starting path (at
  the start, after whitespace, or after `]`), normalised (`./`, `//`, `x/..`) and
  compared in canonical caseless form, and for every watched path as a substring. Every
  comparison (watch matcher, prefilter, substring search) uses one form,
  `NFD(casefold(NFD(...)))` (Unicode canonical caseless matching); the substring search
  builds it character by character with an offset map back to the line, so names that
  change length when folded (`ß`, `ǰ`, `ΐ`) cannot misalign it. Any watched path found
  produces an event. Then, if the line has a `/..` segment or any non-ASCII character,
  two more sources are merged in, deduplicated:
  - **component fallback:** every watched path whose final component occurs in the line
    *outside* the spans the exact searches matched, and that no already reported path
    lies at or below, is reported **as the watched path itself**. This catches
    `/Users/alice/x  y/../.netrc` (whitespace inside a component that `..` removes breaks
    both searches), a decoy in front of the target
    (`~/.aws/config  x/../../.ssh/id_rsa`, `~/.netrc x  y/../.ssh/id`, a rename whose
    destination hides behind `x  y/..`), and non-ASCII lines whose combining marks the
    per-character fold orders differently from the whole-string form;
  - **strict target:** when exact matches exist, the strict column parse's path (which
    resolves `..` itself), if it is watched and lies in a different watched root than
    every exact match (`~/.ssh/id_rsa` in the decoy example).

  If either source adds a path, every event from the line is "process unknown" and
  flagged, with the miss reason `unresolvable '..' path; attributed to watched path by
  component name` (or the non-ASCII variant). With nothing found the line is ignored.
  Otherwise the process name and tid are trusted only when the strict column parse
  yields exactly the single watched path found, at the same place, and the original
  (un-normalised) line gives the same name.tid; otherwise the event is "process unknown"
  and flagged, and a rate-limited WARNING `fs_usage parse miss` is logged. The process
  name is kept as printed (not NFC'd). Limits:
  - a path printed in a form neither search recognises (relative, or glued to a preceding
    path character) is missed, unless the line also has a `/..` segment or non-ASCII text
    and its final component occurs outside the matched spans. See "Known gaps";
  - the component fallback is by name, so it over-reports: `/opt/x/../config` gives
    flagged events for every watched path named `config`, and the reported path is the
    watched path (for a watched directory, the directory), not the file opened; any
    non-ASCII line naming e.g. `.netrc` outside a matched path is flagged too;
  - **wrong file, right root:** if the whitespace component sits *below* a watched
    directory (`~/.ssh/x  y/../id`), the exact search finds `~/.ssh/x`. The fallback and
    strict target add nothing (both are in `~/.ssh`), so the flagged event names the right
    watched directory but the wrong file;
  - **wrong root only if the component hides inside a match:** a target in another watched
    root is reported unless its final component occurs only inside a span the exact
    searches already matched (for example a path that walks *through* another watched
    path with `..`). The decoy is then still reported, flagged, so the line is never
    allowed, but the event can name only the decoy;
  - the strict target is the column parse's guess: with a hostile process name it can
    be a wrong file in the right root. It only ever adds flagged events;
  - a path under a watched directory that holds two consecutive spaces is reported only
    up to the double space;
  - **single-space ambiguity.** The cross-check extends a path across single spaces
    (paths may contain them) and stops at two. If fs_usage ever puts only one space
    between a path under a watched directory and the elapsed column, a process named
    `1.5 ssh` reading `~/.ssh/id` prints `.../.ssh/id 0.000010   1.5 ssh.42`, which is
    indistinguishable from `ssh` reading a file named `id 0.000010`. Both searches agree
    on that path, so the access is attributed to `ssh` (with a wrong path) instead of
    being flagged as "process unknown". It is still reported as an event, and `exe` is
    still unknown unless the tid is the pid or name trust is enabled. Exact watched files
    (not directories) are not affected. The step-1 spacing check decides whether this
    matters in practice. `test_single_space_before_elapsed_is_ambiguous_under_watched_dir`
    pins the behaviour.
- **No inode/dev; the allowlist judges the lexical path.** fs_usage reports no inode, so
  there is nothing to verify a canonical path against. The correlator stores the
  `realpath` result as `canonical_path` for the report, but the allowlist verdict uses
  the reported (lexical) path. A symlink `~/.ssh/x -> ~/.gnupg/secring` read by `git` is
  judged against the `~/.ssh/**` rule. With the default untrusted name resolution such
  events are flagged anyway (unknown exe); with `darwin_trust_name_resolution: true` this
  is a real gap. Linux verifies inode/dev and judges the canonical path.
- **Case-insensitive matching.** APFS is case-insensitive by default, so watched paths
  match case-insensitively. The reported path keeps the caller's case but is lexically
  normalised (`./`, `//`, `x/..` removed) and in NFC form; comparisons use the canonical
  caseless form; the event's `raw` and the
  export keep the line exactly as fs_usage printed it. An access via
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
