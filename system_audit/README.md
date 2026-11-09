# credwatch

A root-run monitor that watches credential files (`~/.ssh`, `~/.aws`, `.env*` files and
more), flags reads by processes that are not on an allowlist, snapshots the offender's
network connections, emails you, and keeps forensic history (SQLite events, rotated
pcaps, raw audit exports).

Primary target: Debian/GNOME/systemd with auditd. Secondary: macOS/launchd with
`fs_usage`, which is much weaker (see [macOS limitations](#macos-limitations)).

## What and why

This was built after a confirmed infostealer incident on a Debian workstation: it read
credentials for two AWS accounts and a GitHub personal access token, and nothing noticed
until the keys were abused. credwatch exists to make the next read of those files loud
and attributable: which process, which executable, which parent chain, which network
connections at that instant, and a pcap covering the time window.

## Threat model and its limits

**Defended against:** user-level malware (an infostealer running as your user) reading
credential files. credwatch runs as root, reads the kernel audit stream (Linux), and
keeps its code, config, secrets and evidence in root-owned locations that user-level
code cannot rewrite.

**Not defended against: root-level malware.** An attacker with root can run
`auditctl -D`, stop the service, edit the config or fill the disk. credwatch cannot
prevent that. It makes it *visible*:

- **Rule-count health check (Linux only).** Every 5 minutes the daemon compares the number of loaded
  `credwatch` audit rules with what it expects (`auditctl -l`). A mismatch (for example
  after `auditctl -D`) raises a health alert by email.
- **Canary probe.** Every hour the daemon reads a canary file in its own data dir and
  waits up to 60 s for the matching audit event. No event means the audit pipeline is
  blind, and a health alert is emailed. `sudo credwatch status --probe` runs the same
  check on demand. The canary holds nothing sensitive, so reads of it (by the daemon or by
  `status --probe`) are recorded as allowed `credwatch-canary` events: visible in reports,
  never alerted. The exemption is by file identity (inode and device, from the kernel on
  Linux), not by path string, and only while the canary is a regular file with one link.
- **Heartbeat.** `status` reports a stale or missing daemon heartbeat (older than 180 s).
- Health alerts are de-duplicated per source (`health`, `canary`, `backend`): an
  identical problem set is not re-sent for 6 hours, and a cleared problem resets its
  source. Flagged-access alerts are coalesced per process: the first event is sent
  immediately, further events from the same process within `email.coalesce_seconds`
  arrive as one batched email.

These detect a blinded monitor only if an email can still leave the host and you notice
its absence; a root attacker can also block mail. Treat the hourly canary as tamper
evidence, not tamper prevention.

**Credentials stay out of the repo, and that is the reason the secrets file is separate.**
The tool must not become a new leak vector. SMTP credentials are read only from
`CREDWATCH_SMTP_USER` / `CREDWATCH_SMTP_PASSWORD` in `/etc/credwatch/secrets.env`
(root, mode 0600). The config file rejects credential-looking keys, credentials are never
logged, echoed or written to the DB, and `.gitignore` excludes the secrets file, `*.db`,
`captures/`, `logs/` and `audit-exports/`.

### Allowlist semantics

An access is "allowed" only if a rule's path glob matches and its process pattern
matches. Process matching is deliberately strict:

- A **basename** pattern (`ssh`, `python3*`) counts only if the process executable lives
  in a trusted directory (`allowlist_trusted_dirs`), its whole directory chain is
  root-owned and not group/other-writable, and the executable file itself is uid 0 and
  not other-writable. Otherwise a stealer could copy itself to `~/.cache/x/ssh`.
- A pattern starting with `/` matches the **full executable path**. This is the escape
  hatch for user-installed tools (`/home/you/.local/bin/aws`).
- If the executable is unknown (exited before inspection, unreadable), the event is
  **always flagged**. `comm` is recorded but never matched; it is spoofable.
- On Linux the audit path is lexical, so the correlator resolves it and accepts the
  canonical path only if its inode and device match what the kernel reported (R23).
  A symlink alias such as `~/.aws/link -> ~/.ssh/id_rsa` cannot borrow the `~/.aws`
  allowlist; unverifiable events are flagged and stored as "UNVERIFIED".
- A deleted executable (`... (deleted)`) is flagged on purpose.

**Decision for you: the default `~/.aws/**` rule allows `python3*`**, because the spec
lists python/boto3 as legitimate readers. That also means a Python-based stealer running
from `/usr/bin/python3` reading `~/.aws/credentials` is *allowed*: it is stored and shown
in the daily digest, but not emailed immediately. If you do not use boto3 scripts,
tighten it by overriding `allowlist` (see below) and removing `python3*`.

## Gmail app password

Alerts go through Gmail SMTP (`smtp.gmail.com:587`, STARTTLS). Use an app password, never
your account password.

1. Turn on 2-Step Verification: <https://myaccount.google.com/security>.
2. Open <https://myaccount.google.com/apppasswords>, create an app password named
   `credwatch`, and copy the 16-character value.
3. Put it in `/etc/credwatch/secrets.env` (see [Secrets file](#secrets-file)).

## Install

credwatch is a Python package (`>=3.11`, deps `psutil`, `PyYAML`). The install itself
must be **root-owned**: the daemon runs as root, so if a normal user could modify the
interpreter, the package or the entry point, that user (or malware running as them) could
get code executed as root. `credwatch install` therefore refuses to configure a service
whose entry point, interpreter, install prefix or package directory (or any ancestor) is
not root-owned or is writable by others. A plain `pipx install` into `~/.local` fails
that check by design.

Install from a root-owned copy of the source, not your own checkout: pip runs the build
as root, and a user-writable tree would let a non-root user get code run as root.

### Debian / Linux

```bash
sudo apt install pipx auditd tcpdump          # auditd provides auditctl/augenrules
sudo install -d -o root -g root -m 0755 /opt/credwatch-src \
  && sudo cp -a ./system_audit/. /opt/credwatch-src/ \
  && sudo chown -R root:root /opt/credwatch-src   # run from the repo root
sudo pipx install --global /opt/credwatch-src  # venv in /opt/pipx
sudo credwatch install                        # config, dirs, audit rules, systemd unit, start
sudoedit /etc/credwatch/secrets.env           # set the Gmail address and app password
sudoedit /etc/credwatch/config.yaml           # set email.from_addr and email.to_addrs
sudo systemctl restart credwatch
```

`install` as root with `sudo` targets the invoking user (`SUDO_USER`) for home-directory
paths; pass `--user NAME` to override. It writes that user into the service as
`run ... --user NAME` (systemd `ExecStart`, launchd `ProgramArguments`), because a service
has no `SUDO_USER`. The name must exist and be a plain login name (no whitespace or
control characters). `run` and `install` refuse to start when the target user resolves to
root without an explicit `--user root` ("target user resolved to root; pass --user
<name> (re-run credwatch install)"), so a unit missing `--user` fails loudly instead of
watching root's home and flagging every read. It is idempotent: rules are rewritten only if
content changes, the loaded rule count is always verified (and reloaded if wrong), and
the service is restarted so config edits apply.

The Linux service runs `credwatch run` as a root **system** service (see
[systemd trade-off](#systemd-system-vs-user-service)). `tcpdump` is started with
`-Z tcpdump`, so packet parsing runs as the unprivileged `tcpdump` user and `captures/`
is owned by it. Debian's AppArmor profile may block that; see
[Debian AppArmor note](#debian-apparmor-note).

### macOS

```bash
brew install pipx
sudo install -d -o root -g wheel -m 0755 /opt/credwatch-src \
  && sudo cp -a ./system_audit/. /opt/credwatch-src/ \
  && sudo chown -R root:wheel /opt/credwatch-src
sudo PIPX_GLOBAL_HOME=/opt/pipx PIPX_GLOBAL_BIN_DIR=/opt/pipx/bin \
     pipx install --global /opt/credwatch-src
sudo /opt/pipx/bin/credwatch install
sudoedit /private/etc/credwatch/secrets.env
```

`/private/etc/credwatch` is `/etc/credwatch`. The default `pipx --global` location
(`/usr/local/bin`) is user-owned on Intel Homebrew installs and `install` will refuse
it, hence the `/opt/pipx` form. The installer writes
`/Library/LaunchDaemons/com.credwatch.daemon.plist` (`RunAtLoad`, `KeepAlive`); launchd
has no `EnvironmentFile`, so the plist passes `--secrets-file /etc/credwatch/secrets.env`
instead. Grant **Full Disk Access** to the credwatch executable and `/usr/bin/fs_usage`.
Walk through [docs/macos-verification.md](docs/macos-verification.md) before relying on it.

## Configuration

Config lives at `/etc/credwatch/config.yaml` (root-owned, created from the example on
first `install`; the repo holds only [config.example.yaml](config.example.yaml)). Any
key you omit keeps its default; mappings are deep-merged over the defaults. Unknown keys
and out-of-range values are rejected at startup with `<dotted.key>: <reason>`.

**Where things live.** The data dir is **root-owned**: `/var/lib/credwatch` on Linux,
`/Library/Application Support/credwatch` on macOS, *not* under your home. A root daemon
writing evidence under a user-owned home can be redirected by user-level malware (swap a
directory for a symlink and root writes where the attacker chooses), and the evidence
there is attacker-writable. The installer and the daemon walk the data-dir path with
no-follow checks and refuse symlinked or user-writable ancestors. On macOS do not point
`data_dir` under `/etc`, `/var` or `/tmp` (symlinks into `/private`).

### Config keys

| Key | Default | Notes |
|-----|---------|-------|
| `data_dir` | `/var/lib/credwatch` (Linux), `/Library/Application Support/credwatch` (macOS) | absolute path, root-owned |
| `extra_paths` | `[]` | additional files/dirs to watch (`~` expands to the target user's home) |
| `env_scan.roots` | `["~"]` | where to look for `.env*` files |
| `env_scan.max_depth` | `4` | integer, `>= 0` |
| `env_scan.excludes` | `[node_modules, .git, venv, .venv]` | directory names skipped |
| `allowlist` | built-in list below | list of `{path_pattern, processes}`; setting it **replaces** the defaults (the canary rule is always appended) |
| `allowlist_trusted_dirs` | Linux: `/usr/bin /usr/sbin /usr/libexec /usr/lib /bin /sbin /usr/local/bin /opt/pipx /snap/bin`; macOS: `/usr/bin /usr/sbin /usr/libexec /bin /sbin /System /opt/pipx` | dirs where a basename allowlist match is honoured (also needs the root-owned chain check) |
| `capture.enabled` | `true` | run `tcpdump` |
| `capture.interface` | `any` (Linux), `pktap,all` (macOS) | passed to `tcpdump -i` |
| `capture.rotate_seconds` | `3600` | pcap rotation period, `>= 1` |
| `capture.retain_files` | `168` | rotated pcaps kept (a week at hourly rotation), `>= 1` |
| `capture.snaplen` | `0` | `0` = full packets |
| `capture.drop_privileges_to` | `tcpdump` (Linux), `root` (macOS) | user for `tcpdump -Z`; macOS has no standard capture user, so tcpdump stays root there |
| `email.smtp_host` | `smtp.gmail.com` | |
| `email.smtp_port` | `587` | `1`-`65535` |
| `email.from_addr` | `""` | **set this** |
| `email.to_addrs` | `[]` | **set this** (list) |
| `email.digest_hour` | `8` | local hour `0`-`23` for the daily digest |
| `email.send_immediately` | `true` | email flagged events as they happen |
| `email.coalesce_seconds` | `60` | per-process batching window for flagged alerts, `>= 0` |
| `audit_export.interval_minutes` | `60` | how often the native audit log is exported |
| `audit_export.retention_days` | `30` | age limit for files in `audit-exports/` |
| `darwin_trust_name_resolution` | `false` | macOS only; see [macOS limitations](#macos-limitations) |

**Default allowlist** (`~` is the target user's home; patterns are segment-aware globs,
`/**` matches a subtree):

| Path | Processes |
|------|-----------|
| `~/.ssh/**` | ssh, git, seahorse, nautilus, gnome-keyring-daemon, scp, sftp, rsync |
| `~/.aws/**` | aws, **python3\***, terraform |
| `~/.config/gh/**` | gh, git |
| `~/.gnupg/**` | gpg, gpg-agent, gpgsm |
| `~/.docker/**` | docker, docker-credential-\* |
| `~/.kube/**` | kubectl, helm, k9s |

Example override that drops `python3*` and allows a user-installed `aws`:

```yaml
allowlist:
  - path_pattern: "~/.aws/**"
    processes: [aws, terraform, /home/you/.local/bin/aws]
```

Because `allowlist` replaces the defaults, repeat any other rules you still want.

**Watched paths** are the fixed credential files (`~/.aws/credentials`, `~/.aws/config`,
`~/.ssh`, `~/.config/gh/hosts.yml`, gcloud, docker, kube, npm, pypi, netrc, gnupg, 1Password
CLI, terraform, azure, doctl), plus `extra_paths`, plus `.env*` files found under
`env_scan.roots`. Only existing paths are watched. The resolved list is stored in
`/etc/credwatch/watched_paths.txt`. Paths containing whitespace or control characters
cannot be watched by auditd; `install` prints them as `skipped:`.

## Secrets file

`/etc/credwatch/secrets.env` (root, 0600), created from
[secrets.env.example](secrets.env.example) on first `install`:

```
CREDWATCH_SMTP_USER=you@gmail.com
CREDWATCH_SMTP_PASSWORD=abcdefghijklmnop
```

systemd reads it through `EnvironmentFile=`; launchd through `--secrets-file`. The same
variables in the environment also work, which is handy for `test-email` in a one-off
shell. If credentials are missing at daemon start, monitoring continues and the problem
is logged and shown by `status` (`last alert error`).

## Re-running install after adding `.env` files

New `.env*` files are only watched after the watch list is regenerated:

```bash
sudo credwatch install
```

Safe to repeat: existing files are reported `unchanged:`, audit rules are not
duplicated, the rule count is verified, and the service restarts. Use `--no-start` to
skip the (re)start.

## Verifying

```bash
sudo credwatch status              # service, backend health, heartbeat, event counts, captures
sudo credwatch status --probe      # also reads the canary and waits up to 15 s for its event
sudo credwatch test-email          # sends a real test message with the configured credentials
```

`status` exits 0 when healthy and 1 when degraded (backend problem, stale heartbeat, or a
failed probe). A healthy probe prints `probe: ok (canary access recorded)`. `status`,
`report` and `run` require root.

Reports:

```bash
sudo credwatch report --last 24h --flagged                    # durations: 30m 12h 7d 2w
sudo credwatch report --last 7d --process ssh --format csv    # --format table|json|csv
sudo credwatch report --last 2d --flagged --format json --output /root/flagged.json
```

`--output` writes mode 0600 and refuses to follow a symlink. CSV cells that start with
`=`, `+`, `-` or `@` are prefixed with `'` to defuse spreadsheet formulas.

The global options `--config PATH`, `--user NAME` and `--secrets-file PATH`, and `-v`
(before the subcommand), are accepted by every command.

## Data layout

```
/etc/credwatch/                 root 0700 (macOS: /private/etc/credwatch)
  config.yaml                   your settings (0600)
  secrets.env                   SMTP credentials (0600)
  watched_paths.txt             the resolved watch list
/var/lib/credwatch/             data_dir, root-owned (0711 when captures/ belongs to the tcpdump user)
  events.db                     SQLite: every event, network snapshots, daily rollups
  canary                        file the health probe reads
  captures/                     rolling tcpdump pcaps, credwatch-YYYYmmdd-HHMMSS.pcap
  audit-exports/                ausearch-*.txt raw auditd exports (macOS: fs_usage-YYYYmmdd.log)
    .checkpoint                 ausearch checkpoint, so exports don't repeat events
  logs/                         credwatch.log (macOS also launchd.out.log, launchd.err.log)
```

### Triage a flagged alert

1. List what was flagged and note the timestamp, pid, exe and remote addresses:

   ```bash
   sudo credwatch report --flagged --last 2d --format json
   ```

   Each event carries `snapshot.connections` (taken at detection time) and
   `snapshot.ancestry` (parent chain with command lines). `canonical_path: null` with an
   `inode` means the path could not be verified and was flagged fail-closed.
2. Open the pcap covering that time and filter on the remote address:

   ```bash
   sudo ls -l /var/lib/credwatch/captures
   sudo tshark -r /var/lib/credwatch/captures/credwatch-<stamp>.pcap -Y 'ip.addr==203.0.113.9'
   ```

   Pick the file whose start stamp is at or before the event time (rotation is hourly by
   default).
3. Match the raw audit records in `audit-exports/` for the same timestamp or pid:

   ```bash
   sudo grep -l 'pid=<pid>' /var/lib/credwatch/audit-exports/ausearch-*.txt        # Linux
   sudo grep -l '<pid>' "/Library/Application Support/credwatch/audit-exports/"fs_usage-*.log   # macOS
   ```
4. Rotate every credential the process could have read (assume the worst), then clean up.

## systemd system vs user service

credwatch runs as a **system** unit (`/etc/systemd/system/credwatch.service`,
`WantedBy=multi-user.target`, `Restart=on-failure`, `EnvironmentFile=/etc/credwatch/secrets.env`).

- *System service (chosen).* Needed to read the audit log, load audit rules, run tcpdump
  and keep root-owned evidence. It starts at boot before any login, so there is no
  window where your session is up and the monitor is not. The cost: it holds root, so
  the install and config must be locked down (which is why they are root-owned).
- *User service (`systemctl --user`).* Would run as you, so it could not read the audit
  log or load rules without sudo/capabilities, and the process, its config and its
  evidence would sit in a place user-level malware can kill, edit or replace. Using one
  would defeat the threat model.

## macOS limitations

Stated plainly: the macOS backend is a stop-gap and much weaker than Linux.

- Needs root and **Full Disk Access** for the credwatch executable and `fs_usage`;
  without it, reads under TCC-protected locations may go unreported.
- `fs_usage` reports a process **name and a thread id**, not a pid. Attribution is
  best-effort. By default an exe resolved only by name is recorded as evidence but not
  trusted, so the allowlist fails closed and **most macOS events are flagged**. Setting
  `darwin_trust_name_resolution: true` accepts name-only resolution and quiets the
  alerts, but an attacker who can choose a process name can then get allowed.
- **Matching is lexical.** Relative-path opens, symlink aliases and hard links that read
  a watched file under another name are not detected, and there is no inode check.
  fs_usage cannot close this gap. The future backend should be **`eslogger`** (macOS 13+,
  Endpoint Security): real pid, audit token, executable and resolved paths. EndpointSecurity
  proper needs a signed, entitled binary, which is out of scope here.
- Very high event volume (the daemon prefilters lines; events are processed on the reader
  thread, so a flood can make `fs_usage` stall). Future macOS releases may restrict
  `fs_usage` further.
- `tcpdump` stays root (no standard capture user), and the interface default is
  `pktap,all`.
- No health signal from the backend itself; rely on the heartbeat and `status --probe`.

Details and the full list of known gaps: [docs/macos-verification.md](docs/macos-verification.md)
("Known gaps" and "Known macOS limitations").

## Debian AppArmor note

Debian's `usr.bin.tcpdump` AppArmor profile can stop tcpdump (running as the `tcpdump`
user) from writing to `/var/lib/credwatch/captures`: no pcaps appear and credwatch
raises a capture health alert. The scoped local override and its risk are in
[docs/linux-verification.md](docs/linux-verification.md), section 5.

## Verification runbooks

- [docs/linux-verification.md](docs/linux-verification.md): real-host Linux steps.
- [docs/macos-verification.md](docs/macos-verification.md): real-host macOS steps.

## What has NOT been verified on real hosts

All development and the automated suite ran on Linux against fakes and hand-written
fixtures. In particular:

- **Real auditd end to end.** The parser fixtures are hand-written in Debian's enriched
  format, not captured. The opt-in e2e test (`CREDWATCH_E2E=1`, root,
  `tests/test_e2e_linux.py`) and the runbook steps for `sudo credwatch install`, a real
  alert email, the canary probe and the AppArmor interaction have not been run on a real
  host.
- **The real Mac.** Nothing in the macOS backend or installer has run on macOS: real
  fs_usage column layout, errno and rename formats, tid-vs-pid, backpressure, launchd,
  TCC and tcpdump all remain to be checked with the runbook.
- **The wheel package-data check.** That `templates/*` is included in an installed wheel
  (the `pip`/`pipx` install, as opposed to the editable dev install) has not been
  confirmed; step 1 of the Linux runbook does it.

## Development

See [CLAUDE.md](CLAUDE.md) for the dev loop and module map.
