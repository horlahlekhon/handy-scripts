# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What credwatch Is

A persistent, cross-platform credential-file access monitor, built after a confirmed infostealer incident (2 AWS accounts + a GitHub PAT stolen from the Debian box). It watches sensitive credential files, flags access by non-allowlisted processes, snapshots the offending process's network connections, emails alerts, and keeps forensic history (SQLite + rotated pcaps + raw audit exports).

Targets: Debian/GNOME/systemd with auditd (primary), macOS/launchd with `fs_usage` (secondary, weaker guarantees, stated honestly in the README). `prmpt.txt` is the original spec. `README.md` is the user-facing doc; `docs/linux-verification.md` and `docs/macos-verification.md` are human-run runbooks (nothing has been run on a real Mac; real auditd e2e is unverified).

## Dev Commands

```bash
cd system_audit
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'      # once
.venv/bin/pytest -q                                              # all tests
.venv/bin/pytest tests/test_allowlist.py::test_name -v           # single test
.venv/bin/pytest -q --cov=credwatch --cov-fail-under=80          # coverage gate (80% line)
python3.11 -c "import ast,pathlib,sys; [ast.parse(p.read_text(), str(p)) for d in ('src','tests') for p in pathlib.Path(d).rglob('*.py')]; print('py311 ok')"   # 3.11 syntax sweep
CREDWATCH_E2E=1 sudo -E .venv/bin/python -m pytest tests/test_e2e_linux.py -v -m e2e   # opt-in, root, real auditd
```

The e2e test skips itself if real credwatch audit rules are loaded (key stays `credwatch`); run it before `credwatch install` or move the rules aside. Tests never need root otherwise: every external command goes through the injectable `credwatch.proc.Runner`.

## Module Map (`src/credwatch/`)

| Module | Role |
|--------|------|
| `cli` | argparse: `run`, `status [--probe]`, `report`, `test-email`, `install`. `--config/--user/--secrets-file` accepted before and after the subcommand. |
| `config` | Frozen config dataclasses, OS-aware defaults, YAML load + strict validation (unknown keys and credential keys rejected). |
| `platform_info` | OS detection, target-user resolution, `/etc/credwatch` paths, root-owned default data dir. |
| `paths` | Default sensitive paths, `.env*` scan, `WatchMatcher`, watch-list file I/O. |
| `models` | Frozen `FileAccessEvent`, `NetworkSnapshot`, `Verdict`, `ProcessedEvent`. |
| `allowlist` | Path glob -> process patterns with trusted-dir / root-owned-chain checks. |
| `correlate` | Canonicalise path (inode/dev verified), allowlist verdict, psutil network snapshot + ancestry. |
| `backends/` | `base` ABC; `linux_audit` (rules render/install, parser, `LinuxAuditBackend`, health rule count, native export); `macos_fsusage` (fs_usage parser, pid resolution, `MacFsUsageBackend`). |
| `store` | SQLite events, snapshots, rollups, meta, query helpers; hardened open. |
| `safe_fs` | `open_dir_chain`: no-follow, ownership-checked directory walk. |
| `capture` | tcpdump supervisor with rotation, capped retention, drop-privileges. |
| `retention` | `prune_old_files`. |
| `tail` | Rotation-aware file follower. |
| `alert` | Credentials loading, `Mailer`, `AlertCoalescer`, retrying `AlertDispatcher`. |
| `messages` | Alert/digest/health email formatting with untrusted-text escaping. |
| `daemon` | Event loop: backend -> correlate -> store -> alert; heartbeat, canary probe, health checks (per-source dedup), export, daily digest. |
| `installer/` | `common` (root-owned install check, no-follow dirs, config/secrets bootstrap), `linux` (rules, systemd unit), `macos` (plist via plistlib). |
| `logging_setup`, `proc` | Rotating log config; `Runner` protocol + `SubprocessRunner`. |
| `templates/` | `credwatch.service`, `config.example.yaml`, `secrets.env.example` (package-data). |

Flow: backend event -> correlate (canonical path, allowlist) -> store -> (flagged) coalesce -> email. Capture runs independently as a rolling buffer.

## Hard Invariants (as implemented)

- **Root-owned everything.** Config/secrets in `/etc/credwatch` (0700/0600); data dir `/var/lib/credwatch` (macOS `/Library/Application Support/credwatch`), never under `~`. Directory creation goes through `safe_fs`/installer no-follow walks; the store opens its DB with `O_NOFOLLOW`. `install` refuses a code location (entry point, interpreter, prefix, package) that is not root-owned.
- **No credentials in the repo, ever.** SMTP creds only from `CREDWATCH_SMTP_USER` / `CREDWATCH_SMTP_PASSWORD` (env or `secrets.env`); config rejects credential keys; never logged, echoed or stored. `.gitignore` covers the secrets file, `*.db`, `captures/`, `logs/`, `audit-exports/`.
- **Fail closed on identity.** Unknown exe -> flagged. Basename allowlist matches only count for root-owned exes in trusted dirs; absolute-path patterns are the escape hatch. `comm` is never matched. Linux canonical paths must match the event inode/dev, else "unverified" -> flagged. macOS name-only exe resolution is untrusted unless `darwin_trust_name_resolution`.
- **Untrusted text everywhere.** Paths, exe, cmdline and hostnames are escaped (Cc/Cf/Zl/Zp/Cs) in emails, CLI output and CSV; subjects are stripped; paths with control characters are never written into audit rules.
- **Audit key is exactly `credwatch`; rule format is `-w <path> -p rwa -k credwatch`.** Data dir subfolders are exactly `captures/`, `audit-exports/`, `logs/`, plus `events.db`.
- **Process-exit races never crash the daemon.** Every pid-taking psutil call catches `NoSuchProcess`/`AccessDenied`/`ZombieProcess` and records the outcome.
- **No silent failure.** Every swallowed exception is logged (`logger.exception` or WARNING+); no bare `except: pass`. Health problems are emailed with per-source 6 h dedup; the hourly canary and rule-count check make a blinded backend visible.
- **`install` is idempotent**: files rewritten only when content differs, loaded rule count verified and repaired, service restarted.
- **Immutability.** Value types are `@dataclass(frozen=True)` with tuples for collections.
- **Python >=3.11**; runtime deps only `psutil` and `PyYAML`.
- tcpdump drops to `capture.drop_privileges_to` (`tcpdump` on Linux, `root` on macOS).
