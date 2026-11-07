# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Status

Pre-implementation. The only artifact is `prmpt.txt` — the full spec for **credwatch**. Read it before building anything; it is the source of truth. Update this file (commands, layout) once code lands.

## What credwatch Is

A persistent, cross-platform credential-file access monitor, built after a confirmed infostealer incident (2 AWS accounts + a GitHub PAT stolen from the Debian box). It watches sensitive credential files, flags access by non-allowlisted processes, snapshots the offending process's network connections, emails alerts, and keeps forensic history (SQLite + rotated pcaps + raw audit exports).

Targets: Debian/GNOME/systemd with auditd (primary), macOS/launchd with `fs_usage` (secondary, weaker guarantees — must be stated honestly in the README).

## Planned Architecture

Installable Python package (`pyproject.toml`, pipx-installed). Runtime deps limited to `psutil` and `PyYAML`; prefer stdlib otherwise. Modules, each independently testable:

| Module | Role |
|--------|------|
| `paths` | Per-OS watch list: fixed credential paths + recursive `.env*` scan (depth-capped, excludes node_modules/.git/venv/.venv). Only existing paths. Re-run on demand. |
| `backends` | Abstract event stream `(timestamp, path, pid, exe, ppid, success)`. Linux: writes `/etc/audit/rules.d/` rules (`-w <path> -p rwa -k credwatch`), `augenrules --load`, tails and parses multi-line SYSCALL/PATH/CWD groups from `/var/log/audit/audit.log`. macOS: parses `fs_usage -w -f filesys` stream. |
| `allowlist` | YAML path-glob → expected process basenames. Non-match = flagged. |
| `correlate` | On flagged event, immediately snapshot pid's connections via psutil. |
| `capture` | Always-on `tcpdump -i any` with time-based rotation and capped file count. |
| `store` | SQLite: all events, network snapshots, daily rollups; query helpers (last N days, by process, flagged only). |
| `alert` | Gmail SMTP (app password). Immediate email on flagged events + daily digest at configurable hour. |
| `cli` | `credwatch install | run | status | report --last <dur> | test-email` |

Flow: backend event → allowlist check → (if flagged) correlate → store → alert. Capture runs independently as a background rolling buffer.

Data dir (`~/.local/share/credwatch` on Linux, `~/Library/Application Support/credwatch` on macOS): `captures/`, `audit-exports/`, `logs/`, `events.db`.

## Hard Invariants

- **No credentials in the repo, ever.** SMTP creds come only from `CREDWATCH_SMTP_USER` / `CREDWATCH_SMTP_PASSWORD`, sourced from a gitignored secrets file (systemd `EnvironmentFile`, launchd equivalent). The tool must not become a new leak vector.
- **Process-exit races never crash the daemon** — catch `psutil.NoSuchProcess`/`AccessDenied`/`ZombieProcess` everywhere a pid is inspected.
- **`install` is idempotent** — re-running (e.g. after new `.env` files appear) must not duplicate audit rules or corrupt state.
- **Fail loudly** — log every failure; silent degradation defeats the tool's purpose as evidence.
- `.gitignore` must cover the secrets file, `*.db`, `captures/`, `logs/`, `audit-exports/`.

## Build Order (per spec)

Linux backend end-to-end → macOS backend → daemon loop, CLI, systemd unit + launchd plist, README, example `config.yaml` and secrets template.
