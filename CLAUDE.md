# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Repo Is

A personal collection of scripts for environment setup, server provisioning, dotfile management, and dev-tool wrappers. No build system — each subdirectory is an independent tool.

## Repository Layout

| Directory | Purpose |
|-----------|---------|
| `dot-files/` | Shell configs (`.bash_aliases`, zsh, tmux). Symlinked into `~` via `init.sh` |
| `shell-scripts/` | Standalone Bash utilities (pomodoro, Kafka/MongoDB setup, finance helpers) |
| `compose_projects/` | Ready-to-run Docker Compose stacks: MySQL 9.2, PostgreSQL 16 + Odyssey, Redis |
| `server_setup/` | Ansible playbook to provision a fresh Ubuntu VPS (Nginx, Certbot, Docker, sudo user) |
| `ansible-plays/` | One-off Ansible plays (e.g. Postgres replication lag monitoring) |
| `python_scripts/` | Python CLI tools (currently: `query_cloudwatch.py` — CloudWatch Logs viewer) |
| `claude-code/` | Claude Code plugin: skills, rules, MCP server configs, install script |

## Common Tasks

**Start a local database stack**
```bash
cd compose_projects/postgresql && docker compose up -d   # Postgres 16 + Odyssey pooler
cd compose_projects/mysql       && docker compose up -d   # MySQL 9.2
cd compose_projects/redis       && docker compose up -d   # Redis
```

**Query CloudWatch Logs**
```bash
cd python_scripts
pip install -r requirements.txt          # boto3 only
python query_cloudwatch.py /aws/lambda/my-fn --from 1h --search error
python query_cloudwatch.py /aws/lambda/my-fn --tail 50   # tail + follow
```

**Run the server provisioning playbook**
```bash
cd server_setup
# Edit vars.yml for target server_name / passwords before running
ansible-playbook -i hosts.ini setup.yml
```

**Bootstrap a new machine (zsh + dotfiles)**
```bash
./init.sh   # installs zsh, oh-my-zsh, copies dot-files to ~
```

## Key Conventions

- **Shell scripts** use `#!/bin/bash` with `set -e` in the longer ones (`server_config.sh`). New scripts should follow the same header style as `help_your_eyes.sh`.
- **Dotfile extensions**: add new aliases/functions to `dot-files/customs/.custom-bash_aliases` (or equivalent custom file) rather than editing the tracked dotfiles directly — `init.sh` loads the `customs/` directory automatically.
- **Ansible variables**: credentials and domain names live in `server_setup/vars.yml`. Keep plaintext passwords out of that file for shared repos; use `ansible-vault` instead.
- **Docker Compose stacks** all expose standard ports (5432, 6432, 3306, 6379) with named volumes for persistence. Default credentials for dev stacks are in each `docker-compose.yml`.
- **Python scripts** target Python 3, standard `argparse` CLI pattern, minimal deps (boto3 only so far).

## Sensitive Data Warning

`server_setup/vars.yml` currently contains a plaintext `sudo_user_password`. Do not commit real credentials there — use `ansible-vault encrypt_string` or a `.vault_pass` file excluded via `.gitignore`.
