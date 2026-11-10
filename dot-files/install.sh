#!/bin/bash
# Hook the dotfiles into ~/.bashrc and ~/.ssh/config. Safe to run repeatedly.
set -euo pipefail

DOTFILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASHRC="${BASHRC:-$HOME/.bashrc}"
SSH_CONFIG="${SSH_CONFIG:-$HOME/.ssh/config}"
SSH_HOSTS="$DOTFILES_DIR/customs/ssh_config"

install_bashrc() {
    local line="[ -f \"$DOTFILES_DIR/bashrc\" ] && source \"$DOTFILES_DIR/bashrc\""
    touch "$BASHRC"
    if grep -qF "$DOTFILES_DIR/bashrc" "$BASHRC"; then
        echo "bashrc: already installed in $BASHRC"
        return
    fi
    printf '\n# handy-scripts dotfiles\n%s\n' "$line" >> "$BASHRC"
    echo "bashrc: installed into $BASHRC"
}

# Include must come before any Host block to apply globally, and ssh uses the
# first match, so hosts added with sshadd override older entries below.
install_ssh() {
    mkdir -p "$(dirname "$SSH_CONFIG")" && chmod 700 "$(dirname "$SSH_CONFIG")"
    touch "$SSH_HOSTS" "$SSH_CONFIG"
    chmod 600 "$SSH_HOSTS"
    if grep -qF "Include $SSH_HOSTS" "$SSH_CONFIG"; then
        echo "ssh: already installed in $SSH_CONFIG"
        return
    fi
    local backup="$SSH_CONFIG.bak.$(date +%Y%m%d%H%M%S)"
    cp -p "$SSH_CONFIG" "$backup"
    { printf '# handy-scripts ssh hosts (manage with sshadd / sshls / sshrm)\nInclude %s\n\n' "$SSH_HOSTS"
      cat "$backup"; } > "$SSH_CONFIG"
    chmod 600 "$SSH_CONFIG"
    echo "ssh: Include added to $SSH_CONFIG (backup: $backup)"
}

mkdir -p "$DOTFILES_DIR/customs"
install_bashrc
install_ssh
echo "done; run: source $BASHRC"
