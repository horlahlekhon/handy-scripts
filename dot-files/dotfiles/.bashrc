#!/bin/bash
# Entry-point bashrc — source this from ~/.bashrc:
#   source "/path/to/handy-scripts/dot-files/dotfiles/.bashrc"
#
# Everything else is loaded relative to this file's location, so no
# hardcoded paths are needed inside this repo.

case $- in
    *i*) ;;
      *) return;;
esac

# Resolve this file's directory at source time
_DOTFILES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_HANDY_SCRIPTS="$(cd "$_DOTFILES_DIR/../.." && pwd)"

# ── History ────────────────────────────────────────────────────────────────────
HISTCONTROL=ignoreboth
shopt -s histappend
HISTSIZE=5000
HISTFILESIZE=10000

shopt -s checkwinsize

# ── Prompt ─────────────────────────────────────────────────────────────────────
case "$TERM" in
    xterm-color|*-256color) color_prompt=yes;;
esac

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        color_prompt=yes
    else
        color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

case "$TERM" in
    xterm*|rxvt*)
        PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
        ;;
esac

# ── Color support ──────────────────────────────────────────────────────────────
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

# ── Modular dotfiles ───────────────────────────────────────────────────────────
for _f in \
    "$_DOTFILES_DIR/.bash_vars" \
    "$_DOTFILES_DIR/.bash_aliases" \
    "$_DOTFILES_DIR/.bash_functions"; do
    [ -f "$_f" ] && source "$_f"
done

# ── Machine-local overrides (dot-files/customs/, not tracked) ─────────────────
_CUSTOMS_DIR="$_HANDY_SCRIPTS/dot-files/customs"
if [ -d "$_CUSTOMS_DIR" ]; then
    for _f in "$_CUSTOMS_DIR"/.*; do
        [ -f "$_f" ] && source "$_f"
    done
fi

unset _DOTFILES_DIR _HANDY_SCRIPTS _CUSTOMS_DIR _f

# ── Completions ────────────────────────────────────────────────────────────────
if ! shopt -oq posix; then
    if [ -f /usr/share/bash-completion/bash_completion ]; then
        . /usr/share/bash-completion/bash_completion
    elif [ -f /etc/bash_completion ]; then
        . /etc/bash_completion
    fi
fi

# ── PATH ───────────────────────────────────────────────────────────────────────
export PATH="$PATH:$HOME/.local/bin"

# ── Git prompt (if installed) ──────────────────────────────────────────────────
if [ -f "$HOME/.bash-git-prompt/gitprompt.sh" ]; then
    GIT_PROMPT_ONLY_IN_REPO=1
    source "$HOME/.bash-git-prompt/gitprompt.sh"
fi
