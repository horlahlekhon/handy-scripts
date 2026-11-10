#!/bin/bash
# SSH host aliases. Hosts live in a gitignored ssh_config file that install.sh
# Includes at the top of ~/.ssh/config, so `ssh <alias>`, scp, rsync, git and
# tab completion all work natively.
#
#   sshadd dev deploy@10.0.0.5                 add
#   sshadd prod ubuntu@1.2.3.4:2222 ~/.ssh/k   add with port + key
#   sshls                                      list
#   sshrm dev                                  remove
#   ssh dev                                    connect

: "${SSH_HOSTS_FILE:=${HANDY_SCRIPTS:-$HOME/workspace/personal/handy-scripts}/dot-files/customs/ssh_config}"

_ssh_has_alias() {
    [ -f "$SSH_HOSTS_FILE" ] && grep -qx "Host $1" "$SSH_HOSTS_FILE"
}

sshadd() {
    if [ $# -lt 2 ] || [ $# -gt 3 ]; then
        echo "usage: sshadd <alias> <user@host[:port]> [identity_file]" >&2
        return 1
    fi
    local alias="$1" target="$2" identity="${3:-}"

    if [[ ! "$alias" =~ ^[A-Za-z0-9._-]+$ ]]; then
        echo "sshadd: alias may only contain letters, digits, '.', '_' and '-'" >&2
        return 1
    fi
    if [[ ! "$target" =~ ^([^@[:space:]]+)@([^:@[:space:]]+)(:([0-9]+))?$ ]]; then
        echo "sshadd: target must look like user@host or user@host:port" >&2
        return 1
    fi
    local user="${BASH_REMATCH[1]}" host="${BASH_REMATCH[2]}" port="${BASH_REMATCH[4]}"

    if _ssh_has_alias "$alias"; then
        echo "sshadd: '$alias' already exists; sshrm $alias first" >&2
        return 1
    fi

    mkdir -p "$(dirname "$SSH_HOSTS_FILE")"
    {
        printf '\nHost %s\n  HostName %s\n  User %s\n' "$alias" "$host" "$user"
        [ -n "$port" ] && printf '  Port %s\n' "$port"
        [ -n "$identity" ] && printf '  IdentityFile %s\n  IdentitiesOnly yes\n' "$identity"
    } >> "$SSH_HOSTS_FILE"
    chmod 600 "$SSH_HOSTS_FILE"
    echo "added: ssh $alias -> $user@$host${port:+:$port}"
}

sshls() {
    [ -f "$SSH_HOSTS_FILE" ] || { echo "no hosts yet; add one with sshadd" >&2; return 0; }
    awk '
        function flush() {
            if (alias != "") printf "%-20s %s@%s%s\n", alias, user, host, (port ? ":" port : "")
            alias = user = host = port = ""
        }
        tolower($1) == "host"     { flush(); alias = $2 }
        tolower($1) == "hostname" { host = $2 }
        tolower($1) == "user"     { user = $2 }
        tolower($1) == "port"     { port = $2 }
        END { flush() }
    ' "$SSH_HOSTS_FILE"
}

sshrm() {
    if [ $# -ne 1 ]; then
        echo "usage: sshrm <alias>" >&2
        return 1
    fi
    if ! _ssh_has_alias "$1"; then
        echo "sshrm: no host '$1' in $SSH_HOSTS_FILE" >&2
        return 1
    fi
    local tmp
    tmp="$(mktemp)" || return 1
    awk -v target="$1" '
        tolower($1) == "host" || tolower($1) == "match" { skip = ($0 == "Host " target) }
        !skip
    ' "$SSH_HOSTS_FILE" > "$tmp" && mv "$tmp" "$SSH_HOSTS_FILE" && chmod 600 "$SSH_HOSTS_FILE"
    echo "removed: $1"
}
