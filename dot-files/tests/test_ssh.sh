#!/bin/bash
# Tests for dot-files/ssh.sh. Run: bash dot-files/tests/test_ssh.sh
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export SSH_HOSTS_FILE="$TMP/ssh_config"
source "$HERE/../ssh.sh"

PASS=0
FAIL=0
check() {  # check <description> <command...>
    local desc="$1"; shift
    if "$@" >/dev/null 2>&1; then
        PASS=$((PASS + 1))
    else
        FAIL=$((FAIL + 1))
        echo "FAIL: $desc"
    fi
}
resolves() {  # resolves <alias> <key> <expected>
    ssh -F "$SSH_HOSTS_FILE" -G "$1" | grep -qix "$2 $3"
}
fails() { ! "$@"; }

# add: basic
check "adds host" sshadd dev deploy@10.0.0.5
check "dev hostname" resolves dev hostname 10.0.0.5
check "dev user" resolves dev user deploy

# add: port and identity file
check "adds host with port+key" sshadd prod ubuntu@203.0.113.9:2222 ~/.ssh/prod_key
check "prod port" resolves prod port 2222
check "prod key" resolves prod identityfile "$HOME/.ssh/prod_key"

# add: validation
check "rejects duplicate alias" fails sshadd dev other@10.0.0.6
check "duplicate did not change dev" resolves dev hostname 10.0.0.5
check "rejects alias with space" fails sshadd "bad alias" u@h
check "rejects wildcard alias" fails sshadd "web*" u@h
check "rejects missing user" fails sshadd box 10.0.0.7
check "rejects missing args" fails sshadd
check "rejects non-numeric port" fails sshadd box u@h:abc

# list
out="$(sshls)"
check "ls shows dev" grep -Eq '^dev +deploy@10\.0\.0\.5' <<<"$out"
check "ls shows prod port" grep -Eq '^prod +ubuntu@203\.0\.113\.9:2222' <<<"$out"

# remove
check "removes host" sshrm dev
check "dev gone from ls" fails grep -q '^dev ' <<<"$(sshls)"
check "prod still resolves" resolves prod hostname 203.0.113.9
check "rm unknown alias fails" fails sshrm nope

echo "passed: $PASS, failed: $FAIL"
[ "$FAIL" -eq 0 ]
