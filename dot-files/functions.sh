#!/bin/bash
# Shell functions. Sourced by dot-files/bashrc.
# Never call `exit` in here: these run in the interactive shell and would close it.

# cd, then list the directory
cd() {
    builtin cd "${@:-$HOME}" && ls -F
}

# show what is listening on a port: port 8080
port() {
    if [ -z "$1" ]; then
        echo "usage: port <number>" >&2
        return 1
    fi
    if [[ "$(uname -s)" == "Darwin" ]]; then
        lsof -nP -iTCP:"$1" -sTCP:LISTEN
    else
        sudo ss -ltnup | grep -E ":$1\b"
    fi
}

# total size of a directory: dsize ~/Downloads
dsize() {
    du -sh "${1:-.}"
}

# start (or create) a throwaway dev Postgres on :5432
# override with PG_CONTAINER / PG_IMAGE / PG_PASSWORD
some_postgres() {
    local name="${PG_CONTAINER:-some-postgres}"
    local image="${PG_IMAGE:-postgres:16}"
    local password="${PG_PASSWORD:-admin}"

    if docker container inspect "$name" >/dev/null 2>&1; then
        docker start "$name" >/dev/null || return 1
        echo "started existing container '$name'"
        return 0
    fi

    docker run -d --name "$name" -e POSTGRES_PASSWORD="$password" \
        -p 5432:5432 "$image" >/dev/null || return 1
    echo "created '$name' ($image): postgres://postgres:$password@localhost:5432/postgres"
}

# CloudWatch Logs viewer: cloudwatch /ecs/my-svc --from 1h --search error
cloudwatch() {
    python3 "$HANDY_SCRIPTS/python_scripts/query_cloudwatch.py" "$@"
}
