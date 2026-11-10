# handy-scripts
This is a collection of handy scripts that i use to work everyday

## Dotfiles

```bash
./dot-files/install.sh   # adds `source dot-files/bashrc` to ~/.bashrc (idempotent)
```

SSH hosts (stored gitignored in `dot-files/customs/ssh_config`, Included at the top of `~/.ssh/config`):

```bash
sshadd dev deploy@10.0.0.5                    # then: ssh dev / scp f dev:/tmp / rsync ... dev:
sshadd prod ubuntu@1.2.3.4:2222 ~/.ssh/key    # port + identity file
sshls                                         # list
sshrm dev                                     # remove
```

Tests: `bash dot-files/tests/test_ssh.sh`

Machine-local additions go in `dot-files/customs/*.sh` (gitignored); they are sourced last.
Promote anything worth keeping into `dot-files/aliases.sh` or `dot-files/functions.sh`.
