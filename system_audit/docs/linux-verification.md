# credwatch: Linux verification runbook

Steps that need root or touch the real system. They are run by a human, not by the
automated dev loop. Run from the repo checkout: `cd handy-scripts` (the directory that
contains `system_audit/`). Expected output is indicative; versions and paths may differ.

## 1. Global pipx install and package-data check

```bash
sudo pipx install --global ./system_audit
```

Expected: `installed package credwatch 0.1.0, installed using Python 3.x` and
`These apps are now globally available: - credwatch`.

Verify the entry point and that the wheel carried `templates/*` (package-data check
deferred from Task 13):

```bash
which credwatch                       # /usr/local/bin/credwatch
sudo /opt/pipx/venvs/credwatch/bin/python - <<'PY'
from importlib.resources import files
names = sorted(p.name for p in (files("credwatch") / "templates").iterdir())
print(names)
assert {"credwatch.service", "config.example.yaml", "secrets.env.example"} <= set(names), names
PY
find /opt/pipx/venvs/credwatch/lib -path '*credwatch/templates/*'
```

Expected: the `print` shows `['config.example.yaml', 'credwatch.service', 'secrets.env.example']`
(the `*.yaml` template and the systemd unit), the assert passes, and `find` lists the same
three files. Every file under `src/credwatch/templates/` in the repo must appear:

```bash
diff <(ls system_audit/src/credwatch/templates) \
     <(ls /opt/pipx/venvs/credwatch/lib/python3*/site-packages/credwatch/templates)
```

Expected: no output. Any difference means `[tool.setuptools.package-data]` misses a file.
(If your pipx global home differs, find it with `pipx environment --global | grep PIPX_GLOBAL_HOME`.)

## 2. End-to-end test (real auditd, root)

The test needs pytest inside the credwatch venv:

```bash
sudo pipx inject --global credwatch pytest pyyaml
```

(`pyyaml` is already a dependency; the inject is then a no-op for it.) Run from the repo's
`system_audit/` directory so `tests/` resolves:

```bash
cd system_audit
sudo CREDWATCH_E2E=1 /opt/pipx/venvs/credwatch/bin/python -m pytest tests/test_e2e_linux.py -v -m e2e
```

Expected:

```
tests/test_e2e_linux.py::test_curl_reading_target_is_flagged_and_stored PASSED
tests/test_e2e_linux.py::test_e2e_canary_probe_ok PASSED
2 passed
```

Notes:
- First test setup waits up to 70 s for the daemon's own startup canary probe (normally
  about 6 s) before reading the target with `/usr/bin/curl`.
- Isolation: temp data dir under `/tmp/credwatch-e2e-*`, rules file
  `/etc/audit/rules.d/credwatch-e2e.rules` watching only temp files, and the hidden
  test-only flag `credwatch run --watch-list PATH` (not shown in `--help`) so the daemon
  does not read `/etc/credwatch/watched_paths.txt`. `/etc/credwatch` and
  `/var/lib/credwatch` are never touched.
- Teardown always stops the daemon, deletes the e2e rules file, runs `augenrules --load`
  and removes the temp dirs, even on failure. Confirm afterwards:
  `ls /etc/audit/rules.d/credwatch-e2e.rules` should say "No such file", and
  `sudo auditctl -l | grep e2e` should print nothing.
- Real credwatch rules and the e2e test cannot coexist (the audit key must stay
  `credwatch`, and rule counting would collide), so the test skips with "real credwatch
  audit rules are loaded" if `/etc/audit/rules.d/credwatch.rules` exists or any
  `-k credwatch` rule is loaded. Stopping the service does NOT unload the rules. If you
  have already run `credwatch install`, move the rules aside first and restore afterwards:

  ```bash
  sudo mv /etc/audit/rules.d/credwatch.rules /root/credwatch.rules.bak && sudo augenrules --load
  # (run the e2e command above)
  sudo mv /root/credwatch.rules.bak /etc/audit/rules.d/credwatch.rules && sudo augenrules --load && sudo credwatch status
  ```
- The e2e daemon gets an empty `--secrets-file` and no `CREDWATCH_SMTP_*` environment, so it
  never sends real mail.
- Persistent side effect: if auditd is not active, the test runs
  `systemctl enable --now auditd`, which starts it and enables it at boot. This is not
  undone by teardown.
- Without `CREDWATCH_E2E=1` or root the tests show as `skipped`.

## 3. Capture real audit lines to replace the hand-written fixtures (ruling R3)

```bash
touch /tmp/cw-probe
sudo auditctl -w /tmp/cw-probe -p rwa -k credwatch
cat /tmp/cw-probe
sleep 2
sudo ausearch -k credwatch --raw > fixture.log
sudo auditctl -W /tmp/cw-probe -p rwa -k credwatch
sudo chown "$USER" fixture.log
wc -l fixture.log
```

Expected: `fixture.log` has several lines per access: `type=SYSCALL ...`, `type=CWD`,
`type=PATH ... name="/tmp/cw-probe"`, sometimes `type=PROCTITLE`, all with
`key="credwatch"`. Check no real secrets leaked into it (paths, cmdlines) before
committing.

For the hex-encoded fixture, watch a directory containing a file whose name has a space:

```bash
mkdir -p "/tmp/cw probe" && echo x > "/tmp/cw probe/x"
sudo auditctl -w /tmp/cw\ probe -p rwa -k credwatch 2>/dev/null || sudo auditctl -w "/tmp/cw probe" -p rwa -k credwatch
cat "/tmp/cw probe/x"
sleep 2
sudo ausearch -k credwatch --raw > fixture-hex.log
sudo auditctl -W "/tmp/cw probe" -p rwa -k credwatch
sudo chown "$USER" fixture-hex.log
```

auditd hex-encodes `name=` values that contain spaces (`name=2F746D702F...`, unquoted).
Confirm the hex form appears in `fixture-hex.log` (`grep -E 'name=[0-9A-F]{8,}' fixture-hex.log`)
before using it as `audit_hex.log`. If `auditctl` rejects the spaced path, note that and
rely on a real log line from `/var/log/audit/audit.log` instead.

Swap them in and re-run the parser tests:

```bash
cp fixture.log system_audit/tests/fixtures/audit_enriched.log   # and audit_hex.log for the hex case
cd system_audit
.venv/bin/pytest tests/test_linux_audit_parser.py tests/test_linux_audit_backend.py -v
```

If an assertion pins values from the old hand-written lines (pid, timestamp, path,
exe), update the expected values to match the new file, or adjust the parser if a real
field format differs. Report any parser change as a bug fix with the real line quoted.

## 4. Real install

```bash
sudo credwatch install
```

Expected: a per-step install report (data dir and canary, config, audit rules, systemd
unit, service start) with no errors; re-running it reports everything unchanged. Then:

```bash
sudoedit /etc/credwatch/secrets.env       # set CREDWATCH_SMTP_USER and CREDWATCH_SMTP_PASSWORD
sudo credwatch test-email                 # expect "sent" and an email in the inbox
sudo credwatch status --probe             # expect the line `probe: ok (canary access recorded)` and exit 0 (on failure: `probe: FAILED (no event within N s)`, exit non-zero)
echo $?
sudo ls -l /var/lib/credwatch/captures    # a *.pcap file is present and its size grows
sleep 10; sudo ls -l /var/lib/credwatch/captures
```

(If `from_addr`/`to_addrs` are unset, edit `/etc/credwatch/config.yaml` first.)

Trigger a real alert:

```bash
/bin/cat ~/.aws/credentials > /dev/null    # use any existing watched file, e.g. ~/.ssh/id_ed25519
```

Expected within about a minute (coalescing window): an email "flagged" alert naming `cat`
and the path, with the network snapshot. Confirm in the store:

```bash
sudo credwatch report --last 10m --flagged --format table
```

Restart the service and re-check status afterwards:
`sudo systemctl restart credwatch && sudo credwatch status`.

## 5. AppArmor and tcpdump

Debian's `usr.bin.tcpdump` profile may block tcpdump (running as the `tcpdump` user)
from writing under `/var/lib/credwatch/captures`. Symptom: no pcap files, and a credwatch
health alert about the capture process.

```bash
sudo aa-status | grep tcpdump
journalctl -k | grep -i apparmor | grep tcpdump
```

Expected when blocked: `aa-status` lists `/usr/bin/tcpdump` in enforce mode, and the kernel
log shows `apparmor="DENIED" operation="mknod"` (or `open`) with
`profile="/usr/bin/tcpdump"` and `name="/var/lib/credwatch/captures/..."`.

Fix with a local override, not by disabling AppArmor:

```bash
echo '/var/lib/credwatch/captures/** rw,' | sudo tee -a /etc/apparmor.d/local/usr.bin.tcpdump
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.tcpdump
sudo systemctl restart credwatch
sudo ls -l /var/lib/credwatch/captures
```

Risk: this grants tcpdump (a network-facing parser of untrusted packets) write access to
that directory. It is scoped to the capture directory only, which is owned for the
capture user and holds nothing else. Do not widen it (for example to `/var/lib/**`), and
do not put the profile in complain mode or disable it.

## 6. Noisy allowlist candidates

After a day of normal desktop use:

```bash
sudo credwatch report --last 1d --format table
sudo credwatch report --last 1d --flagged --format table
```

Look for flagged rows from legitimate processes (for example GNOME daemons touching
`~/.ssh` or `~/.gnupg`: `gnome-keyring-daemon`, `gvfsd-*`, `gcr-ssh-agent`). Record them
and add entries to `allowlist` in `/etc/credwatch/config.yaml`, using the process name
(`comm`) and a path glob:

```yaml
allowlist:
  - path_pattern: "~/.ssh/**"
    processes: [ssh, git, gcr-ssh-agent]
```

Note that a user-supplied `allowlist` replaces the default list of the same key, so
copy the defaults you still want from `config.example.yaml`. Then
`sudo systemctl restart credwatch`. Only allow processes whose executable lives in a
trusted directory (`allowlist_trusted_dirs`). Send any entries that should be shipped as
defaults back to the repo as a change to `default_config_dict` in `config.py`.
