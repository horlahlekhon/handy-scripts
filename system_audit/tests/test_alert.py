import logging
import os
import smtplib
import ssl
import threading
from datetime import datetime, timezone
from pathlib import Path

import pytest

from credwatch.alert import (
    AlertCoalescer,
    AlertDispatcher,
    CredentialsError,
    Mailer,
    MailerError,
    QUEUE_MAX,
    SmtpCredentials,
    load_credentials,
    parse_env_file,
)
from credwatch.config import EmailConfig
from credwatch.models import FileAccessEvent, ProcessedEvent, Verdict

USER_VAR = "CREDWATCH_SMTP_USER"
PASS_VAR = "CREDWATCH_SMTP_PASSWORD"
SECRET = "s3cr3t-pw-XYZ"


def _cfg(**kw):
    base = dict(
        smtp_host="smtp.example.com", smtp_port=587, from_addr="cw@example.com",
        to_addrs=("ops@example.com",), digest_hour=8, send_immediately=True,
        coalesce_seconds=60,
    )
    return EmailConfig(**{**base, **kw})


def _pe(exe="/usr/bin/curl", comm="curl", path="/home/u/.ssh/id_rsa"):
    ev = FileAccessEvent(
        timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc), path=path, pid=1,
        ppid=0, exe=exe, comm=comm, success=True, backend="t", raw="",
    )
    return ProcessedEvent(event=ev, verdict=Verdict(False, None), snapshot=None)


# ---- credentials ----

def test_env_overrides_secrets_file(tmp_path):
    f = tmp_path / "s.env"
    f.write_text(f"{USER_VAR}=fileuser\n{PASS_VAR}=filepw\n")
    f.chmod(0o600)
    creds = load_credentials({USER_VAR: "envuser", PASS_VAR: "envpw"}, f)
    assert (creds.user, creds.password) == ("envuser", "envpw")


def test_file_used_when_env_missing(tmp_path):
    f = tmp_path / "s.env"
    f.write_text(f"export {USER_VAR}='fu'\n{PASS_VAR}=\"fp\"\nOTHER=x\n")
    f.chmod(0o600)
    creds = load_credentials({}, f)
    assert (creds.user, creds.password) == ("fu", "fp")


def test_missing_password_error_names_var_not_value():
    with pytest.raises(CredentialsError) as ei:
        load_credentials({USER_VAR: "uniq-user-value"}, None)
    assert PASS_VAR in str(ei.value)
    assert "uniq-user-value" not in str(ei.value)


def test_placeholder_value_rejected():
    with pytest.raises(CredentialsError) as ei:
        load_credentials({USER_VAR: "u", PASS_VAR: "REPLACE_ME"}, None)
    assert PASS_VAR in str(ei.value)


def test_credentials_repr_masks_password():
    c = SmtpCredentials("u", SECRET)
    assert SECRET not in repr(c)
    assert SECRET not in str(c)
    assert "u" in repr(c)


def test_world_readable_secrets_file_warns(tmp_path, caplog):
    f = tmp_path / "s.env"
    f.write_text(f"{USER_VAR}=u\n{PASS_VAR}=p\n")
    f.chmod(0o644)
    with caplog.at_level(logging.WARNING):
        load_credentials({}, f)
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_symlink_secrets_file_refused(tmp_path):
    real = tmp_path / "real.env"
    real.write_text(f"{USER_VAR}=u\n{PASS_VAR}=p\n")
    real.chmod(0o600)
    link = tmp_path / "link.env"
    link.symlink_to(real)
    with pytest.raises(CredentialsError, match="symlink"):
        load_credentials({}, link)


def test_non_regular_secrets_file_refused(tmp_path):
    with pytest.raises(CredentialsError, match="regular"):
        load_credentials({}, tmp_path)


def test_secrets_file_wrong_owner_refused(tmp_path, monkeypatch):
    f = tmp_path / "s.env"
    f.write_text(f"{USER_VAR}=u\n{PASS_VAR}=p\n")
    f.chmod(0o600)
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(f).st_uid + 4242)
    if os.stat(f).st_uid == 0:
        pytest.skip("owned by root")
    with pytest.raises(CredentialsError, match="owned"):
        load_credentials({}, f)


def test_missing_secrets_file_errors(tmp_path):
    with pytest.raises(CredentialsError):
        load_credentials({}, tmp_path / "nope.env")


def test_parse_env_file_handles_comments_quotes_export():
    text = "# c\n\nexport A=1\nB='two words'\nC=\"x\"\nbad line\n D = 4 \n"
    assert parse_env_file(text) == {"A": "1", "B": "two words", "C": "x", "D": "4"}


# ---- mailer ----

class FakeSMTP:
    instances: list = []

    def __init__(self, host, port, timeout=None, starttls_ok=True, login_exc=None):
        self.calls = [("init", host, port, timeout)]
        self.starttls_ok = starttls_ok
        self.login_exc = login_exc
        self.sent = []
        FakeSMTP.instances.append(self)

    def ehlo(self):
        self.calls.append(("ehlo",))

    def has_extn(self, name):
        return self.starttls_ok and name == "starttls"

    def starttls(self, context=None):
        assert isinstance(context, ssl.SSLContext)
        self.calls.append(("starttls",))

    def login(self, u, p):
        self.calls.append(("login", u))
        if self.login_exc:
            raise self.login_exc

    def send_message(self, msg):
        self.calls.append(("send",))
        self.sent.append(msg)

    def quit(self):
        self.calls.append(("quit",))

    def close(self):
        self.calls.append(("close",))


@pytest.fixture(autouse=True)
def _reset_fake():
    FakeSMTP.instances = []


def test_mailer_uses_starttls_and_login():
    m = Mailer(_cfg(), SmtpCredentials("u", "p"), smtp_factory=FakeSMTP)
    m.send("subj", "body")
    smtp = FakeSMTP.instances[0]
    names = [c[0] for c in smtp.calls]
    assert names == ["init", "ehlo", "starttls", "ehlo", "login", "send", "quit"]
    assert smtp.calls[0] == ("init", "smtp.example.com", 587, 30)
    msg = smtp.sent[0]
    assert msg["To"] == "ops@example.com"
    assert msg["From"] == "cw@example.com"
    assert msg["Subject"] == "subj"


def test_mailer_from_defaults_to_user():
    m = Mailer(_cfg(from_addr=""), SmtpCredentials("me@x.com", "p"), smtp_factory=FakeSMTP)
    m.send("s", "b")
    assert FakeSMTP.instances[0].sent[0]["From"] == "me@x.com"


def test_empty_to_addrs_rejected():
    with pytest.raises(CredentialsError, match="email.to_addrs is empty"):
        Mailer(_cfg(to_addrs=()), SmtpCredentials("u", "p"))


def test_refuses_without_starttls():
    def factory(h, p, timeout=None):
        return FakeSMTP(h, p, timeout, starttls_ok=False)

    m = Mailer(_cfg(), SmtpCredentials("u", "p"), smtp_factory=factory)
    with pytest.raises(MailerError, match="STARTTLS"):
        m.send("s", "b")
    smtp = FakeSMTP.instances[0]
    assert not smtp.sent
    assert ("login", "u") not in smtp.calls


def test_subject_newlines_sanitised():
    m = Mailer(_cfg(), SmtpCredentials("u", "p"), smtp_factory=FakeSMTP)
    m.send("a\r\nBcc: evil@x.com", "b")
    assert "\n" not in FakeSMTP.instances[0].sent[0]["Subject"]
    assert FakeSMTP.instances[0].sent[0]["Bcc"] is None


# ---- coalescer ----

def test_sweep_of_40_files_yields_one_immediate_and_one_batch():
    c = AlertCoalescer(60)
    now = 1000.0
    results = [c.add(_pe(path=f"/f{i}"), now + i * 0.05) for i in range(40)]
    assert results[0] is not None and len(results[0]) == 1
    assert all(r is None for r in results[1:])
    assert c.drain_due(now + 30) == []
    batches = c.drain_due(now + 61)
    assert len(batches) == 1 and len(batches[0]) == 39
    assert c.drain_due(now + 200) == []


def test_distinct_keys_each_send_immediately():
    c = AlertCoalescer(60)
    assert c.add(_pe(exe="/usr/bin/a"), 0) is not None
    assert c.add(_pe(exe="/opt/b"), 0) is not None
    assert c.add(_pe(exe=None, comm="zed"), 0) is not None
    assert c.add(_pe(exe=None, comm="zed"), 1) is None
    assert c.add(_pe(exe=None, comm=None), 0) is not None
    assert c.add(_pe(exe=None, comm=None), 1) is None


def test_new_window_after_expiry_keeps_old_batch():
    c = AlertCoalescer(60)
    c.add(_pe(), 0)
    c.add(_pe(), 1)
    assert c.add(_pe(), 100) is not None  # new window, immediate
    batches = c.drain_due(100)
    assert [len(b) for b in batches] == [1]
    assert c.drain_due(200) == []


def test_window_with_only_first_event_leaves_no_batch():
    c = AlertCoalescer(60)
    c.add(_pe(), 0)
    assert c.drain_due(61) == []
    assert c.add(_pe(), 62) is not None


# ---- dispatcher ----

class _Mailer:
    def __init__(self, fail_times=0, exc=None):
        self.fail_times = fail_times
        self.exc = exc or OSError("boom")
        self.sent = []

    def send(self, subject, body):
        if self.fail_times > 0:
            self.fail_times -= 1
            raise self.exc
        self.sent.append((subject, body))


def _dispatcher(mailer, errors, sleeps):
    return AlertDispatcher(lambda: mailer, "host1", errors.append, sleep=sleeps.append)


def test_dispatcher_sends_message():
    mailer, errors, sleeps = _Mailer(), [], []
    d = _dispatcher(mailer, errors, sleeps)
    d.start()
    d.submit("s", "b")
    d.stop(timeout=5)
    assert mailer.sent == [("s", "b")]
    assert errors == [] and sleeps == []


def test_dispatcher_retries_then_succeeds():
    mailer, errors, sleeps = _Mailer(fail_times=2), [], []
    d = _dispatcher(mailer, errors, sleeps)
    d.start()
    d.submit("s", "b")
    d.stop(timeout=5)
    assert len(mailer.sent) == 1
    assert sleeps == [5, 30]
    assert errors == []


def test_dispatcher_retries_then_reports_error():
    mailer, errors, sleeps = _Mailer(fail_times=99), [], []
    d = _dispatcher(mailer, errors, sleeps)
    d.start()
    d.submit("subject-x", "b")
    d.stop(timeout=5)
    assert mailer.sent == []
    assert sleeps == [5, 30]
    assert len(errors) == 1
    assert "subject-x" in errors[0]


def test_auth_failure_log_has_no_password(caplog):
    exc = smtplib.SMTPAuthenticationError(535, b"5.7.8 bad credentials")
    errors, sleeps = [], []
    creds = SmtpCredentials("u", SECRET)

    def factory():
        return Mailer(_cfg(), creds, smtp_factory=lambda h, p, timeout=None: FakeSMTP(
            h, p, timeout, login_exc=exc))

    d = AlertDispatcher(factory, "host1", errors.append, sleep=sleeps.append)
    with caplog.at_level(logging.DEBUG):
        d.start()
        d.submit("s", "b")
        d.stop(timeout=5)
    assert len(errors) == 1
    assert sleeps == []
    assert len([r for r in caplog.records if r.levelno >= logging.WARNING]) == 1
    assert len(FakeSMTP.instances) == 1
    assert SECRET not in caplog.text
    assert all(SECRET not in e for e in errors)
    assert "535" in caplog.text
    assert "SMTPAuthenticationError" in caplog.text or "authentication" in caplog.text


def test_full_queue_drops_oldest_and_reports_count(caplog):
    mailer, errors, sleeps = _Mailer(), [], []
    d = _dispatcher(mailer, errors, sleeps)
    with caplog.at_level(logging.ERROR):
        for i in range(1003):  # not started: nothing consumes
            d.submit(f"s{i}", "b")
    assert any(r.levelno == logging.ERROR for r in caplog.records)
    d.start()
    d.stop(timeout=10)
    assert len(mailer.sent) == 1000
    assert mailer.sent[0][0] == "s3"
    assert "3 alerts dropped" in mailer.sent[0][1]
    assert all("dropped" not in b for _, b in mailer.sent[1:])


def test_stop_logs_abandoned_pending(caplog):
    gate = threading.Event()
    started = threading.Event()

    class Slow:
        def send(self, subject, body):
            started.set()
            gate.wait(5)

    d = AlertDispatcher(lambda: Slow(), "h", lambda m: None, sleep=lambda s: None)
    d.start()
    d.submit("one", "b")
    assert started.wait(2) is True
    d.submit("two", "b")
    with caplog.at_level(logging.ERROR):
        d.stop(timeout=0.2)
    gate.set()
    text = caplog.text.lower()
    assert "abandon" in text
    assert "one" in text and "two" in text


def test_surrogate_in_body_still_sends(caplog):
    m = Mailer(_cfg(), SmtpCredentials("u", "p"), smtp_factory=FakeSMTP)
    with caplog.at_level(logging.WARNING):
        m.send("subj \udcff", "cmdline: bad\udcffbyte")
    assert len(FakeSMTP.instances) == 1
    sent = FakeSMTP.instances[0].sent[0]
    assert "\\udcff" in sent.get_content()
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_quit_oserror_does_not_resend(caplog):
    class QuitFails(FakeSMTP):
        def quit(self):
            raise OSError("connection reset")

    m = Mailer(_cfg(), SmtpCredentials("u", "p"), smtp_factory=QuitFails)
    errors, sleeps = [], []
    d = AlertDispatcher(lambda: m, "h", errors.append, sleep=sleeps.append)
    with caplog.at_level(logging.WARNING):
        d.start()
        d.submit("s", "b")
        d.stop(timeout=5)
    assert len(FakeSMTP.instances) == 1
    assert len(FakeSMTP.instances[0].sent) == 1
    assert errors == [] and sleeps == []
    assert "quit failed" in caplog.text


def test_unicode_error_from_send_is_not_retried():
    class SendFails(FakeSMTP):
        def send_message(self, msg):
            raise UnicodeEncodeError("ascii", "x", 0, 1, "boom")

    m = Mailer(_cfg(), SmtpCredentials("u", "p"), smtp_factory=SendFails)
    with pytest.raises(UnicodeError):
        m.send("s", "b")
    assert len(FakeSMTP.instances) == 1


def test_message_has_date_and_message_id():
    m = Mailer(_cfg(), SmtpCredentials("u", "p"), smtp_factory=FakeSMTP)
    m.send("s", "b")
    msg = FakeSMTP.instances[0].sent[0]
    assert msg["Date"] and msg["Message-ID"].startswith("<")


def test_submit_after_stop_logs_error(caplog):
    mailer, errors, sleeps = _Mailer(), [], []
    d = _dispatcher(mailer, errors, sleeps)
    d.start()
    d.stop(timeout=5)
    with caplog.at_level(logging.ERROR):
        d.submit("late-subject", "b")
    assert "alert submitted after dispatcher stop; not sent: late-subject" in caplog.text
    assert mailer.sent == []


def test_stop_logs_pending_dropped_count(caplog):
    d = _dispatcher(_Mailer(), [], [])
    for i in range(QUEUE_MAX + 2):
        d.submit(f"s{i}", "b")
    with caplog.at_level(logging.ERROR):
        d.stop(timeout=1)  # never started
    assert "2 alert(s) were dropped" in caplog.text
