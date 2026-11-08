"""Credentials, SMTP delivery, alert coalescing and the retrying dispatcher."""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
import stat
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path
from typing import Callable, Mapping

from credwatch.config import EmailConfig
from credwatch.models import ProcessedEvent

logger = logging.getLogger(__name__)

USER_VAR = "CREDWATCH_SMTP_USER"
PASSWORD_VAR = "CREDWATCH_SMTP_PASSWORD"
PLACEHOLDER = "REPLACE_ME"
SMTP_TIMEOUT_SECONDS = 30
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (5, 30)
QUEUE_MAX = 1000
UNKNOWN_KEY = "unknown"


class CredentialsError(Exception):
    """Credentials or mail configuration unusable. Never contains secret values."""


class MailerError(Exception):
    """Mail delivery refused or failed; message is safe to log."""


class AuthenticationFailed(MailerError):
    """SMTP login rejected; retrying cannot help."""


@dataclass(frozen=True)
class SmtpCredentials:
    user: str
    password: str = field(repr=False)

    def __repr__(self) -> str:
        return f"SmtpCredentials(user={self.user!r}, password='***')"

    __str__ = __repr__


def parse_env_file(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export ") or line.startswith("export\t"):
            line = line[len("export"):].strip()
        key, sep, value = line.partition("=")
        key = key.strip()
        if not sep or not key:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        out[key] = value
    return out


def _read_secrets_file(path: Path) -> dict[str, str]:
    try:
        st = os.lstat(path)
    except OSError as exc:
        raise CredentialsError(f"cannot stat secrets file {path}: {exc.strerror}") from None
    if stat.S_ISLNK(st.st_mode):
        raise CredentialsError(f"secrets file {path} is a symlink; refusing")
    if not stat.S_ISREG(st.st_mode):
        raise CredentialsError(f"secrets file {path} is not a regular file")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise CredentialsError(f"cannot open secrets file {path}: {exc.strerror}") from None
    with os.fdopen(fd, "rb") as fh:
        fst = os.fstat(fh.fileno())
        if not stat.S_ISREG(fst.st_mode):
            raise CredentialsError(f"secrets file {path} is not a regular file")
        if fst.st_uid not in (0, os.geteuid()):
            raise CredentialsError(
                f"secrets file {path} is not owned by root or the current user"
            )
        if fst.st_mode & (stat.S_IRGRP | stat.S_IROTH):
            logger.warning(
                "secrets file %s is group- or world-readable (mode %o); chmod 600",
                path, stat.S_IMODE(fst.st_mode),
            )
        try:
            text = fh.read().decode("utf-8")
        except UnicodeDecodeError:
            raise CredentialsError(f"secrets file {path} is not valid UTF-8") from None
    return parse_env_file(text)


def load_credentials(
    environ: Mapping[str, str], secrets_file: Path | None
) -> SmtpCredentials:
    values = {k: environ.get(k, "") for k in (USER_VAR, PASSWORD_VAR)}
    if secrets_file is not None and not all(values.values()):
        file_vals = _read_secrets_file(Path(secrets_file))
        values = {k: v or file_vals.get(k, "") for k, v in values.items()}
    for var in (USER_VAR, PASSWORD_VAR):
        if not values[var]:
            raise CredentialsError(f"{var} is not set")
        if values[var] == PLACEHOLDER:
            raise CredentialsError(f"{var} is still the placeholder {PLACEHOLDER}")
    return SmtpCredentials(user=values[USER_VAR], password=values[PASSWORD_VAR])


def _safe_error(exc: BaseException) -> str:
    """Describe an exception without echoing server text that may carry secrets."""
    name = type(exc).__name__
    if isinstance(exc, smtplib.SMTPResponseException):
        return f"{name} (SMTP code {exc.smtp_code})"
    if isinstance(exc, MailerError):
        return f"{name}: {exc}"
    return f"{name}: {exc}" if isinstance(exc, OSError) else name


class Mailer:
    def __init__(self, cfg: EmailConfig, creds: SmtpCredentials, smtp_factory=smtplib.SMTP):
        if not cfg.to_addrs:
            raise CredentialsError("email.to_addrs is empty")
        self._cfg = cfg
        self._creds = creds
        self._factory = smtp_factory

    def __repr__(self) -> str:
        return f"Mailer(host={self._cfg.smtp_host!r}, port={self._cfg.smtp_port})"

    def _build(self, subject: str, body: str) -> EmailMessage:
        msg = EmailMessage()
        msg["Subject"] = " ".join(subject.split("\r\n")).replace("\n", " ").replace("\r", " ")
        msg["From"] = self._cfg.from_addr or self._creds.user
        msg["To"] = ", ".join(self._cfg.to_addrs)
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid()
        msg.set_content(body, charset="utf-8")
        return msg

    def _prepare(self, subject: str, body: str) -> EmailMessage:
        msg = self._build(subject, body)
        msg.as_bytes()  # surface encoding errors before any network I/O
        return msg

    def _deliver(self, msg: EmailMessage) -> None:
        smtp = self._factory(
            self._cfg.smtp_host, self._cfg.smtp_port, timeout=SMTP_TIMEOUT_SECONDS
        )
        try:
            smtp.ehlo()
            if not smtp.has_extn("starttls"):
                raise MailerError("server does not advertise STARTTLS; refusing to send")
            smtp.starttls(context=ssl.create_default_context())
            smtp.ehlo()
            try:
                smtp.login(self._creds.user, self._creds.password)
            except smtplib.SMTPAuthenticationError as exc:
                raise AuthenticationFailed(
                    f"SMTP authentication failed (SMTP code {exc.smtp_code})"
                ) from None
            smtp.send_message(msg)
            try:
                smtp.quit()
            except (smtplib.SMTPException, OSError) as exc:
                logger.warning("SMTP quit failed: %s", _safe_error(exc))
        except BaseException:
            try:
                smtp.close()
            except (smtplib.SMTPException, OSError) as exc:
                logger.warning("SMTP close failed: %s", _safe_error(exc))
            raise

    def send(self, subject: str, body: str) -> None:
        try:
            msg = self._prepare(subject, body)
        except UnicodeError:
            logger.warning("alert not encodable as UTF-8; sending with escaped characters")
            msg = self._prepare(_escape(subject), _escape(body))
        self._deliver(msg)


def _escape(text: str) -> str:
    return text.encode("utf-8", "backslashreplace").decode("ascii")


class AlertCoalescer:
    """Per-process-key rate limiting: first event now, the rest batched per window."""

    def __init__(self, window_seconds: int):
        self._window = window_seconds
        self._lock = threading.Lock()
        self._open: dict[str, tuple[float, list[ProcessedEvent]]] = {}
        self._ready: list[list[ProcessedEvent]] = []

    @staticmethod
    def _key(pe: ProcessedEvent) -> str:
        exe = pe.event.exe
        if exe:
            base = exe.rstrip("/").rsplit("/", 1)[-1]
            if base:
                return base
        return pe.event.comm or UNKNOWN_KEY

    def _close_if_due(self, key: str, now: float) -> None:
        started, pending = self._open[key]
        if now - started >= self._window:
            if pending:
                self._ready.append(pending)
            del self._open[key]

    def add(self, pe: ProcessedEvent, now: float) -> list[ProcessedEvent] | None:
        key = self._key(pe)
        with self._lock:
            if key in self._open:
                self._close_if_due(key, now)
            if key not in self._open:
                self._open[key] = (now, [])
                return [pe]
            self._open[key][1].append(pe)
            return None

    def drain_due(self, now: float) -> list[list[ProcessedEvent]]:
        with self._lock:
            for key in list(self._open):
                self._close_if_due(key, now)
            batches, self._ready = self._ready, []
            return batches


class AlertDispatcher:
    def __init__(
        self,
        mailer_factory: Callable[[], Mailer],
        hostname: str,
        on_error: Callable[[str], None],
        sleep: Callable[[float], None] = time.sleep,
    ):
        self._factory = mailer_factory
        self._hostname = hostname
        self._on_error = on_error
        self._sleep = sleep
        self._cond = threading.Condition()
        self._queue: deque[tuple[str, str]] = deque()
        self._dropped = 0
        self._stopping = False
        self._abandon = False
        self._in_flight: str | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._cond:
            if self._thread is not None:
                return
            self._thread = threading.Thread(
                target=self._run, name="credwatch-alerts", daemon=True
            )
            self._thread.start()

    def submit(self, subject: str, body: str) -> None:
        with self._cond:
            if self._stopping:
                logger.error("alert submitted after dispatcher stop; not sent: %s", subject)
                return
            if len(self._queue) >= QUEUE_MAX:
                dropped_subject, _ = self._queue.popleft()
                self._dropped += 1
                logger.error(
                    "alert queue full (%d); dropped oldest alert %r",
                    QUEUE_MAX, dropped_subject,
                )
            self._queue.append((subject, body))
            self._cond.notify()

    def stop(self, timeout: float = 10.0) -> None:
        with self._cond:
            self._stopping = True
            self._cond.notify_all()
            thread = self._thread
        if thread is not None:
            thread.join(timeout)
        with self._cond:
            self._abandon = True
            dropped = self._dropped
            pending = [s for s, _ in self._queue]
            if self._in_flight is not None:
                pending.insert(0, self._in_flight)
            self._queue.clear()
            self._cond.notify_all()
        if dropped:
            logger.error(
                "host %s: %d alert(s) were dropped and never reported", self._hostname, dropped
            )
        if pending:
            logger.error(
                "host %s: abandoned %d unsent alert(s): %s",
                self._hostname, len(pending), "; ".join(pending[:10]),
            )

    def _next(self) -> tuple[str, str, int] | None:
        with self._cond:
            while not self._queue:
                if self._stopping or self._abandon:
                    return None
                self._cond.wait()
            if self._abandon:
                return None
            subject, body = self._queue.popleft()
            dropped = self._dropped
            if dropped:
                body = f"{dropped} alerts dropped (queue overflow) before this message\n\n{body}"
            self._in_flight = subject
            return subject, body, dropped

    def _run(self) -> None:
        while True:
            item = self._next()
            if item is None:
                return
            subject, body, dropped = item
            ok = self._send_with_retry(subject, body)
            with self._cond:
                self._in_flight = None
                if ok:
                    self._dropped -= dropped

    def _send_with_retry(self, subject: str, body: str) -> bool:
        last = ""
        for attempt in range(MAX_ATTEMPTS):
            if self._abandon:
                return False
            try:
                self._factory().send(subject, body)
                return True
            except AuthenticationFailed as exc:
                return self._give_up(subject, f"{exc}", "authentication failed", 1)
            except Exception as exc:  # noqa: BLE001 - logged, reported after retries
                last = _safe_error(exc)
                logger.warning(
                    "alert send failed (attempt %d/%d, %r): %s",
                    attempt + 1, MAX_ATTEMPTS, subject, last,
                )
            if attempt < MAX_ATTEMPTS - 1:
                self._sleep(BACKOFF_SECONDS[attempt])
        return self._give_up(subject, last, "not delivered", MAX_ATTEMPTS)

    def _give_up(self, subject: str, reason: str, what: str, attempts: int) -> bool:
        message = f"alert {subject!r} {what} after {attempts} attempt(s): {reason}"
        logger.error(message)
        try:
            self._on_error(message)
        except Exception:
            logger.exception("on_error callback failed")
        return False
