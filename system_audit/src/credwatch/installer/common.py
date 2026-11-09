"""Platform-neutral install steps: install-location checks, safe dirs/files, bootstrap.

Ownership seam: every function that checks or sets ownership takes `owner_uid`
(default 0 = root). Production always uses 0; tests pass os.geteuid() so they
can install into tmp_path without root. No other ownership override exists.
"""
from __future__ import annotations

import errno
import logging
import os
import pwd
import re
import shutil
import stat
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, replace
from importlib import resources
from pathlib import Path
from typing import Any

import credwatch
from credwatch.allowlist import is_root_controlled_dir, is_root_controlled_file
from credwatch.config import Config, ConfigError, load_config
from credwatch.paths import (
    has_control_chars,
    read_watch_list,
    resolve_watch_paths_report,
    write_watch_list,
)
from credwatch.platform_info import CONFIG_PATH, SECRETS_PATH, WATCH_LIST_PATH, TargetUser
from credwatch.safe_fs import UnsafePathError, open_dir_chain

logger = logging.getLogger(__name__)

PRIVATE_DIR_MODE = 0o700
TRAVERSE_ONLY_DIR_MODE = 0o711
PRIVATE_FILE_MODE = 0o600
DATA_SUBDIRS = ("audit-exports", "logs")
CAPTURES_SUBDIR = "captures"
CANARY_NAME = "canary"
CANARY_BODY = (
    "credwatch canary file. Every access to this file is recorded and verified.\n"
    "Do not edit or delete it.\n"
)
CONFIG_TEMPLATE = "config.example.yaml"
SECRETS_TEMPLATE = "secrets.env.example"
SECRETS_PLACEHOLDER = "REPLACE_ME"
ROOT_USER = "root"
REINSTALL_HINT = "reinstall root-owned with `sudo pipx install --global .`"
ENTRY_POINT_NAME = "credwatch"
SHEBANG_MAX_BYTES = 4096

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
_CREATE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_SYMLINK_ERRNOS = frozenset({errno.ELOOP, errno.ENOTDIR})
_WRITABLE_BY_OTHERS = stat.S_IWGRP | stat.S_IWOTH
# Service user names rendered into the unit/plist argv (`run --user <name>`).
# Linux: the portable useradd/NAME_REGEX form. macOS short names also allow
# upper case and dots. Neither allows whitespace or control characters.
_USER_NAME_RE = {
    "linux": re.compile(r"[a-z_][a-z0-9_-]*[$]?"),
    "darwin": re.compile(r"[A-Za-z_][A-Za-z0-9_.-]*"),
}


class InstallError(RuntimeError):
    """Install cannot proceed safely; the message says what to fix."""


@dataclass(frozen=True)
class InstallReport:
    created: tuple[str, ...]
    unchanged: tuple[str, ...]
    warnings: tuple[str, ...]
    watched: int
    skipped: tuple[Path, ...]


@dataclass(frozen=True)
class StepResult:
    created: tuple[str, ...] = ()
    unchanged: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def merge(self, other: StepResult) -> StepResult:
        return StepResult(
            self.created + other.created,
            self.unchanged + other.unchanged,
            self.warnings + other.warnings,
        )


def outcome(label: str, created: bool) -> StepResult:
    return StepResult(created=(label,)) if created else StepResult(unchanged=(label,))


def template_text(name: str) -> str:
    return (resources.files(credwatch) / "templates" / name).read_text(encoding="utf-8")


# --- install location -----------------------------------------------------------


def _is_trusted(path: Path, stat_fn: Callable[[str], Any]) -> bool:
    """path itself plus every ancestor up to '/' is root-controlled (allowlist predicates)."""
    return is_root_controlled_file(str(path), stat_fn) and is_root_controlled_dir(
        str(path.parent), stat_fn
    )


def _variants(path: Path) -> tuple[Path, ...]:
    """The path as given and its symlink-resolved form (both must be trustworthy)."""
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError) as exc:
        raise InstallError(f"cannot resolve {path} ({exc}); {REINSTALL_HINT}") from exc
    return (path,) if resolved == path else (path, resolved)


def assert_root_owned_install(
    executable: Path,
    prefix: Path,
    *,
    interpreter: Path | None = None,
    package_dir: Path | None = None,
    stat_fn: Callable[[str], Any] = os.stat,
) -> None:
    """Refuse to configure a root service around code a non-root user could modify.

    Checks the entry point, the interpreter, the install prefix and the credwatch
    package dir (each as given and resolved) plus every ancestor up to '/'.
    """
    checks = (
        ("credwatch entry point", executable),
        ("python interpreter", interpreter or Path(sys.executable)),
        ("install prefix", prefix),
        ("credwatch package", package_dir or Path(credwatch.__file__).parent),
    )
    problems = []
    for label, path in checks:
        for variant in _variants(path):
            if not _is_trusted(variant, stat_fn):
                problems.append(
                    f"{label} {variant}: it or an ancestor dir is not root-owned "
                    "or is writable by non-root"
                )
                break
    if problems:
        raise InstallError("unsafe install location: " + "; ".join(problems) + f"; {REINSTALL_HINT}")


# --- directories ----------------------------------------------------------------


def _open_dir(path: Path, mode: int = PRIVATE_DIR_MODE) -> int:
    try:
        return open_dir_chain(path, create_mode=mode)
    except (UnsafePathError, ValueError) as exc:
        raise InstallError(f"refusing unsafe directory {path}: {exc}") from exc


def _open_owned_dir(path: Path, owner_uid: int, mode: int) -> int:
    """open_dir_chain + owner check; tightens/sets the mode through the fd."""
    fd = _open_dir(path, mode)
    try:
        st = os.fstat(fd)
        if st.st_uid != owner_uid:
            raise InstallError(f"{path} is owned by uid {st.st_uid}, expected {owner_uid}")
        if stat.S_IMODE(st.st_mode) != mode:
            os.fchmod(fd, mode)
        return fd
    except BaseException:
        os.close(fd)
        raise


def ensure_owned_dir(path: Path, *, owner_uid: int = 0, mode: int = PRIVATE_DIR_MODE) -> StepResult:
    existed = os.path.lexists(path)
    os.close(_open_owned_dir(path, owner_uid, mode))
    return outcome(f"directory {path}", not existed)


def _capture_owner(
    user: str, getpwnam: Callable[[str], Any]
) -> tuple[tuple[int, int] | None, tuple[str, ...]]:
    if user == ROOT_USER:
        return None, ()
    try:
        entry = getpwnam(user)
    except KeyError:
        return None, (
            f"capture user {user!r} does not exist; captures/ left root-owned and "
            "packet capture will report this at runtime (create the user or set "
            "capture.drop_privileges_to)",
        )
    return (entry.pw_uid, entry.pw_gid), ()


def _ensure_captures(
    data_fd: int, data_dir: Path, owner_uid: int, capture_owner: tuple[int, int] | None
) -> StepResult:
    path = data_dir / CAPTURES_SUBDIR
    try:
        os.mkdir(CAPTURES_SUBDIR, PRIVATE_DIR_MODE, dir_fd=data_fd)
        created = True
    except FileExistsError:
        created = False
    try:
        fd = os.open(CAPTURES_SUBDIR, _DIR_FLAGS, dir_fd=data_fd)
    except OSError as exc:
        if exc.errno in _SYMLINK_ERRNOS:
            raise InstallError(f"refusing {path}: symlink or not a directory") from exc
        raise
    try:
        st = os.fstat(fd)
        target_uid, target_gid = capture_owner or (owner_uid, -1)
        if st.st_uid not in (owner_uid, target_uid):
            raise InstallError(f"{path} is owned by uid {st.st_uid}, expected {target_uid}")
        if st.st_mode & _WRITABLE_BY_OTHERS:
            raise InstallError(f"refusing {path}: group/other writable")
        if st.st_uid != target_uid or (target_gid != -1 and st.st_gid != target_gid):
            os.fchown(fd, target_uid, target_gid)
        os.fchmod(fd, PRIVATE_DIR_MODE)
    finally:
        os.close(fd)
    return outcome(f"directory {path}", created)


def _open_existing_file(dir_fd: int, name: str, path: Path, owner_uid: int) -> int:
    try:
        fd = os.open(name, _READ_FLAGS, dir_fd=dir_fd)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise InstallError(f"refusing {path}: it is a symlink") from exc
        raise
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise InstallError(f"refusing {path}: not a regular file")
        if st.st_uid != owner_uid:
            raise InstallError(f"refusing {path}: owned by uid {st.st_uid}, expected {owner_uid}")
        if st.st_mode & _WRITABLE_BY_OTHERS:
            raise InstallError(f"refusing {path}: group/other writable")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _create_exclusive(dir_fd: int, name: str, content: str, mode: int) -> bool:
    """Create name with content; False (untouched) if anything already exists there."""
    try:
        fd = os.open(name, _CREATE_FLAGS, mode, dir_fd=dir_fd)
    except FileExistsError:
        return False
    try:
        os.fchmod(fd, mode)
        os.write(fd, content.encode("utf-8"))
        os.fsync(fd)
    except BaseException:
        logger.exception("failed creating %s; removing partial file", name)
        os.close(fd)
        os.unlink(name, dir_fd=dir_fd)
        raise
    os.close(fd)
    return True


def _ensure_file(
    path: Path, content: str, *, owner_uid: int, mode: int, tighten: bool
) -> tuple[bool, str, tuple[str, ...]]:
    """Create path exclusively, or verify the existing file. Returns (created, text, warnings)."""
    dir_fd = _open_dir(path.parent)
    try:
        if _create_exclusive(dir_fd, path.name, content, mode):
            return True, content, ()
        fd = _open_existing_file(dir_fd, path.name, path, owner_uid)
        try:
            warnings: tuple[str, ...] = ()
            current = stat.S_IMODE(os.fstat(fd).st_mode)
            if tighten and current != mode:
                os.fchmod(fd, mode)
                warnings = (f"{path} had mode {current:o}; tightened to {mode:o}",)
            with os.fdopen(os.dup(fd), "r", encoding="utf-8", errors="replace") as fh:
                return False, fh.read(), warnings
        finally:
            os.close(fd)
    finally:
        os.close(dir_fd)


def ensure_dirs(
    config: Config,
    *,
    owner_uid: int = 0,
    getpwnam: Callable[[str], Any] = pwd.getpwnam,
) -> StepResult:
    """Create data dir, its subdirs and the canary, all owned by owner_uid.

    The data dir is 0711 (traverse, no listing) when captures/ is handed to an
    unprivileged capture user: tcpdump -Z reopens rotated files as that user and
    needs search permission on the parent. Otherwise it is 0700.
    """
    data_dir = config.data_dir
    if not data_dir.is_absolute():
        raise InstallError(f"data_dir must be an absolute path: {data_dir}")
    capture_owner, warnings = _capture_owner(config.capture.drop_privileges_to, getpwnam)
    data_mode = TRAVERSE_ONLY_DIR_MODE if capture_owner else PRIVATE_DIR_MODE
    result = ensure_owned_dir(data_dir, owner_uid=owner_uid, mode=data_mode)
    for name in DATA_SUBDIRS:
        result = result.merge(ensure_owned_dir(data_dir / name, owner_uid=owner_uid))
    data_fd = _open_owned_dir(data_dir, owner_uid, data_mode)
    try:
        result = result.merge(_ensure_captures(data_fd, data_dir, owner_uid, capture_owner))
    finally:
        os.close(data_fd)
    canary = data_dir / CANARY_NAME
    created, _, canary_warnings = _ensure_file(
        canary, CANARY_BODY, owner_uid=owner_uid, mode=PRIVATE_FILE_MODE, tighten=True
    )
    return result.merge(outcome(f"file {canary}", created)).merge(
        StepResult(warnings=warnings + canary_warnings)
    )


# --- config / secrets -----------------------------------------------------------


def bootstrap_config(dest: Path, *, owner_uid: int = 0) -> bool:
    """Write the example config only if dest is missing. Returns True if created."""
    created, _, _ = _ensure_file(
        dest, template_text(CONFIG_TEMPLATE), owner_uid=owner_uid,
        mode=PRIVATE_FILE_MODE, tighten=False,
    )
    return created


def bootstrap_secrets(dest: Path, *, owner_uid: int = 0) -> tuple[bool, tuple[str, ...]]:
    """Copy the secrets template only if missing; keep it 0600. Returns (created, warnings)."""
    created, text, warnings = _ensure_file(
        dest, template_text(SECRETS_TEMPLATE), owner_uid=owner_uid,
        mode=PRIVATE_FILE_MODE, tighten=True,
    )
    if SECRETS_PLACEHOLDER in text:
        warnings = (*warnings, f"{dest} still has {SECRETS_PLACEHOLDER} placeholders; "
                               "fill in CREDWATCH_SMTP_USER / CREDWATCH_SMTP_PASSWORD")
    return created, warnings


# --- atomic file write ----------------------------------------------------------


def write_if_changed(path: Path, content: str, mode: int) -> bool:
    """Atomically replace path with content unless it already matches. True if written."""
    try:
        if path.read_text(encoding="utf-8") == content and not path.is_symlink():
            return False
    except FileNotFoundError:
        pass
    except (OSError, UnicodeDecodeError):
        logger.warning("cannot read existing %s; rewriting it", path, exc_info=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            os.fchmod(fh.fileno(), mode)
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        logger.exception("failed writing %s", path)
        Path(tmp).unlink(missing_ok=True)
        raise
    _fsync_dir(path.parent)
    return True


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


# --- shared install flow ----------------------------------------------------------


def rooted(root: Path, path: Path) -> Path:
    """Map an absolute system path under root (identity when root is '/')."""
    return root / path.relative_to("/")


def _shebang_interpreter(script: Path) -> Path | None:
    try:
        with script.open("rb") as fh:
            first = fh.readline(SHEBANG_MAX_BYTES)
    except OSError:
        logger.warning("cannot read %s to check its interpreter", script, exc_info=True)
        return None
    if not first.startswith(b"#!"):
        return None
    words = first[2:].decode("utf-8", errors="replace").split()
    return Path(words[0]) if words else None


def find_executable(
    argv0: str | None = None,
    *,
    which: Callable[[str], str | None] = shutil.which,
    prefix: Path | None = None,
) -> Path:
    """The entry point that is actually running (unresolved, so a pipx symlink stays).

    Falls back to PATH lookup only when argv[0] is not a file, and then only if
    that script's interpreter lives inside our own sys.prefix.
    """
    argv0 = sys.argv[0] if argv0 is None else argv0
    if argv0.endswith(".py"):
        raise InstallError("run install via the installed `credwatch` command")
    running = Path(os.path.abspath(argv0))
    if running.is_file():
        return running
    found = which(ENTRY_POINT_NAME)
    if not found:
        raise InstallError("cannot locate the credwatch entry point; run the installed `credwatch` command")
    candidate = Path(os.path.abspath(found))
    own_prefix = (prefix or Path(sys.prefix)).resolve()
    interpreter = _shebang_interpreter(candidate)
    if interpreter is None or own_prefix not in interpreter.resolve().parents:
        raise InstallError(
            f"{candidate} (found on PATH) does not run this credwatch installation "
            f"(interpreter {interpreter}, expected inside {own_prefix})"
        )
    return candidate


def validate_executable(executable: Path) -> None:
    text = str(executable)
    if not executable.is_absolute():
        raise InstallError(f"credwatch executable path must be absolute: {text!r}")
    if has_control_chars(text) or any(c.isspace() for c in text):
        raise InstallError(
            f"credwatch executable path contains whitespace/control characters: {text!r}"
        )


def validate_service_user(
    name: str, os_name: str, *, getpwnam: Callable[[str], Any] = pwd.getpwnam
) -> str:
    """The target user name the service runs `--user` with; refuse anything unsafe."""
    if any(ch.isspace() or not ch.isprintable() for ch in name):
        raise InstallError(f"target user name contains whitespace/control characters: {name!r}")
    pattern = _USER_NAME_RE.get(os_name, _USER_NAME_RE["linux"])
    if not pattern.fullmatch(name):
        raise InstallError(f"target user name {name!r} is not a valid {os_name} user name")
    try:
        getpwnam(name)
    except KeyError as exc:
        raise InstallError(f"no such user: {name!r}") from exc
    return name


def _config_files(config_dir: Path, owner_uid: int) -> StepResult:
    config_path = config_dir / CONFIG_PATH.name
    secrets_path = config_dir / SECRETS_PATH.name
    result = ensure_owned_dir(config_dir, owner_uid=owner_uid)
    created = bootstrap_config(config_path, owner_uid=owner_uid)
    secrets_created, warnings = bootstrap_secrets(secrets_path, owner_uid=owner_uid)
    return (
        result.merge(outcome(f"file {config_path}", created))
        .merge(outcome(f"file {secrets_path}", secrets_created))
        .merge(StepResult(warnings=warnings))
    )


def _load(config_path: Path, os_name: str, target: TargetUser) -> Config:
    try:
        cfg = load_config(config_path, os_name, target)
    except ConfigError as exc:
        raise InstallError(f"invalid config {config_path}: {exc}") from exc
    if not cfg.data_dir.is_absolute():
        raise InstallError(f"data_dir must be an absolute path: {cfg.data_dir}")
    return cfg


def _watch_list(paths: tuple[Path, ...], dest: Path) -> StepResult:
    try:
        if read_watch_list(dest) == paths:
            return outcome(f"file {dest}", False)
    except FileNotFoundError:
        pass
    except (OSError, ValueError):  # includes UnicodeDecodeError
        logger.warning("cannot read existing watch list %s; rewriting it", dest, exc_info=True)
    write_watch_list(paths, dest)
    return outcome(f"file {dest}", True)


@dataclass(frozen=True)
class PreparedInstall:
    """Outcome of the OS-neutral steps; the OS module adds its service on top."""

    executable: Path
    user: str  # validated target user name for the service's `--user`
    config: Config  # as loaded: real system paths (what the service will see)
    paths: tuple[Path, ...]  # watched paths written to the watch list
    result: StepResult


def prepare_install(
    os_name: str,
    target: TargetUser,
    *,
    root: Path,
    owner_uid: int,
    executable: Path | None,
    config_dir: Path,
    trust_check: Callable[[Path, Path], None],
) -> PreparedInstall:
    """Root check, executable trust, config/secrets bootstrap, data dirs, watch list.

    config_dir is the system config dir as safe_fs must see it (on macOS the
    /private-resolved form of /etc/credwatch); it is mapped under root here.
    """
    if os.geteuid() != owner_uid:
        raise InstallError("credwatch install must be run as root (sudo credwatch install)")
    user = validate_service_user(target.name, os_name)
    exe = executable or find_executable()
    validate_executable(exe)
    trust_check(exe, Path(sys.prefix))

    local_config_dir = rooted(root, config_dir)
    result = _config_files(local_config_dir, owner_uid)
    cfg = _load(local_config_dir / CONFIG_PATH.name, os_name, target)
    local_cfg = replace(cfg, data_dir=rooted(root, cfg.data_dir))
    result = result.merge(ensure_dirs(local_cfg, owner_uid=owner_uid))

    paths, skipped_targets = resolve_watch_paths_report(local_cfg)
    link_warnings = tuple(
        f"symlink {link} points outside {cfg.home} (or to an unsafe path) at {target_path}; "
        "only the link is watched"
        for link, target_path in skipped_targets
    )
    result = result.merge(StepResult(warnings=link_warnings)).merge(
        _watch_list(paths, local_config_dir / WATCH_LIST_PATH.name)
    )
    return PreparedInstall(executable=exe, user=user, config=cfg, paths=paths, result=result)
