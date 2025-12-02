"""Utilities for creating and using the passwd.txt password file."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from .authentication import verify_password

DEFAULT_PASSWD_PATH = Path(__file__).resolve().parents[1] / "passwd.txt"


@dataclass(frozen=True)
class PasswordRecord:
    """Represents one line stored in passwd.txt."""

    username: str
    role: str
    password_hash: str


def _resolve_path(path: Optional[Path]) -> Path:
    return path or DEFAULT_PASSWD_PATH


def _sanitize(value: str, field_name: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError(f"{field_name} is required.")
    if "|" in value or "\n" in value:
        raise ValueError(f"{field_name} cannot contain '|' or newlines.")
    return value


def parse_record(line: str) -> PasswordRecord:
    """Parse a passwd.txt line into a PasswordRecord."""

    username, role, password_hash = line.rstrip("\n").split("|", maxsplit=2)
    return PasswordRecord(username=username, role=role, password_hash=password_hash)


def iter_records(path: Optional[Path] = None) -> Iterator[PasswordRecord]:
    """Yield records from the password file."""

    file_path = _resolve_path(path)
    if not file_path.exists():
        return iter(())
    for line in file_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        yield parse_record(line)


def get_record(username: str, path: Optional[Path] = None) -> Optional[PasswordRecord]:
    """Return the record for username, if present."""

    username = username.strip()
    for record in iter_records(path):
        if record.username == username:
            return record
    return None


def _hash_password(
    password: str, *, iterations: int = 600_000, salt_bytes: int = 16
) -> str:
    salt = secrets.token_bytes(salt_bytes)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"


def add_record(
    username: str,
    role: str,
    password: str,
    *,
    path: Optional[Path] = None,
    iterations: int = 600_000,
    salt_bytes: int = 16,
) -> PasswordRecord:
    """Append a new record to passwd.txt, returning the stored entry."""

    username = _sanitize(username, "username")
    role = _sanitize(role, "role")
    if get_record(username, path):
        raise ValueError(f"Username '{username}' already exists.")
    password_hash = _hash_password(password, iterations=iterations, salt_bytes=salt_bytes)
    record = PasswordRecord(username=username, role=role, password_hash=password_hash)
    file_path = _resolve_path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    needs_leading_newline = (
        file_path.exists() and file_path.stat().st_size > 0 and not _ends_with_newline(file_path)
    )
    with file_path.open("a", encoding="utf-8") as handle:
        if needs_leading_newline:
            handle.write("\n")
        handle.write(f"{record.username}|{record.role}|{record.password_hash}\n")
    return record


def _ends_with_newline(path: Path) -> bool:
    """Return True if the file currently ends with a newline character."""

    with path.open("rb") as handle:
        handle.seek(0, 2)
        if handle.tell() == 0:
            return True
        handle.seek(-1, 2)
        return handle.read(1) == b"\n"


def verify_credentials(
    username: str, password: str, *, path: Optional[Path] = None
) -> bool:
    """Return True if the password matches the stored hash for username."""

    record = get_record(username, path)
    if record is None:
        return False
    return verify_password(password, record.password_hash)

