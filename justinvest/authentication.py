"""Authentication helpers for the justInvest prototype."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import Dict, Optional

from .models import UserRecord, build_user_lookup


class AuthenticationError(Exception):
    """Raised when authentication input is invalid or corrupt."""


def _parse_hash(hash_string: str) -> tuple[str, int, bytes, bytes]:
    try:
        algorithm, iteration_str, salt_hex, digest_hex = hash_string.split("$")
        return algorithm, int(iteration_str), bytes.fromhex(salt_hex), bytes.fromhex(
            digest_hex
        )
    except ValueError as exc:  # pragma: no cover - defensive
        raise AuthenticationError("Corrupt password hash format.") from exc


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored PBKDF2 hash."""

    algorithm, iterations, salt, stored_digest = _parse_hash(stored_hash)
    if algorithm != "pbkdf2_sha256":
        raise AuthenticationError(f"Unsupported hash algorithm '{algorithm}'.")
    candidate_digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )
    return hmac.compare_digest(candidate_digest, stored_digest)


@dataclass
class AuthenticatedUser:
    username: str
    full_name: str
    role: str


class CredentialStore:
    """In-memory credential store backed by the JSON user list."""

    def __init__(self, users: list[UserRecord]) -> None:
        self._users: Dict[str, UserRecord] = build_user_lookup(users)

    def authenticate(self, username: str, password: str) -> Optional[AuthenticatedUser]:
        record = self._users.get(username)
        if record is None:
            return None
        if not verify_password(password, record.password_hash):
            return None
        return AuthenticatedUser(
            username=record.username, full_name=record.full_name, role=record.role
        )

