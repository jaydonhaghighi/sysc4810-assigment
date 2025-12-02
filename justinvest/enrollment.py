"""User enrollment helpers for Problem 3."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from .models import RoleDefinition
from .password_file import add_record
from .password_policy import PasswordPolicy

DEFAULT_USERS_PATH = Path(__file__).resolve().parents[1] / "data" / "users.json"
DEFAULT_PASSWD_PATH = Path(__file__).resolve().parents[1] / "passwd.txt"


class EnrollmentError(Exception):
    """Raised when enrollment fails."""


@dataclass(frozen=True)
class EnrollmentResult:
    username: str
    role: str
    password_hash: str
    password_file: Path
    users_file: Path


def get_self_signup_roles(roles: Iterable[RoleDefinition]) -> List[RoleDefinition]:
    """Return the subset of roles that permit self-service enrollment."""

    return [role for role in roles if role.allow_self_signup]


def enroll_user(
    username: str,
    role: RoleDefinition,
    password: str,
    *,
    policy: PasswordPolicy | None = None,
    passwd_path: Path | None = None,
    users_path: Path | None = None,
) -> EnrollmentResult:
    """Enroll a user by appending to passwd.txt and users.json."""

    policy = policy or PasswordPolicy()
    check = policy.validate(username, password)
    if not check.is_valid:
        raise EnrollmentError("; ".join(check.violations))
    if not role.allow_self_signup:
        raise EnrollmentError(f"Role '{role.label}' cannot be selected during signup.")

    passwd_file = passwd_path or DEFAULT_PASSWD_PATH
    users_file = users_path or DEFAULT_USERS_PATH
    try:
        record = add_record(username, role.name, password, path=passwd_file)
    except ValueError as exc:
        raise EnrollmentError(str(exc)) from exc
    _append_user_json(username, role.name, record.password_hash, users_file)
    return EnrollmentResult(
        username=username,
        role=role.name,
        password_hash=record.password_hash,
        password_file=passwd_file,
        users_file=users_file,
    )


def _append_user_json(
    username: str, role: str, password_hash: str, path: Path | None = None
) -> None:
    file_path = path or DEFAULT_USERS_PATH
    payload = {"users": []}
    if file_path.exists():
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    if any(entry["username"] == username for entry in payload.get("users", [])):
        raise EnrollmentError(f"Username '{username}' already exists in users.json.")
    payload.setdefault("users", []).append(
        {
            "username": username,
            "full_name": username,
            "role": role,
            "password_hash": password_hash,
        }
    )
    file_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

