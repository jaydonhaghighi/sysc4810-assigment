"""Login helpers for Problem 4."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Sequence

from .access_control import AccessControlEngine
from .models import RoleDefinition, SessionContext
from .operations import ALL_OPERATIONS, OPERATIONS_BY_CODE
from .password_file import PasswordRecord, get_record, verify_credentials


class LoginError(Exception):
    """Raised when login fails."""


@dataclass(frozen=True)
class LoginResult:
    username: str
    role_name: str
    role_label: str
    allowed_operation_codes: Sequence[str]

    @property
    def allowed_operation_labels(self) -> List[str]:
        return [
            OPERATIONS_BY_CODE[code].label
            for code in self.allowed_operation_codes
            if code in OPERATIONS_BY_CODE
        ]


def perform_login(
    username: str,
    password: str,
    engine: AccessControlEngine,
    *,
    roles: Iterable[RoleDefinition],
    passwd_path: Path | None = None,
    as_of: datetime | None = None,
) -> LoginResult:
    """Authenticate and return the user's permissions."""

    username = username.strip()
    if not username:
        raise LoginError("Username is required.")

    record = get_record(username, path=passwd_path)
    if record is None:
        raise LoginError("Invalid username or password.")
    if not verify_credentials(username, password, path=passwd_path):
        raise LoginError("Invalid username or password.")

    role = _find_role(record.role, roles)
    context = SessionContext(as_of=as_of or datetime.now())
    permitted_codes = engine.permitted_operations(role.name, context)
    return LoginResult(
        username=username,
        role_name=role.name,
        role_label=role.label,
        allowed_operation_codes=permitted_codes,
    )


def _find_role(role_name: str, roles: Iterable[RoleDefinition]) -> RoleDefinition:
    for role in roles:
        if role.name == role_name:
            return role
    raise LoginError(f"Role '{role_name}' is not recognized.")

