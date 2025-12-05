from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Set


@dataclass(frozen=True)
class ConstraintDefinition:
    """defines a rule that limits when a role can be used."""

    type: str
    params: Dict[str, str]


@dataclass(frozen=True)
class RoleDefinition:
    """stores everything we need to know about a role."""

    name: str
    label: str
    permissions: Set[str]
    constraints: Sequence[ConstraintDefinition]
    allow_self_signup: bool = False

    def allows(self, permission: str) -> bool:
        return permission in self.permissions


@dataclass(frozen=True)
class UserRecord:
    """stores a user's info from the database."""

    username: str
    full_name: str
    role: str
    password_hash: str


@dataclass
class SessionContext:
    """stores info about when this request happened."""

    as_of: datetime


@dataclass
class AuthorizationDecision:
    """indicates whether access was granted and why."""

    granted: bool
    reason: Optional[str] = None


def build_role_lookup(definitions: Iterable[RoleDefinition]) -> Dict[str, RoleDefinition]:
    """turns a list of roles into a lookup table."""

    return {definition.name: definition for definition in definitions}


def build_user_lookup(records: Iterable[UserRecord]) -> Dict[str, UserRecord]:
    """turns a list of users into a lookup table."""

    return {record.username: record for record in records}