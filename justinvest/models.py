"""Core data models for the justInvest prototype."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Sequence, Set


@dataclass(frozen=True)
class ConstraintDefinition:
    """Represents a policy constraint attached to a role."""

    type: str
    params: Dict[str, str]


@dataclass(frozen=True)
class RoleDefinition:
    """Container for role metadata used by the access-control engine."""

    name: str
    label: str
    permissions: Set[str]
    constraints: Sequence[ConstraintDefinition]
    allow_self_signup: bool = False

    def allows(self, permission: str) -> bool:
        return permission in self.permissions


@dataclass(frozen=True)
class UserRecord:
    """Represents an entry in the user store."""

    username: str
    full_name: str
    role: str
    password_hash: str


@dataclass
class SessionContext:
    """Holds request-specific metadata used when evaluating constraints."""

    as_of: datetime


@dataclass
class AuthorizationDecision:
    """Result of a permission check."""

    granted: bool
    reason: Optional[str] = None


def build_role_lookup(definitions: Iterable[RoleDefinition]) -> Dict[str, RoleDefinition]:
    """Convert a list of RoleDefinition objects into a dictionary."""

    return {definition.name: definition for definition in definitions}


def build_user_lookup(records: Iterable[UserRecord]) -> Dict[str, UserRecord]:
    """Convert user records into a dictionary keyed by username."""

    return {record.username: record for record in records}

