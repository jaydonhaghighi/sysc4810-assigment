from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, List

from .models import ConstraintDefinition, RoleDefinition, UserRecord


def _ensure_path(path: Path | None, default_filename: str) -> Path:
    """figures out where to find a data file."""

    if path is not None:
        return path
    project_root = Path(__file__).resolve().parents[1]
    return project_root / "data" / default_filename


def load_roles(path: Path | None = None) -> List[RoleDefinition]:
    """reads the roles from the config file."""

    file_path = _ensure_path(path, "roles.json")
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    role_defs = []
    for role_payload in payload.get("roles", []):
        constraints = [
            ConstraintDefinition(type=constraint["type"], params=constraint)
            for constraint in role_payload.get("constraints", [])
        ]
        role_defs.append(
            RoleDefinition(
                name=role_payload["name"],
                label=role_payload.get("label", role_payload["name"]),
                permissions=set(role_payload.get("permissions", [])),
                constraints=constraints,
                allow_self_signup=role_payload.get("allow_self_signup", False),
            )
        )
    return role_defs


def load_users(path: Path | None = None) -> List[UserRecord]:
    """reads the users from the config file."""

    file_path = _ensure_path(path, "users.json")
    payload = json.loads(file_path.read_text(encoding="utf-8"))
    users = []
    for user_payload in payload.get("users", []):
        users.append(
            UserRecord(
                username=user_payload["username"],
                full_name=user_payload.get("full_name", user_payload["username"]),
                role=user_payload["role"],
                password_hash=user_payload["password_hash"],
            )
        )
    return users