"""CLI entry point for Problem 1c: access control implementation."""

from __future__ import annotations

from datetime import datetime
from typing import Dict

from justinvest.access_control import AccessControlEngine
from justinvest.authentication import AuthenticatedUser, CredentialStore
from justinvest.models import SessionContext
from justinvest.operations import ALL_OPERATIONS, format_operations_menu
from justinvest.repository import load_roles, load_users

try:
    import getpass
except ImportError:  # pragma: no cover - getpass always available in CPython
    getpass = None


def _build_operation_index() -> Dict[str, int]:
    return {op.code: idx for idx, op in enumerate(ALL_OPERATIONS, start=1)}


def _auth_prompt(credentials: CredentialStore) -> AuthenticatedUser | None:
    print("\nEnter your credentials to continue.")
    username = input("Enter username: ").strip()
    if not username:
        print("Username is required.")
        return None
    if getpass:
        password = getpass.getpass("Enter password: ")
    else:  # pragma: no cover - fallback for limited environments
        password = input("Enter password: ")
    user = credentials.authenticate(username=username, password=password)
    if user is None:
        print("ACCESS DENIED. Invalid username or password.")
        return None
    print("\nACCESS GRANTED!")
    return user


def _display_authorized_operations(
    engine: AccessControlEngine, user: AuthenticatedUser, context: SessionContext
) -> None:
    operation_numbers = _build_operation_index()
    allowed_codes = []
    denial_reason = None
    for operation in ALL_OPERATIONS:
        decision = engine.is_operation_allowed(user.role, operation.code, context)
        if decision.granted:
            allowed_codes.append(operation.code)
        elif denial_reason is None:
            denial_reason = decision.reason

    if not allowed_codes:
        print(f"\nNo operations available. Reason: {denial_reason or 'Not authorized.'}")
        return

    allowed_numbers = [
        str(operation_numbers[operation.code])
        for operation in ALL_OPERATIONS
        if operation.code in allowed_codes
    ]
    friendly_labels = [
        f"{operation_numbers[operation.code]} ({operation.label})"
        for operation in ALL_OPERATIONS
        if operation.code in allowed_codes
    ]
    print("Your authorized operations are: " + ", ".join(friendly_labels))

    selection = input("Which operation would you like to perform? ").strip()
    if selection not in allowed_numbers:
        print("Operation not authorized or invalid selection.")
    else:
        chosen_op = ALL_OPERATIONS[int(selection) - 1]
        print(f"Executing placeholder for '{chosen_op.label}'.")


def main() -> None:
    print("justInvest System")
    print(format_operations_menu())

    roles = load_roles()
    users = load_users()
    credentials = CredentialStore(users)
    engine = AccessControlEngine(roles)

    user = _auth_prompt(credentials)
    if user is None:
        return
    context = SessionContext(as_of=datetime.now())
    _display_authorized_operations(engine, user, context)


if __name__ == "__main__":
    main()

