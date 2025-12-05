from __future__ import annotations

from datetime import datetime

from justinvest.access_control import AccessControlEngine
from justinvest.login import LoginError, perform_login
from justinvest.operations import OPERATIONS_BY_CODE, format_operations_menu
from justinvest.repository import load_roles

try:
    import getpass
except ImportError:
    getpass = None


def main() -> None:
    """runs the login portal, authenticates the user, and displays their permissions."""
    print("justInvest Login Portal")
    print(format_operations_menu())

    roles = load_roles()
    engine = AccessControlEngine(roles)

    username = input("\nEnter username: ").strip()
    if getpass:
        password = getpass.getpass("Enter password: ")
    else:
        password = input("Enter password: ")

    try:
        result = perform_login(
            username,
            password,
            engine,
            roles=roles,
            as_of=datetime.now(),
        )
    except LoginError as exc:
        print(f"\nACCESS DENIED: {exc}")
        return

    print("\nACCESS GRANTED!")
    print(f"Username: {result.username}")
    print(f"Role: {result.role_label} ({result.role_name})")
    if result.allowed_operation_codes:
        print("Authorized operations:")
        for code in result.allowed_operation_codes:
            label = OPERATIONS_BY_CODE.get(code, None)
            label_text = label.label if label else code
            print(f"  - {code}: {label_text}")
    else:
        print("No operations available for the current context.")


if __name__ == "__main__":
    main()