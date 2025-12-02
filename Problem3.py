"""CLI for Problem 3: user enrollment with proactive password checks."""

from __future__ import annotations

from justinvest.enrollment import EnrollmentError, enroll_user, get_self_signup_roles
from justinvest.password_policy import PasswordPolicy
from justinvest.repository import load_roles

try:
    import getpass
except ImportError:  # pragma: no cover
    getpass = None


def _prompt_username() -> str:
    while True:
        candidate = input("Choose a username: ").strip()
        if candidate:
            return candidate
        print("Username cannot be empty.")


def _prompt_role(roles) -> object:
    print("\nSelect your role:")
    for idx, role in enumerate(roles, start=1):
        print(f"{idx}. {role.label} ({role.name})")
    while True:
        choice = input("Enter the number corresponding to your role: ").strip()
        if not choice.isdigit():
            print("Please enter a numeric choice.")
            continue
        idx = int(choice)
        if 1 <= idx <= len(roles):
            return roles[idx - 1]
        print("Selection out of range.")


def _prompt_password(policy: PasswordPolicy, username: str) -> str:
    while True:
        if getpass:
            password = getpass.getpass("Choose a password: ")
            confirm = getpass.getpass("Confirm password: ")
        else:  # pragma: no cover
            password = input("Choose a password: ")
            confirm = input("Confirm password: ")
        if password != confirm:
            print("Passwords do not match.")
            continue
        result = policy.validate(username, password)
        if result.is_valid:
            return password
        print("Password does not meet policy:")
        for violation in result.violations:
            print(f"  - {violation}")


def main() -> None:
    print("justInvest Self-Service Signup")
    roles = load_roles()
    signup_roles = get_self_signup_roles(roles)
    if not signup_roles:
        print("Self-service signup is currently unavailable.")
        return
    policy = PasswordPolicy()
    username = _prompt_username()
    role = _prompt_role(signup_roles)
    password = _prompt_password(policy, username)
    try:
        result = enroll_user(username, role, password, policy=policy)
    except EnrollmentError as exc:
        print(f"Enrollment failed: {exc}")
        return
    print(
        f"\nEnrollment successful! Username '{result.username}' is ready to log in as '{role.label}'."
    )


if __name__ == "__main__":
    main()

