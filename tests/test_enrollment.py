"\"\"\"Tests covering the enrollment workflow.\"\"\""

from pathlib import Path

import json
import pytest

from justinvest.enrollment import EnrollmentError, enroll_user
from justinvest.models import ConstraintDefinition, RoleDefinition
from justinvest.password_policy import PasswordPolicy


@pytest.fixture()
def client_role() -> RoleDefinition:
    return RoleDefinition(
        name="client",
        label="Client",
        permissions={"VIEW_ACCOUNT_BALANCE"},
        constraints=(),
        allow_self_signup=True,
    )


@pytest.fixture()
def teller_role() -> RoleDefinition:
    return RoleDefinition(
        name="teller",
        label="Teller",
        permissions={"VIEW_ACCOUNT_BALANCE"},
        constraints=(),
        allow_self_signup=False,
    )


@pytest.fixture()
def files(tmp_path: Path) -> tuple[Path, Path]:
    passwd = tmp_path / "passwd.txt"
    users = tmp_path / "users.json"
    return passwd, users


def test_successful_enrollment_updates_files(
    client_role: RoleDefinition, files: tuple[Path, Path]
) -> None:
    passwd_path, users_path = files
    policy = PasswordPolicy(weak_passwords={"password"})
    result = enroll_user(
        "new.client",
        client_role,
        "Valid@123",
        policy=policy,
        passwd_path=passwd_path,
        users_path=users_path,
    )
    assert result.username == "new.client"
    assert passwd_path.read_text(encoding="utf-8").startswith(
        "new.client|client|pbkdf2_sha256$"
    )
    users = json.loads(users_path.read_text(encoding="utf-8"))
    assert users["users"][0]["username"] == "new.client"


def test_enrollment_rejects_duplicate_username(
    client_role: RoleDefinition, files: tuple[Path, Path]
) -> None:
    passwd_path, users_path = files
    policy = PasswordPolicy(weak_passwords={"password"})
    enroll_user(
        "dup.client",
        client_role,
        "Valid@123",
        policy=policy,
        passwd_path=passwd_path,
        users_path=users_path,
    )
    with pytest.raises(EnrollmentError):
        enroll_user(
            "dup.client",
            client_role,
            "Another@123",
            policy=policy,
            passwd_path=passwd_path,
            users_path=users_path,
        )


def test_enrollment_rejects_disallowed_role(
    teller_role: RoleDefinition, files: tuple[Path, Path]
) -> None:
    passwd_path, users_path = files
    policy = PasswordPolicy(weak_passwords={"password"})
    with pytest.raises(EnrollmentError):
        enroll_user(
            "teller.applicant",
            teller_role,
            "Valid@123",
            policy=policy,
            passwd_path=passwd_path,
            users_path=users_path,
        )


def test_enrollment_rejects_weak_password(
    client_role: RoleDefinition, files: tuple[Path, Path]
) -> None:
    passwd_path, users_path = files
    policy = PasswordPolicy(weak_passwords={"password"})
    with pytest.raises(EnrollmentError):
        enroll_user(
            "weak.client",
            client_role,
            "password",  # on blacklist
            policy=policy,
            passwd_path=passwd_path,
            users_path=users_path,
        )

