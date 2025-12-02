"\"\"\"Tests for the login flow in Problem 4.\"\"\""

from datetime import datetime
from pathlib import Path
from shutil import copyfile

import pytest

from justinvest.access_control import AccessControlEngine
from justinvest.login import LoginError, perform_login
from justinvest.password_file import add_record
from justinvest.repository import load_roles


@pytest.fixture(scope="module")
def roles():
    return load_roles()


@pytest.fixture(scope="module")
def engine(roles):
    return AccessControlEngine(roles)


@pytest.fixture()
def passwd_file(tmp_path: Path) -> Path:
    src = Path(__file__).resolve().parents[1] / "passwd.txt"
    dest = tmp_path / "passwd.txt"
    copyfile(src, dest)
    return dest


def test_login_success_displays_permissions(roles, engine, passwd_file: Path) -> None:
    result = perform_login(
        "sasha.kim",
        "Aster!1A",
        engine,
        roles=roles,
        passwd_path=passwd_file,
        as_of=datetime(2025, 1, 1, 10, 0),
    )
    assert result.username == "sasha.kim"
    assert result.role_label == "Client"
    assert "VIEW_ACCOUNT_BALANCE" in result.allowed_operation_codes
    assert "Modify investment portfolio" not in result.allowed_operation_labels


def test_login_rejects_invalid_password(roles, engine, passwd_file: Path) -> None:
    with pytest.raises(LoginError):
        perform_login(
            "sasha.kim",
            "wrongpass",
            engine,
            roles=roles,
            passwd_path=passwd_file,
        )


def test_login_fails_for_unknown_role(engine, passwd_file: Path, roles) -> None:
    add_record("ghost.user", "mystery_role", "Valid@123", path=passwd_file, iterations=1000, salt_bytes=8)
    with pytest.raises(LoginError):
        perform_login(
            "ghost.user",
            "Valid@123",
            engine,
            roles=roles,
            passwd_path=passwd_file,
        )

