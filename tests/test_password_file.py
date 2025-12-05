"""Tests for the passwd.txt helper functions."""

from pathlib import Path
from shutil import copyfile

import pytest

from justinvest.password_file import add_record, get_record, verify_credentials


@pytest.fixture()
def passwd_file(tmp_path: Path) -> Path:
    src = Path(__file__).resolve().parents[1] / "passwd.txt"
    dest = tmp_path / "passwd.txt"
    copyfile(src, dest)
    return dest


def test_get_existing_record(passwd_file: Path) -> None:
    record = get_record("sasha.kim", passwd_file)
    assert record is not None
    assert record.role == "client"


def test_verify_credentials(passwd_file: Path) -> None:
    assert verify_credentials("sasha.kim", "Aster!1A", path=passwd_file)
    assert not verify_credentials("sasha.kim", "wrongpass", path=passwd_file)
    assert not verify_credentials("unknown", "whatever", path=passwd_file)


def test_add_record(passwd_file: Path) -> None:
    new_record = add_record(
        "new.user",
        "client",
        "Secure@123",
        path=passwd_file,
        iterations=1000,
        salt_bytes=8,
    )
    assert new_record.username == "new.user"
    lines = passwd_file.read_text(encoding="utf-8").strip().splitlines()
    assert lines[-1].startswith("new.user|client|pbkdf2_sha256$")


def test_add_record_duplicate(passwd_file: Path) -> None:
    with pytest.raises(ValueError):
        add_record("sasha.kim", "client", "Another@123", path=passwd_file)

