"""Tests for the proactive password policy."""

import pytest

from justinvest.password_policy import PasswordPolicy


@pytest.fixture()
def policy() -> PasswordPolicy:
    weak_list = {"password", "letmein", "12345678"}
    return PasswordPolicy(weak_passwords=weak_list)


def test_password_must_meet_length(policy: PasswordPolicy) -> None:
    result = policy.validate("alice", "Ab1!")
    assert not result.is_valid
    assert "between" in result.violations[0]


def test_password_requires_character_classes(policy: PasswordPolicy) -> None:
    result = policy.validate("alice", "abcdefgh")
    assert not result.is_valid
    assert any("uppercase" in msg for msg in result.violations)
    assert any("digit" in msg for msg in result.violations)
    assert any("special" in msg for msg in result.violations)


def test_password_cannot_match_username(policy: PasswordPolicy) -> None:
    result = policy.validate("alice", "Alice")
    assert not result.is_valid
    assert any("match the username" in msg for msg in result.violations)


def test_password_blacklist(policy: PasswordPolicy) -> None:
    result = policy.validate("alice", "password")
    assert not result.is_valid
    assert any("blacklist" in msg for msg in result.violations)


def test_default_blacklist_loaded_from_file(monkeypatch, tmp_path):
    weak_file = tmp_path / "weak_passwords.txt"
    weak_file.write_text("secretpass\n", encoding="utf-8")
    monkeypatch.setattr(
        "justinvest.password_policy.DEFAULT_WEAK_PASSWORDS",
        weak_file,
    )
    policy = PasswordPolicy()
    result = policy.validate("alice", "secretpass")
    assert not result.is_valid
    assert any("blacklist" in msg for msg in result.violations)


def test_password_requires_lowercase(policy: PasswordPolicy) -> None:
    result = policy.validate("alice", "UPPER123!")
    assert not result.is_valid
    assert any("lowercase" in msg for msg in result.violations)


def test_valid_password_passes(policy: PasswordPolicy) -> None:
    result = policy.validate("alice", "Valid@123")
    assert result.is_valid

