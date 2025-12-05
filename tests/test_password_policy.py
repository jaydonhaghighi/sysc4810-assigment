"""Tests for the proactive password policy."""

import pytest

from justinvest.password_policy import PasswordPolicy


@pytest.fixture()
def policy() -> PasswordPolicy:
    weak_list = {"password", "letmein", "12345678"}
    return PasswordPolicy(weak_passwords=weak_list)


def test_length_rule(policy: PasswordPolicy) -> None:
    """verifies that passwords shorter than 8 characters are rejected."""
    result = policy.validate("alice", "Ab1!")
    assert not result.is_valid
    assert "between" in result.violations[0]


def test_character_class_rules(policy: PasswordPolicy) -> None:
    """verifies that passwords must include uppercase, digits, and special characters."""
    result = policy.validate("alice", "abcdefgh")
    assert not result.is_valid
    assert any("uppercase" in msg for msg in result.violations)
    assert any("digit" in msg for msg in result.violations)
    assert any("special" in msg for msg in result.violations)


def test_username_match(policy: PasswordPolicy) -> None:
    """verifies that passwords matching the username are rejected."""
    result = policy.validate("alice", "Alice")
    assert not result.is_valid
    assert any("match the username" in msg for msg in result.violations)


def test_custom_blacklist(policy: PasswordPolicy) -> None:
    """verifies that passwords on the custom blacklist are rejected."""
    result = policy.validate("alice", "password")
    assert not result.is_valid
    assert any("blacklist" in msg for msg in result.violations)


def test_default_blacklist(monkeypatch, tmp_path):
    """verifies that passwords from the default blacklist file are rejected."""
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


def test_lowercase_rule(policy: PasswordPolicy) -> None:
    """verifies that passwords must include at least one lowercase letter."""
    result = policy.validate("alice", "UPPER123!")
    assert not result.is_valid
    assert any("lowercase" in msg for msg in result.violations)


def test_valid_password(policy: PasswordPolicy) -> None:
    """verifies that passwords meeting all requirements are accepted."""
    result = policy.validate("alice", "Valid@123")
    assert result.is_valid

