"""Proactive password policy enforcement for justInvest."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Set


DEFAULT_WEAK_PASSWORDS = Path(__file__).resolve().parents[1] / "data" / "weak_passwords.txt"
SPECIAL_CHARS = "!@#$%*&"


@dataclass(frozen=True)
class PasswordCheckResult:
    is_valid: bool
    violations: list[str]


class PasswordPolicy:
    """Validates candidate passwords against justInvest's requirements."""

    def __init__(
        self,
        *,
        min_length: int = 8,
        max_length: int = 12,
        special_characters: str = SPECIAL_CHARS,
        weak_passwords: Optional[Iterable[str]] = None,
        weak_passwords_path: Optional[Path] = None,
    ) -> None:
        self.min_length = min_length
        self.max_length = max_length
        self.special_characters = special_characters
        self._weak_passwords = self._load_weak_passwords(
            weak_passwords, weak_passwords_path
        )

    def _load_weak_passwords(
        self,
        weak_passwords: Optional[Iterable[str]],
        weak_passwords_path: Optional[Path],
    ) -> Set[str]:
        if weak_passwords is not None:
            return {entry.strip().lower() for entry in weak_passwords if entry.strip()}
        path = weak_passwords_path or DEFAULT_WEAK_PASSWORDS
        if path.exists():
            return {
                line.strip().lower()
                for line in path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            }
        return set()

    def validate(self, username: str, password: str) -> PasswordCheckResult:
        """Return a result describing whether the password meets policy."""

        violations: list[str] = []
        trimmed = password.strip()
        if len(password) != len(trimmed):
            violations.append("Password cannot start or end with whitespace.")
        if len(password) < self.min_length or len(password) > self.max_length:
            violations.append(
                f"Password must be between {self.min_length} and {self.max_length} characters."
            )
        if not any(c.islower() for c in password):
            violations.append("Password must include at least one lowercase letter.")
        if not any(c.isupper() for c in password):
            violations.append("Password must include at least one uppercase letter.")
        if not any(c.isdigit() for c in password):
            violations.append("Password must include at least one digit.")
        if not any(c in self.special_characters for c in password):
            violations.append(
                f"Password must include at least one special character from {self.special_characters}."
            )
        if username and password.lower() == username.lower():
            violations.append("Password cannot match the username.")
        if password.lower() in self._weak_passwords:
            violations.append("Password appears on the weak password blacklist.")

        return PasswordCheckResult(is_valid=not violations, violations=violations)

