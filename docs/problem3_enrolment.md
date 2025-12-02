# Problem 3 – User Enrollment

## (a) Signup Interface

- CLI entry point: `Problem3.py`.
- Flow: users enter a username, pick a self-service role (Client or Premium Client – the only roles marked `allow_self_signup` in `data/roles.json`), and provide a password/confirmation. No other attributes are collected, satisfying the “only necessary information” requirement.
- Successful enrollments append to `passwd.txt` and refresh `data/users.json` so the new account can log in immediately.

## (b) Proactive Password Checker

Implemented in `justinvest/password_policy.py` and invoked from both the CLI and the `enroll_user` helper. Policy rules mirror Problem 1’s specification:

1. Length between 8 and 12 characters inclusive.
2. At least one lowercase, uppercase, digit, and special character (special set: `!@#$%*&`).
3. Password must not match the username (case-insensitive).
4. Password must not appear in the configurable blacklist (`data/weak_passwords.txt`).
5. Leading/trailing whitespace is prohibited to avoid accidental padding.

The `PasswordPolicy` class exposes `validate(username, password)` which returns a `PasswordCheckResult` listing any violations, enabling the CLI to give actionable feedback.

## (c) Testing

- `tests/test_password_policy.py` exercises each rule individually (length, missing character classes, username match, blacklist membership, and a passing case).
- `tests/test_enrollment.py` covers:
  1. Successful enrollment (verifies entries in both `passwd.txt` and `users.json`).
  2. Duplicate username handling (second enrollment attempt fails).
  3. Rejection when a role is not eligible for self-service signup.

Together, these tests confirm that the proactive password checker blocks bad passwords and that the enrollment pipeline correctly updates the credential store while enforcing business constraints.

