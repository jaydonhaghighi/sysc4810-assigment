# Problem 2 – Password File

## (a) Hash Function Selection

I am using **PBKDF2 with SHA-256** (`pbkdf2_sha256`) for the password file. Parameters:

- **Iterations:** 600,000 (≈0.1s per hash on the target VM). This slows down brute-force attempts while remaining fast enough for legitimate logins.
- **Salt length:** 16 bytes (128 bits) generated with `secrets.token_bytes()`. This size matches common guidance and eliminates rainbow-table reuse.
- **Derived-key length:** the default 32-byte SHA-256 output, encoded as hex in the file for readability.

PBKDF2 remains FIPS-approved, widely supported in Python’s standard library, and avoids external dependencies—important for the assignment constraints. Salts and iteration counts are stored alongside the hash so the verifier knows how to recompute candidates.

## (b) Password File Structure

Each line of `passwd.txt` stores a record:

```
<username>|<role>|pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
```

- `username`: canonical login identifier (no spaces or pipes).
- `role`: role string consumed by the RBAC engine (e.g., `teller`, `financial_planner`).
- `pbkdf2_sha256$…`: self-describing password hash composed of the algorithm tag, iteration count, salt, and derived key; this mirrors modern `/etc/shadow` formats and enables algorithm agility.

**Example record**

```
sasha.kim|client|pbkdf2_sha256$600000$cda08b5c3c10e5e87b66047848dc26e8$fe8f4482b62938b4e9d682e0ef62cf084c49c955461fbe4cfdaa16d991235ee9
```

The record keeps only the data required to (1) authenticate a user, and (2) link that user to an authorization role—no plaintext or reversible secrets are ever stored.

## (c) Implementation

- `passwd.txt` (root of repo) holds the initial dataset generated from the provided roster.
- `justinvest/password_file.py` defines:
  - `PasswordRecord` dataclass and `parse_record` helpers.
  - `add_record(...)`: sanitizes input, hashes the password with PBKDF2, and appends a new line to `passwd.txt`.
  - `get_record(...)`: retrieves a user’s record from the file.
  - `verify_credentials(...)`: combines `get_record` with the existing PBKDF2 verifier to support authentication during login.

Because the file format is plain text, the functions work for enrollment (append-only) and login (read-only) without requiring a database.

## (d) Testing

Automated tests in `tests/test_password_file.py` provide coverage:

1. **Record retrieval** – confirms that `get_record` returns the expected role for an existing user.
2. **Credential verification** – validates both success and failure cases for `verify_credentials`.
3. **Record creation** – uses a temporary passwd file, calls `add_record`, and asserts that the new line is appended with the correct format.
4. **Duplicate detection** – ensures `add_record` rejects attempts to re-enroll an existing username.

Together, these tests cover the enrollment path, login path, and error-handling behavior required by the assignment.

