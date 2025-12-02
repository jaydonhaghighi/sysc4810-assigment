# justInvest Access Control Prototype

This repository hosts the deliverables for **Problem 1** of the justInvest assignment. The prototype demonstrates a Role-Based Access Control (RBAC) mechanism, credential storage, and automated tests that enforce the policy requirements described in the assignment brief.

## Repository Layout

- `Problem1c.py` – CLI entry point that prints the operations menu, prompts for credentials, and enforces authorization decisions.
- `justinvest/` – Python package containing reusable modules:
  - `operations.py` – canonical list of system operations.
  - `models.py`, `repository.py` – data models and JSON loading helpers.
  - `access_control.py` – RBAC engine plus constraint evaluation (e.g., Teller business hours).
  - `authentication.py` – PBKDF2-based credential verification.
  - `password_file.py` – helpers to append/read/verify entries in `passwd.txt`.
  - `password_policy.py` – proactive password checker.
  - `enrollment.py` – reusable enrollment workflow functions.
- `data/roles.json` | `data/users.json` – editable data sources for roles/permissions and sample users (no code changes needed when roles or assignments change).
- `passwd.txt` – plaintext password file described in Problem 2.
- `data/weak_passwords.txt` – blacklist consumed by the password policy.
- `docs/problem1_access_control.md` – report-ready notes covering model selection, RBAC sketch, and test summary.
- `docs/problem2_password_file.md` – report-ready notes covering password-hash selection, file format, and tests.
- `docs/problem3_enrolment.md` – report-ready notes covering the signup UI, password checker, and tests.
- `docs/problem4_login.md` – report-ready notes covering login UI, privilege display, and tests.
- `tests/test_access_control.py` – automated coverage for every role/permission combination, Teller constraint, and authentication success/failure cases.
- `tests/test_password_file.py` – exercises password file CRUD and verification paths.
- `tests/test_password_policy.py` – validates each password-policy rule.
- `tests/test_enrollment.py` – covers successful signup, duplicate rejection, and role gating.
- `tests/test_login.py` – validates the login workflow and privilege computation.

## Requirements

- Python ≥ 3.10 (assignment target is 3.12.3 on Ubuntu 24.04.3).
- `python3 -m venv` to create isolated environments (bundled with Python 3.10+).

## Setup (recommended virtual environment)

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Each grading run on Ubuntu 24.04.3 can repeat the same steps to recreate your environment. When you’re done working locally, run `deactivate` to exit the virtual environment.

## Running the Prototype

```bash
python3 Problem1c.py
```

You will see the operations menu, then be prompted for a username and password. Sample usernames match the provided roster (e.g., `sasha.kim`, `harper.diaz`). Passwords follow the policy (e.g., `Aster!1A` for Sasha Kim); see `data/users.json` if you need to reset or add accounts.

## Running the Tests

```bash
source .venv/bin/activate  # if not already active
python3 -m pytest
```

## Self-Service Signup

```bash
python3 Problem3.py
```

You will be prompted for:

1. Username.
2. Eligible role (Client or Premium Client, as defined by `allow_self_signup` in `data/roles.json`).
3. Password (with confirmation). The CLI enforces the proactive password policy and explains any violations.

Successful enrollment appends the new record to `passwd.txt` and updates `data/users.json`, enabling immediate login through `Problem1c.py`.

## Login Portal

```bash
python3 Problem4.py
```

Enter the username/password of an enrolled account (e.g., `sasha.kim` / `Aster!1A`). Upon success the CLI prints the user’s role and enumerates all operations authorized by the RBAC policy. Failed attempts reuse the hardened password verification logic from Problem 2.

## Password File Helpers

The `passwd.txt` file at the project root stores user credentials in the format `<username>|<role>|pbkdf2_sha256$…`. Use `justinvest.password_file.add_record()` to enroll new accounts—it hashes the password and appends a new line. `verify_credentials()` reads the file and replays PBKDF2 to authenticate login attempts, while `get_record()` exposes entries for integration with the RBAC layer. Tests in `tests/test_password_file.py` cover enrollment, login, and duplicate detection.

The suite validates:

1. Each role’s permitted operations.
2. Teller access restrictions inside/outside the 09:00–17:00 window.
3. Authentication success for valid credentials and rejection for invalid passwords.

## Extending the Prototype

- **Add users**: append an entry to `data/users.json` and provide a PBKDF2 hash in the `pbkdf2_sha256$iterations$salt$hash` format. Helper utilities can be added later to automate hash creation.
- **Modify roles or permissions**: edit `data/roles.json`. The CLI and policy engine load the file at runtime, so no Python changes are required.
- **Add constraints**: extend the JSON with constraint definitions (e.g., new time windows) and add the corresponding evaluator to `justinvest/access_control.py`.

These steps ensure the system remains configurable without altering source code, satisfying the client’s maintainability requirement.