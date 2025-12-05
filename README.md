## Environment Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

## Automated Tests

```bash
source .venv/bin/activate
python3 -m pytest
```

This runs all unit tests, Problems 1–4. Coverage was gathered with:

```bash
coverage run --source=justinvest -m pytest
coverage report
```

## Manual Tests

1. **Access-control CLI**
   ```bash
   python3 Problem1c.py
   ```
   - Use roster credentials from `data/users.json` (e.g., `sasha.kim` / `Aster!1A`).
   - After login, verify only the authorized operations are listed and selectable.

2. **Self-service signup**
   ```bash
   python3 Problem3.py
   ```
   - Enroll a new Client or Premium Client with a compliant password.
   - Confirm the new entry appears in `passwd.txt` and `data/users.json`.
   - Immediately log in via `Problem1c.py` to show the account works.

3. **Login portal overview**
   ```bash
   python3 Problem4.py
   ```
   - Authenticate with any enrolled user and ensure the CLI prints username, role label, and each permitted operation.

4. **Password policy check**
   - During signup, try a known weak password (e.g., `password`) and confirm the CLI rejects it with policy violations.

All data files referenced in the report are already populated.