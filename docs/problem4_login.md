# Problem 4 – User Login

## (a) Login Interface

- CLI entry point: `Problem4.py`.
- Workflow: prompt for username/password (password via `getpass`), invoke `perform_login(...)` which reuses the `passwd.txt` store and PBKDF2 verification functions built in Problem 2.
- Error feedback: invalid username/password combinations and missing roles produce `ACCESS DENIED` messages.

## (b) Displaying Access Privileges

After successful login, the CLI prints:

1. Username.
2. Role label and identifier (e.g., `Client (client)`).
3. Enumerated authorized operations (codes + human-readable labels) derived from the RBAC engine and the access-control policy defined in `data/roles.json`.

`justinvest/login.py` wraps this logic, ensuring that the access-control policy has the final say on permissible operations (including contextual constraints like Teller business hours).

## (c) Testing

`tests/test_login.py` covers:

1. Successful login for a Client, verifying both authentication and the returned permission list.
2. Invalid password attempts, ensuring they are rejected.
3. Handling of malformed data (user record referencing an unknown role), which must produce a failure instead of silently granting access.

These tests, combined with the existing RBAC suite, demonstrate that login and authorization behave correctly under normal and error conditions.

