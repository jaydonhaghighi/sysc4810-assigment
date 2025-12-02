# Problem 1 – Access Control Mechanism (justInvest)

## (a) Access Control Model Selection

I selected **Role-Based Access Control (RBAC)** augmented with constraint handling (specifically time-based constraints for Tellers). RBAC satisfies justInvest’s requirements because:

- The policy is already role-centric (Clients, Premium Clients, Financial Advisors, Financial Planners, Tellers, general employees). Mapping permissions to roles directly encodes the rules without listing object-level ACLs.
- Onboarding, offboarding, or role changes only require updating user-to-role assignments or the JSON role definition—no code changes—aligning with the client request for operational flexibility.
- RBAC is broadly adopted, well understood, and compatible with least-privilege enforcement and separation of duties should the policy expand.
- Constraints such as “Teller access between 09:00–17:00” are handled as role constraints without affecting other roles or permissions.

## (b) Access Control Sketch

The RBAC mapping is captured in JSON (`data/roles.json`) and summarized below. A ✅ indicates that the role has the permission; a 🚫 indicates that it does not. The Teller role includes a time-window constraint (09:00–17:00 local time) that must be satisfied before any permission is granted.

| Operation / Role                         | Client | Premium Client | Financial Advisor | Financial Planner | Teller (09:00–17:00) |
|-----------------------------------------|:------:|:--------------:|:-----------------:|:-----------------:|:--------------------:|
| View account balance                    |   ✅   |       ✅       |        ✅         |        ✅         |          ✅           |
| View investment portfolio               |   ✅   |       ✅       |        ✅         |        ✅         |          ✅           |
| Modify investment portfolio             |   🚫   |       ✅       |        ✅         |        ✅         |          🚫           |
| View Financial Advisor contact info     |   ✅   |       ✅       |        🚫         |        🚫         |          🚫           |
| View Financial Planner contact info     |   🚫   |       ✅       |        🚫         |        🚫         |          🚫           |
| View money market instruments           |   🚫   |       🚫       |        🚫         |        ✅         |          🚫           |
| View private consumer instruments       |   🚫   |       🚫       |        ✅         |        ✅         |          🚫           |

This table doubles as the “sketch” requested in the report. Because the definitions live in JSON, adding new roles or modifying permissions does not require touching the Python code.

## (c) Implementation & Testing Summary

- **Implementation:** `Problem1c.py` wires together the RBAC engine (`justinvest/access_control.py`), credential store (`justinvest/authentication.py`), and JSON data sources (`data/users.json`, `data/roles.json`) to present the CLI described in the assignment. Sample operations are defined in `justinvest/operations.py`.
- **Testing:** Automated tests in `tests/test_access_control.py` exercise every role/permission combination, ensure the teller time-window constraint both allows and denies access at appropriate hours, and verify authentication success/failure paths.
- **Test coverage reasoning:** Each user category, each special permission (e.g., modify portfolio, instrument visibility), and the unique Teller constraint are covered. Adding more roles or constraints would only require new fixture data plus corresponding assertions.

