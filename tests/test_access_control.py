"\"\"\"Automated tests for Problem 1 access control implementation.\"\"\""

from datetime import datetime

import pytest

from justinvest.access_control import AccessControlEngine
from justinvest.authentication import CredentialStore
from justinvest.models import SessionContext
from justinvest.operations import ALL_OPERATIONS
from justinvest.repository import load_roles, load_users


@pytest.fixture(scope="module")
def engine() -> AccessControlEngine:
    roles = load_roles()
    return AccessControlEngine(roles)


@pytest.fixture(scope="module")
def credentials() -> CredentialStore:
    users = load_users()
    return CredentialStore(users)


def permitted_labels(engine: AccessControlEngine, role: str, hour: int) -> list[str]:
    context = SessionContext(as_of=datetime(2025, 1, 1, hour, 0))
    permitted_codes = engine.permitted_operations(role, context)
    return [op.label for op in ALL_OPERATIONS if op.code in permitted_codes]


def test_clients_have_read_only_permissions(engine: AccessControlEngine) -> None:
    labels = permitted_labels(engine, "client", 11)
    assert labels == [
        "View account balance",
        "View investment portfolio",
        "View Financial Advisor contact info",
    ]


def test_premium_clients_gain_additional_permissions(engine: AccessControlEngine) -> None:
    labels = permitted_labels(engine, "premium_client", 11)
    assert "Modify investment portfolio" in labels
    assert "View Financial Planner contact info" in labels
    assert len(labels) == 5


def test_advisors_can_modify_and_view_private_instruments(
    engine: AccessControlEngine,
) -> None:
    labels = permitted_labels(engine, "financial_advisor", 11)
    assert "Modify investment portfolio" in labels
    assert "View private consumer instruments" in labels
    assert "View money market instruments" not in labels


def test_planners_can_view_money_market(engine: AccessControlEngine) -> None:
    labels = permitted_labels(engine, "financial_planner", 11)
    assert "View money market instruments" in labels
    assert "View private consumer instruments" in labels


def test_tellers_blocked_outside_business_hours(engine: AccessControlEngine) -> None:
    after_hours_context = SessionContext(as_of=datetime(2025, 1, 1, 20, 0))
    assert engine.permitted_operations("teller", after_hours_context) == []
    business_hours_context = SessionContext(as_of=datetime(2025, 1, 1, 10, 0))
    codes = engine.permitted_operations("teller", business_hours_context)
    assert len(codes) == 2


def test_authentication_succeeds_with_valid_credentials(credentials: CredentialStore) -> None:
    user = credentials.authenticate("sasha.kim", "Aster!1A")
    assert user is not None
    assert user.role == "client"


def test_authentication_rejects_invalid_password(credentials: CredentialStore) -> None:
    assert credentials.authenticate("sasha.kim", "wrongpass") is None


def test_access_denied_for_disallowed_operation(engine: AccessControlEngine) -> None:
    decision = engine.is_operation_allowed(
        "client",
        "MODIFY_INVESTMENT_PORTFOLIO",
        SessionContext(as_of=datetime(2025, 1, 1, 11, 0)),
    )
    assert not decision.granted
    assert "lacks 'MODIFY_INVESTMENT_PORTFOLIO'" in (decision.reason or "")

