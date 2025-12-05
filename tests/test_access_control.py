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


def test_client_permissions(engine: AccessControlEngine) -> None:
    """verifies that clients can only view their balance, portfolio, and advisor contact."""
    labels = permitted_labels(engine, "client", 11)
    assert labels == [
        "View account balance",
        "View investment portfolio",
        "View Financial Advisor contact info",
    ]


def test_premium_client_permissions(engine: AccessControlEngine) -> None:
    """verifies that premium clients can modify portfolios and view planner contact info."""
    labels = permitted_labels(engine, "premium_client", 11)
    assert "Modify investment portfolio" in labels
    assert "View Financial Planner contact info" in labels
    assert len(labels) == 5


def test_financial_advisor_permissions(
    engine: AccessControlEngine,
) -> None:
    """verifies that advisors can modify portfolios and view private instruments, but not money market."""
    labels = permitted_labels(engine, "financial_advisor", 11)
    assert "Modify investment portfolio" in labels
    assert "View private consumer instruments" in labels
    assert "View money market instruments" not in labels


def test_financial_planner_permissions(engine: AccessControlEngine) -> None:
    """verifies that planners can view both money market and private consumer instruments."""
    labels = permitted_labels(engine, "financial_planner", 11)
    assert "View money market instruments" in labels
    assert "View private consumer instruments" in labels


def test_teller_constraints(engine: AccessControlEngine) -> None:
    """verifies that tellers are blocked outside business hours but allowed during them."""
    after_hours_context = SessionContext(as_of=datetime(2025, 1, 1, 20, 0))
    assert engine.permitted_operations("teller", after_hours_context) == []
    business_hours_context = SessionContext(as_of=datetime(2025, 1, 1, 10, 0))
    codes = engine.permitted_operations("teller", business_hours_context)
    assert len(codes) == 2


def test_authenticate_success(credentials: CredentialStore) -> None:
    """verifies that valid credentials authenticate successfully and return the correct role."""
    user = credentials.authenticate("sasha.kim", "Aster!1A")
    assert user is not None
    assert user.role == "client"


def test_authenticate_invalid_password(credentials: CredentialStore) -> None:
    """verifies that incorrect passwords are rejected."""
    assert credentials.authenticate("sasha.kim", "wrongpass") is None


def test_access_denied_for_disallowed_operation(engine: AccessControlEngine) -> None:
    """verifies that clients are denied access to operations they don't have permission for."""
    decision = engine.is_operation_allowed(
        "client",
        "MODIFY_INVESTMENT_PORTFOLIO",
        SessionContext(as_of=datetime(2025, 1, 1, 11, 0)),
    )
    assert not decision.granted
    assert "lacks 'MODIFY_INVESTMENT_PORTFOLIO'" in (decision.reason or "")
