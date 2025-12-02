"""Definitions for system operations and helper utilities."""

from dataclasses import dataclass
from typing import Dict, List


@dataclass(frozen=True)
class Operation:
    """Represents a business operation exposed by the justInvest prototype."""

    code: str
    label: str
    description: str


ALL_OPERATIONS: List[Operation] = [
    Operation(
        code="VIEW_ACCOUNT_BALANCE",
        label="View account balance",
        description="Display the latest balance for the authenticated client's account.",
    ),
    Operation(
        code="VIEW_INVESTMENT_PORTFOLIO",
        label="View investment portfolio",
        description="Display holdings and allocations for the authenticated client's portfolio.",
    ),
    Operation(
        code="MODIFY_INVESTMENT_PORTFOLIO",
        label="Modify investment portfolio",
        description="Create or update investment allocations for a client.",
    ),
    Operation(
        code="VIEW_FINANCIAL_ADVISOR_CONTACT",
        label="View Financial Advisor contact info",
        description="Display contact information for the assigned Financial Advisor.",
    ),
    Operation(
        code="VIEW_FINANCIAL_PLANNER_CONTACT",
        label="View Financial Planner contact info",
        description="Display contact information for the assigned Financial Planner.",
    ),
    Operation(
        code="VIEW_MONEY_MARKET_INSTRUMENTS",
        label="View money market instruments",
        description="Display available money market instruments.",
    ),
    Operation(
        code="VIEW_PRIVATE_CONSUMER_INSTRUMENTS",
        label="View private consumer instruments",
        description="Display private consumer instruments available to advisors/planners.",
    ),
]


OPERATIONS_BY_CODE: Dict[str, Operation] = {op.code: op for op in ALL_OPERATIONS}


def format_operations_menu() -> str:
    """Return a numbered menu string for CLI presentation."""

    lines = ["Operations available on the system:"]
    for index, operation in enumerate(ALL_OPERATIONS, start=1):
        lines.append(f"{index}. {operation.label}")
    return "\n".join(lines)

