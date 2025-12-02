"""RBAC-based access control engine for justInvest."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time
from typing import Dict, Iterable, List, Protocol, Sequence

from .models import (
    AuthorizationDecision,
    ConstraintDefinition,
    RoleDefinition,
    SessionContext,
    build_role_lookup,
)


class ConstraintEvaluator(Protocol):
    """Protocol implemented by constraint evaluators."""

    def evaluate(self, context: SessionContext) -> AuthorizationDecision:
        ...


@dataclass
class TimeWindowConstraint:
    """Constraint ensuring access is only allowed during a specific time window."""

    start: time
    end: time

    def evaluate(self, context: SessionContext) -> AuthorizationDecision:
        current_time = context.as_of.time()
        if self.start <= current_time <= self.end:
            return AuthorizationDecision(granted=True)
        return AuthorizationDecision(
            granted=False,
            reason=(
                "Access restricted to business hours "
                f"{self.start.strftime('%H:%M')}–{self.end.strftime('%H:%M')}."
            ),
        )


class ConstraintFactory:
    """Factory that builds constraint evaluators from definitions."""

    def __init__(self) -> None:
        self._builders = {
            "time_window": self._build_time_window,
        }

    def build(self, definition: ConstraintDefinition) -> ConstraintEvaluator:
        if definition.type not in self._builders:
            raise ValueError(f"Unsupported constraint type: {definition.type}")
        return self._builders[definition.type](definition.params)

    def _build_time_window(self, params: Dict[str, str]) -> ConstraintEvaluator:
        start_raw = params.get("start")
        end_raw = params.get("end")
        if not start_raw or not end_raw:
            raise ValueError("time_window constraint requires 'start' and 'end'")
        start = datetime.strptime(start_raw, "%H:%M").time()
        end = datetime.strptime(end_raw, "%H:%M").time()
        return TimeWindowConstraint(start=start, end=end)


class AccessControlEngine:
    """Enforces justInvest's access control policy via RBAC."""

    def __init__(self, roles: Iterable[RoleDefinition]) -> None:
        self._roles = build_role_lookup(roles)
        self._constraint_factory = ConstraintFactory()

    def get_role(self, role_name: str) -> RoleDefinition:
        if role_name not in self._roles:
            raise KeyError(f"Unknown role '{role_name}'")
        return self._roles[role_name]

    def _evaluate_role_constraints(
        self, role: RoleDefinition, context: SessionContext
    ) -> AuthorizationDecision:
        for definition in role.constraints:
            evaluator = self._constraint_factory.build(definition)
            decision = evaluator.evaluate(context)
            if not decision.granted:
                return decision
        return AuthorizationDecision(granted=True)

    def is_operation_allowed(
        self,
        role_name: str,
        permission_code: str,
        context: SessionContext | None = None,
    ) -> AuthorizationDecision:
        context = context or SessionContext(as_of=datetime.now())
        role = self.get_role(role_name)
        if not role.allows(permission_code):
            return AuthorizationDecision(
                granted=False, reason=f"Role '{role.label}' lacks '{permission_code}'."
            )
        constraint_decision = self._evaluate_role_constraints(role, context)
        if not constraint_decision.granted:
            return constraint_decision
        return AuthorizationDecision(granted=True)

    def permitted_operations(
        self, role_name: str, context: SessionContext | None = None
    ) -> List[str]:
        context = context or SessionContext(as_of=datetime.now())
        role = self.get_role(role_name)
        constraint_decision = self._evaluate_role_constraints(role, context)
        if not constraint_decision.granted:
            return []
        return sorted(role.permissions)

