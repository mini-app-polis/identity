"""The Python binding against the shared fixture suite.

This file is the Python half of a cross-language contract. When the
TypeScript binding lands it gets its own runner over these same fixtures,
and the two must agree case for case. Changing an expected value here
without changing it there is the failure mode this suite exists to catch.
"""

from __future__ import annotations

import uuid

import pytest

from identity.policy import authorize
from identity.types import Principal, Role


def _roles(fixture_roles: dict) -> dict[str, Role]:
    return {
        r["name"]: Role(
            name=r["name"],
            scopes=frozenset(r["scopes"]),
            description=r.get("description", ""),
        )
        for r in fixture_roles["roles"]
    }


def _principal(raw: dict | None) -> Principal | None:
    if raw is None:
        return None
    return Principal(
        id=uuid.UUID(raw["id"]),
        kind=raw["kind"],
        issuer=raw["issuer"],
        subject=raw["subject"],
        roles=tuple(raw["roles"]),
        status=raw["status"],
    )


def test_fixture_suite_is_not_empty(authorize_cases: list[dict]) -> None:
    assert len(authorize_cases) >= 10


def test_every_case_runs(authorize_cases: list[dict], fixture_roles: dict) -> None:
    """Belt and braces: parametrization below would silently pass on an empty suite."""
    assert {c["name"] for c in authorize_cases}


@pytest.mark.parametrize("case_index", range(13))
def test_authorize_matches_fixture(
    case_index: int, authorize_cases: list[dict], fixture_roles: dict
) -> None:
    case = authorize_cases[case_index]
    grants = {tuple(g) for g in case.get("explicit_grants", [])}

    decision = authorize(
        _principal(case["principal"]),
        case["scope"],
        _roles(fixture_roles),
        resource=case.get("resource"),
        explicit_grants=grants or None,
    )

    expected = case["expected"]
    assert decision.allowed is expected["allowed"], case["name"]
    assert decision.reason == expected["reason"], case["name"]
    assert decision.matched_role == expected["matched_role"], case["name"]
    assert decision.scope == case["scope"], case["name"]
