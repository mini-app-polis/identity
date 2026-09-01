"""The schemas are the source of truth; these tests keep them loadable and
keep the fixtures honest against them."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

SCOPE_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*){2}$")
ROLE_RE = re.compile(r"^[a-z][a-z0-9-]*$")

SCHEMA_FILES = [
    "principal.schema.json",
    "role.schema.json",
    "authorization-decision.schema.json",
    "audit-event.schema.json",
]


@pytest.mark.parametrize("name", SCHEMA_FILES)
def test_schema_parses_and_is_identified(name: str, schema_dir: Path) -> None:
    doc = json.loads((schema_dir / name).read_text())
    assert doc["$schema"].startswith("https://json-schema.org/draft/")
    assert doc["$id"].endswith(name)
    assert doc["title"]


def test_fixture_roles_conform_to_role_grammar(fixture_roles: dict) -> None:
    for role in fixture_roles["roles"]:
        assert ROLE_RE.match(role["name"]), role["name"]
        assert role["scopes"], role["name"]
        for scope in role["scopes"]:
            assert SCOPE_RE.match(scope), scope


def test_every_scope_in_authorize_cases_is_well_formed(
    authorize_cases: list[dict],
) -> None:
    for case in authorize_cases:
        assert SCOPE_RE.match(case["scope"]), case["name"]


def test_decision_reasons_in_fixtures_are_declared_in_schema(
    authorize_cases: list[dict], schema_dir: Path
) -> None:
    doc = json.loads((schema_dir / "authorization-decision.schema.json").read_text())
    allowed = set(doc["properties"]["reason"]["enum"])
    for case in authorize_cases:
        assert case["expected"]["reason"] in allowed, case["name"]
