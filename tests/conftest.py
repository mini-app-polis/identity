from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "fixtures"
SCHEMA = REPO_ROOT / "schema"


def _load(path: Path) -> dict:
    return json.loads(path.read_text())


@pytest.fixture(scope="session")
def fixture_roles() -> dict:
    return _load(FIXTURES / "roles.json")


@pytest.fixture(scope="session")
def authorize_cases() -> list[dict]:
    return _load(FIXTURES / "authorize" / "cases.json")["cases"]


@pytest.fixture(scope="session")
def schema_dir() -> Path:
    return SCHEMA
