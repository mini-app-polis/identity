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


def pytest_generate_tests(metafunc: pytest.Metafunc) -> None:
    """Parametrize ``authorize_case`` over every case in the fixture file.

    Done at collection time from the file, so the number of tests is the
    number of cases — adding a case adds a test, with no count to update.
    """
    if "authorize_case" in metafunc.fixturenames:
        cases = _load(FIXTURES / "authorize" / "cases.json")["cases"]
        metafunc.parametrize("authorize_case", cases, ids=[c["name"] for c in cases])
