"""The SQLAlchemy store, exercised on SQLite.

Running these on SQLite is the point, not a shortcut: the Python enforcement
point's own test suite is SQLite in-memory, so a store that needed Postgres
would be a store its host could not test against.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from identity.policy import authorize
from identity.store import (
    ExplicitGrant,
    IdentityBase,
    Issuer,
    Principal,
    PrincipalRole,
    Role,
    RoleScope,
    SqlAlchemyAuditSink,
    SqlAlchemyPrincipalStore,
    new_audit_event,
)
from identity.store.models import AuditEventRow
from identity.types import VerifiedSubject

ISSUER_A = "https://clerk.kaianolevine.com"
ISSUER_B = "https://clerk.deejaytools.com"


@pytest.fixture
async def session():
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    async with engine.begin() as conn:
        await conn.run_sync(IdentityBase.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        yield s
    await engine.dispose()


async def _seed(s: AsyncSession) -> dict[str, uuid.UUID]:
    s.add_all(
        [
            Issuer(issuer=ISSUER_A, jwks_url=f"{ISSUER_A}/.well-known/jwks.json"),
            Issuer(issuer=ISSUER_B, jwks_url=f"{ISSUER_B}/.well-known/jwks.json"),
            Role(name="catalog-ingest", description="DJ set ingest"),
            RoleScope(role_name="catalog-ingest", scope="catalog.sets.write"),
            Role(name="wcs-reader", description="read notes"),
            RoleScope(role_name="wcs-reader", scope="wcs.notes.read"),
        ]
    )
    await s.flush()

    machine_id = uuid.uuid4()
    human_id = uuid.uuid4()
    collider_id = uuid.uuid4()
    s.add_all(
        [
            Principal(
                id=machine_id,
                kind="machine",
                issuer=ISSUER_A,
                subject="mch_deejay_cog",
                display_name="deejay-cog",
            ),
            Principal(id=human_id, kind="human", issuer=ISSUER_A, subject="user_1"),
            # Same subject string, different tenant. This row is the reason
            # principals have their own id rather than keying on `sub`.
            Principal(id=collider_id, kind="human", issuer=ISSUER_B, subject="user_1"),
            PrincipalRole(principal_id=machine_id, role_name="catalog-ingest"),
            PrincipalRole(principal_id=human_id, role_name="wcs-reader"),
        ]
    )
    await s.commit()
    return {"machine": machine_id, "human": human_id, "collider": collider_id}


async def test_resolve_returns_none_for_unknown_subject(session: AsyncSession) -> None:
    await _seed(session)
    store = SqlAlchemyPrincipalStore(session, enforcement_point="test")
    got = await store.resolve(
        VerifiedSubject(issuer=ISSUER_A, subject="nobody", kind="human")
    )
    assert got is None


async def test_same_subject_in_two_tenants_resolves_to_different_principals(
    session: AsyncSession,
) -> None:
    ids = await _seed(session)
    store = SqlAlchemyPrincipalStore(session, enforcement_point="test")

    a = await store.resolve(
        VerifiedSubject(issuer=ISSUER_A, subject="user_1", kind="human")
    )
    b = await store.resolve(
        VerifiedSubject(issuer=ISSUER_B, subject="user_1", kind="human")
    )

    assert a is not None and b is not None
    assert a.id == ids["human"]
    assert b.id == ids["collider"]
    assert a.id != b.id


async def test_machine_resolves_with_its_roles(session: AsyncSession) -> None:
    ids = await _seed(session)
    store = SqlAlchemyPrincipalStore(session, enforcement_point="test")

    p = await store.resolve(
        VerifiedSubject(issuer=ISSUER_A, subject="mch_deejay_cog", kind="machine")
    )
    assert p is not None
    assert p.id == ids["machine"]
    assert p.kind == "machine"
    assert p.roles == ("catalog-ingest",)


async def test_end_to_end_resolve_then_authorize(session: AsyncSession) -> None:
    await _seed(session)
    store = SqlAlchemyPrincipalStore(session, enforcement_point="test")
    roles = await store.load_roles()

    p = await store.resolve(
        VerifiedSubject(issuer=ISSUER_A, subject="mch_deejay_cog", kind="machine")
    )
    allow = authorize(p, "catalog.sets.write", roles)
    deny = authorize(p, "wcs.notes.write", roles)

    assert allow.allowed and allow.reason == "granted_by_role"
    assert allow.matched_role == "catalog-ingest"
    assert not deny.allowed and deny.reason == "no_matching_scope"


async def test_explicit_grants_round_trip(session: AsyncSession) -> None:
    ids = await _seed(session)
    session.add(
        ExplicitGrant(
            principal_id=ids["human"], scope="wcs.notes.write", resource="note-42"
        )
    )
    await session.commit()

    store = SqlAlchemyPrincipalStore(session, enforcement_point="test")
    grants = await store.load_explicit_grants(ids["human"])
    assert grants == {("wcs.notes.write", "note-42")}

    roles = await store.load_roles()
    p = await store.resolve(
        VerifiedSubject(issuer=ISSUER_A, subject="user_1", kind="human")
    )
    d = authorize(
        p, "wcs.notes.write", roles, resource="note-42", explicit_grants=grants
    )
    assert d.allowed and d.reason == "granted_by_explicit_grant"


async def test_audit_records_denials_too(session: AsyncSession) -> None:
    ids = await _seed(session)
    store = SqlAlchemyPrincipalStore(session, enforcement_point="api-test")
    sink = SqlAlchemyAuditSink(session)
    roles = await store.load_roles()

    p = await store.resolve(
        VerifiedSubject(issuer=ISSUER_A, subject="user_1", kind="human")
    )
    decision = authorize(p, "wcs.notes.write", roles)
    await sink.emit_audit(
        new_audit_event(
            enforcement_point="api-test",
            scope=decision.scope,
            allowed=decision.allowed,
            reason=decision.reason,
            principal=p,
        )
    )

    from sqlalchemy import select

    rows = (await session.execute(select(AuditEventRow))).scalars().all()
    assert len(rows) == 1
    assert rows[0].allowed is False
    assert rows[0].reason == "no_matching_scope"
    assert rows[0].principal_id == ids["human"]
    assert rows[0].enforcement_point == "api-test"


async def test_audit_survives_principal_deletion(session: AsyncSession) -> None:
    """The trail must not erase itself when the principal is removed."""
    ids = await _seed(session)
    sink = SqlAlchemyAuditSink(session)
    await sink.emit_audit(
        new_audit_event(
            enforcement_point="api-test",
            scope="catalog.sets.write",
            allowed=True,
            reason="granted_by_role",
            principal=await SqlAlchemyPrincipalStore(
                session, enforcement_point="api-test"
            ).resolve(
                VerifiedSubject(
                    issuer=ISSUER_A, subject="mch_deejay_cog", kind="machine"
                )
            ),
        )
    )

    from sqlalchemy import delete, select

    await session.execute(
        delete(PrincipalRole).where(PrincipalRole.principal_id == ids["machine"])
    )
    await session.execute(delete(Principal).where(Principal.id == ids["machine"]))
    await session.commit()

    rows = (await session.execute(select(AuditEventRow))).scalars().all()
    assert len(rows) == 1
    assert rows[0].principal_id == ids["machine"]
