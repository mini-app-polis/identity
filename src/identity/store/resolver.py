"""SQLAlchemy-backed ``resolve`` and ``emit_audit``.

Two of the four contract functions. ``verify`` lives in ``identity.clerk``
because it talks to an issuer, not a database; ``authorize`` lives in
``identity.policy`` because it talks to neither.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..types import AuditEvent, Principal, Role, VerifiedSubject
from .models import (
    AuditEventRow,
    ExplicitGrant,
    PrincipalRole,
    RoleScope,
)
from .models import Principal as PrincipalRow
from .models import Role as RoleRow

_log = logging.getLogger(__name__)


class SqlAlchemyPrincipalStore:
    """Resolves verified subjects against one ecosystem's principal store."""

    def __init__(self, session: AsyncSession, *, enforcement_point: str) -> None:
        self._session = session
        self._enforcement_point = enforcement_point

    @property
    def enforcement_point(self) -> str:
        return self._enforcement_point

    async def resolve(self, subject: VerifiedSubject) -> Principal | None:
        """Look up ``(issuer, subject)``. Returns None when unknown here.

        None is not an error: a valid token from a trusted issuer for someone
        this ecosystem has never seen is an expected state, and the caller may
        legitimately provision on first sight.
        """
        row = (
            (
                await self._session.execute(
                    select(PrincipalRow).where(
                        PrincipalRow.issuer == subject.issuer,
                        PrincipalRow.subject == subject.subject,
                    )
                )
            )
            .scalars()
            .first()
        )
        if row is None:
            return None

        role_names = (
            (
                await self._session.execute(
                    select(PrincipalRole.role_name)
                    .where(PrincipalRole.principal_id == row.id)
                    .order_by(PrincipalRole.role_name)
                )
            )
            .scalars()
            .all()
        )

        return Principal(
            id=row.id,
            kind=row.kind,  # type: ignore[arg-type]
            issuer=row.issuer,
            subject=row.subject,
            roles=tuple(role_names),
            status=row.status,  # type: ignore[arg-type]
            display_name=row.display_name,
            email=row.email,
            created_at=row.created_at,
            last_seen_at=row.last_seen_at,
        )

    async def load_roles(self) -> dict[str, Role]:
        """Load the role table this enforcement point decides against."""
        rows = (await self._session.execute(select(RoleRow))).scalars().all()
        scopes_by_role: dict[str, set[str]] = {r.name: set() for r in rows}
        for role_name, scope in (
            await self._session.execute(select(RoleScope.role_name, RoleScope.scope))
        ).all():
            scopes_by_role.setdefault(role_name, set()).add(scope)
        return {
            r.name: Role(
                name=r.name,
                scopes=frozenset(scopes_by_role.get(r.name, set())),
                description=r.description,
            )
            for r in rows
        }

    async def load_explicit_grants(
        self, principal_id: uuid.UUID
    ) -> set[tuple[str, str]]:
        rows = (
            await self._session.execute(
                select(ExplicitGrant.scope, ExplicitGrant.resource).where(
                    ExplicitGrant.principal_id == principal_id
                )
            )
        ).all()
        return {(scope, resource) for scope, resource in rows}


class SqlAlchemyAuditSink:
    """Writes audit events. Never raises into the request path."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def emit_audit(self, event: AuditEvent) -> None:
        """Record one decision.

        Failures are logged and swallowed on purpose. An audit sink that can
        fail a request converts an observability outage into a service
        outage; the sink's own health is monitored separately.
        """
        try:
            self._session.add(
                AuditEventRow(
                    event_id=event.event_id,
                    occurred_at=event.occurred_at,
                    enforcement_point=event.enforcement_point,
                    principal_id=event.principal_id,
                    principal_kind=event.principal_kind,
                    issuer=event.issuer,
                    subject=event.subject,
                    scope=event.scope,
                    resource=event.resource,
                    allowed=event.allowed,
                    reason=event.reason,
                    request_id=event.request_id,
                )
            )
            await self._session.commit()
        except Exception as exc:  # noqa: BLE001 - deliberate: see docstring
            _log.warning("[identity] audit emit failed: %r", exc)
            try:
                await self._session.rollback()
            except Exception as rollback_exc:  # noqa: BLE001
                _log.debug("[identity] audit rollback failed: %r", rollback_exc)


def new_audit_event(
    *,
    enforcement_point: str,
    scope: str,
    allowed: bool,
    reason: str,
    principal: Principal | None = None,
    subject: VerifiedSubject | None = None,
    resource: str | None = None,
    request_id: str | None = None,
) -> AuditEvent:
    """Build an event from whatever is known at the point of decision.

    Both ``principal`` and ``subject`` are optional because the interesting
    denials happen when one or both are missing: a forged credential has
    neither, an unknown-but-valid token has a subject and no principal.
    """
    return AuditEvent(
        event_id=uuid.uuid4(),
        occurred_at=dt.datetime.now(dt.UTC),
        enforcement_point=enforcement_point,
        scope=scope,
        allowed=allowed,
        reason=reason,  # type: ignore[arg-type]
        principal_id=principal.id if principal else None,
        principal_kind=principal.kind if principal else None,
        issuer=principal.issuer if principal else (subject.issuer if subject else None),
        subject=principal.subject
        if principal
        else (subject.subject if subject else None),
        resource=resource,
        request_id=request_id,
    )
