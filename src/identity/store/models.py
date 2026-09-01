"""SQLAlchemy models for the principal store.

These mirror ``sql/principal-store.sql``. The SQL file is what a Postgres
deployment runs (it carries CHECK constraints that use Postgres regex
operators); these models are what the Python enforcement point queries
through, and they stay portable so the host's test suite can create them on
SQLite.

They hang off their own ``IdentityBase``, not the host application's. An
enforcement point creates both metadatas in its test harness — one explicit
extra line — rather than the store quietly grafting itself onto whatever
declarative base happened to import it.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class IdentityBase(DeclarativeBase):
    """Declarative base owned by the identity package."""


class Issuer(IdentityBase):
    """A trusted token issuer. Multi-issuer by design."""

    __tablename__ = "identity_issuers"

    issuer: Mapped[str] = mapped_column(String, primary_key=True)
    display_name: Mapped[str] = mapped_column(String, nullable=False, default="")
    jwks_url: Mapped[str] = mapped_column(String, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Role(IdentityBase):
    __tablename__ = "identity_roles"

    name: Mapped[str] = mapped_column(String, primary_key=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RoleScope(IdentityBase):
    __tablename__ = "identity_role_scopes"

    role_name: Mapped[str] = mapped_column(
        String, ForeignKey("identity_roles.name", ondelete="CASCADE"), primary_key=True
    )
    scope: Mapped[str] = mapped_column(String, primary_key=True)


class Principal(IdentityBase):
    __tablename__ = "identity_principals"
    __table_args__ = (
        UniqueConstraint(
            "issuer", "subject", name="uq_identity_principal_issuer_subject"
        ),
        Index("idx_identity_principals_issuer_subject", "issuer", "subject"),
    )

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    kind: Mapped[str] = mapped_column(String, nullable=False)
    issuer: Mapped[str] = mapped_column(
        String, ForeignKey("identity_issuers.issuer"), nullable=False
    )
    subject: Mapped[str] = mapped_column(String, nullable=False)
    display_name: Mapped[str] = mapped_column(String, nullable=False, default="")
    email: Mapped[str | None] = mapped_column(String, nullable=True, default=None)
    status: Mapped[str] = mapped_column(String, nullable=False, default="active")
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_seen_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )


class PrincipalRole(IdentityBase):
    __tablename__ = "identity_principal_roles"

    principal_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("identity_principals.id", ondelete="CASCADE"),
        primary_key=True,
    )
    role_name: Mapped[str] = mapped_column(
        String, ForeignKey("identity_roles.name"), primary_key=True
    )
    granted_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    granted_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ExplicitGrant(IdentityBase):
    __tablename__ = "identity_explicit_grants"

    principal_id: Mapped[uuid.UUID] = mapped_column(
        Uuid,
        ForeignKey("identity_principals.id", ondelete="CASCADE"),
        primary_key=True,
    )
    scope: Mapped[str] = mapped_column(String, primary_key=True)
    resource: Mapped[str] = mapped_column(String, primary_key=True)
    granted_by: Mapped[str] = mapped_column(String, nullable=False, default="")
    granted_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuditEventRow(IdentityBase):
    __tablename__ = "identity_audit_events"
    __table_args__ = (
        Index("idx_identity_audit_occurred_at", "occurred_at"),
        Index("idx_identity_audit_principal", "principal_id", "occurred_at"),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    enforcement_point: Mapped[str] = mapped_column(String, nullable=False)
    # No FK to identity_principals: an audit event must survive the deletion of
    # the principal it describes, or the trail erases itself exactly when it
    # matters most.
    principal_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    principal_kind: Mapped[str | None] = mapped_column(String, nullable=True)
    issuer: Mapped[str | None] = mapped_column(String, nullable=True)
    subject: Mapped[str | None] = mapped_column(String, nullable=True)
    scope: Mapped[str] = mapped_column(String, nullable=False)
    resource: Mapped[str | None] = mapped_column(String, nullable=True)
    allowed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(String, nullable=False)
    request_id: Mapped[str | None] = mapped_column(String, nullable=True)
