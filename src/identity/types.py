"""Types mirroring the JSON Schemas in ``schema/``.

The schemas are the source of truth; these dataclasses are the Python
projection of them. The fixture suite in ``fixtures/`` is what keeps the two
honest — every binding, in every language, must produce these values from
those inputs.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import Literal

PrincipalKind = Literal["human", "machine"]
PrincipalStatus = Literal["active", "suspended"]

DecisionReason = Literal[
    "granted_by_role",
    "granted_by_explicit_grant",
    "no_matching_scope",
    "principal_suspended",
    "principal_not_found",
    "issuer_not_trusted",
    "credential_invalid",
]


@dataclass(frozen=True, slots=True)
class VerifiedSubject:
    """What ``verify`` returns: an authenticated subject, and nothing more.

    This is intentionally not a Principal. Verification proves who the issuer
    says you are; it says nothing about what this ecosystem knows about you.
    Collapsing the two is how ``sub`` ends up used as a primary key.
    """

    issuer: str
    subject: str
    kind: PrincipalKind
    claims: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class Role:
    name: str
    scopes: frozenset[str]
    description: str = ""


@dataclass(frozen=True, slots=True)
class Principal:
    """What ``resolve`` returns: this ecosystem's record of a verified subject."""

    id: uuid.UUID
    kind: PrincipalKind
    issuer: str
    subject: str
    roles: tuple[str, ...]
    status: PrincipalStatus
    display_name: str = ""
    email: str | None = None
    created_at: dt.datetime | None = None
    last_seen_at: dt.datetime | None = None


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """What ``authorize`` returns — for allow and deny alike."""

    allowed: bool
    scope: str
    reason: DecisionReason
    principal_id: uuid.UUID | None = None
    resource: str | None = None
    matched_role: str | None = None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """What ``emit_audit`` records."""

    event_id: uuid.UUID
    occurred_at: dt.datetime
    enforcement_point: str
    scope: str
    allowed: bool
    reason: DecisionReason
    principal_id: uuid.UUID | None = None
    principal_kind: PrincipalKind | None = None
    issuer: str | None = None
    subject: str | None = None
    resource: str | None = None
    request_id: str | None = None
