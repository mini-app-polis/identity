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

#: Which of a machine's configured keys a credential matched. A key being
#: rotated out stays accepted as ``previous`` until it is retired; recording
#: the slot is how retirement can tell when nothing presents it any more.
KeySlot = Literal["current", "previous"]

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

    ``key_slot`` is set only by named-key verification, and says which of the
    machine's keys matched. It is a field of its own rather than a claim
    because claims come from the credential: an issuer-signed token could
    carry a claim of any name, and a slot read from one would be whatever the
    token said. None for every other verifier.
    """

    issuer: str
    subject: str
    kind: PrincipalKind
    claims: dict[str, object] = field(default_factory=dict)
    key_slot: KeySlot | None = None


@dataclass(frozen=True, slots=True)
class Role:
    """A named bundle of scopes.

    Roles are the only thing granted. Humans and machines resolve
    through the same vocabulary, so an authorization decision does not
    branch on what kind of principal is asking — which is what keeps
    "is this a service?" from becoming an authority check.
    """

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
    #: Which of a machine's named keys proved it; None for any other
    #: credential. A previous key is retired once no event names it.
    key_slot: KeySlot | None = None
