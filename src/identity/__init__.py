"""Cross-ecosystem identity contract.

One specification, N conformant enforcement points — explicitly not a central
auth service on the request path.
"""

from .contract import (
    AuditSink,
    Authorizer,
    IdentityBinding,
    PrincipalResolver,
    Verifier,
)
from .errors import CredentialInvalid, IdentityError, IssuerNotTrusted
from .types import (
    AuditEvent,
    AuthorizationDecision,
    DecisionReason,
    Principal,
    PrincipalKind,
    PrincipalStatus,
    Role,
    VerifiedSubject,
)

__all__ = [
    "AuditEvent",
    "AuditSink",
    "AuthorizationDecision",
    "Authorizer",
    "CredentialInvalid",
    "DecisionReason",
    "IdentityBinding",
    "IdentityError",
    "IssuerNotTrusted",
    "Principal",
    "PrincipalKind",
    "PrincipalResolver",
    "PrincipalStatus",
    "Role",
    "VerifiedSubject",
    "Verifier",
]
