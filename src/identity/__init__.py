"""Cross-ecosystem identity contract.

One specification, N conformant enforcement points — explicitly not a central
auth service on the request path.
"""

from .apikey import API_KEY_ISSUER, ApiKeyVerifier, MachineKey
from .chain import ChainVerifier
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
    "API_KEY_ISSUER",
    "ApiKeyVerifier",
    "AuditEvent",
    "AuditSink",
    "AuthorizationDecision",
    "Authorizer",
    "ChainVerifier",
    "CredentialInvalid",
    "DecisionReason",
    "IdentityBinding",
    "IdentityError",
    "IssuerNotTrusted",
    "MachineKey",
    "Principal",
    "PrincipalKind",
    "PrincipalResolver",
    "PrincipalStatus",
    "Role",
    "VerifiedSubject",
    "Verifier",
]
