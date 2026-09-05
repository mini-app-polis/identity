"""Cross-ecosystem identity contract.

One specification, N conformant enforcement points — explicitly not a central
auth service on the request path.

Install name:  miniapppolis-identity   (the distribution, on PyPI)
Import name:   identity                (the package, in your source)

The two differ because `identity` was already taken on PyPI by an unrelated
Microsoft auth library, so the distribution carries the ecosystem prefix
while the import stays what every enforcement point already writes. One
consequence worth knowing: the import name is shared with a package this
ecosystem does not own, so installing PyPI `identity` alongside this one
would collide at the top level. Repository: mini-app-polis/identity.

Install:
    # pyproject.toml
    dependencies = ["miniapppolis-identity>=2.0,<3"]
    # add the [store] extra at an enforcement point that resolves principals:
    dependencies = ["miniapppolis-identity[store]>=2.0,<3"]

Import:
    from identity import ChainVerifier, Principal, VerifiedSubject
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
