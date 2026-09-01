"""The authorization decision — the one part of the contract that is pure.

``verify`` needs a network, ``resolve`` needs a database, ``emit_audit``
needs a sink. This does not: given a principal, a role table and a scope, the
decision is a total function. That is why it is the part the shared fixture
suite can pin exactly, and why every binding in every language must produce
byte-identical decisions from the fixtures in ``fixtures/authorize/``.

Precedence is fixed and deliberately short:

    1. No principal            -> deny, principal_not_found
    2. Suspended principal     -> deny, principal_suspended
    3. Scope in any role       -> allow, granted_by_role
    4. Explicit resource grant -> allow, granted_by_explicit_grant
    5. Otherwise               -> deny, no_matching_scope

Suspension is checked before roles on purpose: a suspended principal is
denied everything, including scopes its roles still nominally grant.
Reversing 2 and 3 would make suspension a suggestion.
"""

from __future__ import annotations

from collections.abc import Mapping
from collections.abc import Set as AbstractSet

from .types import AuthorizationDecision, Principal, Role


def effective_scopes(principal: Principal, roles: Mapping[str, Role]) -> frozenset[str]:
    """Union of the scopes of every role the principal holds.

    Unknown role names are ignored rather than raising: a principal carrying a
    role this enforcement point has not been configured with should lose that
    role's privileges, not lock the principal out of ones it does hold.
    """
    scopes: set[str] = set()
    for name in principal.roles:
        role = roles.get(name)
        if role is not None:
            scopes.update(role.scopes)
    return frozenset(scopes)


def authorize(
    principal: Principal | None,
    scope: str,
    roles: Mapping[str, Role],
    *,
    resource: str | None = None,
    explicit_grants: AbstractSet[tuple[str, str]] | None = None,
) -> AuthorizationDecision:
    """Decide, and say why. Never raises.

    ``explicit_grants`` is the instance-level escape hatch — a set of
    ``(scope, resource)`` pairs granted to this principal directly rather than
    through a role. It exists because ``wcs_note_grants`` already works this
    way; it is not a general-purpose ACL and it is checked only after roles.
    """
    if principal is None:
        return AuthorizationDecision(
            allowed=False, scope=scope, reason="principal_not_found", resource=resource
        )

    if principal.status == "suspended":
        return AuthorizationDecision(
            allowed=False,
            scope=scope,
            reason="principal_suspended",
            principal_id=principal.id,
            resource=resource,
        )

    for name in principal.roles:
        role = roles.get(name)
        if role is not None and scope in role.scopes:
            return AuthorizationDecision(
                allowed=True,
                scope=scope,
                reason="granted_by_role",
                principal_id=principal.id,
                resource=resource,
                matched_role=name,
            )

    if (
        resource is not None
        and explicit_grants
        and (scope, resource) in explicit_grants
    ):
        return AuthorizationDecision(
            allowed=True,
            scope=scope,
            reason="granted_by_explicit_grant",
            principal_id=principal.id,
            resource=resource,
        )

    return AuthorizationDecision(
        allowed=False,
        scope=scope,
        reason="no_matching_scope",
        principal_id=principal.id,
        resource=resource,
    )
