"""The binding contract every enforcement point implements.

Four functions, in this order, once per request:

    verify(credential)            -> VerifiedSubject      (raises on failure)
    resolve(subject)              -> Principal | None
    authorize(principal, scope)   -> AuthorizationDecision
    emit_audit(event)             -> None

Why four and not one: each step fails differently and each failure needs a
different response. A collapsed ``is_allowed(token, scope) -> bool`` cannot
distinguish "your token is forged" from "you are suspended" from "you are
who you say and simply lack this scope" — and cannot record any of them.

Services implement none of this. They supply configuration (which issuers
are trusted, which store to resolve against, which enforcement point they
are) and a thin framework adapter that turns a Decision into a response.
Anything more in a service is drift.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from .types import AuditEvent, AuthorizationDecision, Principal, VerifiedSubject


@runtime_checkable
class Verifier(Protocol):
    """Step 1 — prove the credential and extract the issuer's subject."""

    async def verify(self, credential: str) -> VerifiedSubject:
        """Raise CredentialInvalid or IssuerNotTrusted; never return None."""
        ...


@runtime_checkable
class PrincipalResolver(Protocol):
    """Step 2 — look the verified subject up in this ecosystem's store."""

    async def resolve(self, subject: VerifiedSubject) -> Principal | None:
        """Return None when the subject is unknown here.

        None is not an error. A valid token from a trusted issuer for someone
        this ecosystem has never seen is an expected state, and the caller
        may legitimately choose to provision on first sight.
        """
        ...


@runtime_checkable
class Authorizer(Protocol):
    """Step 3 — one decision, for humans and machines alike."""

    async def authorize(
        self,
        principal: Principal | None,
        scope: str,
        *,
        resource: str | None = None,
    ) -> AuthorizationDecision:
        """Never raises. A denial is a value, because it has to be audited."""
        ...


@runtime_checkable
class AuditSink(Protocol):
    """Step 4 — record the decision that was made."""

    async def emit_audit(self, event: AuditEvent) -> None:
        """Must not raise into the request path.

        An audit sink that can fail a request converts an observability
        outage into a service outage. Failures here are logged and dropped;
        the sink's own health is monitored separately.
        """
        ...


@runtime_checkable
class IdentityBinding(Verifier, PrincipalResolver, Authorizer, AuditSink, Protocol):
    """The whole contract. Conformance means passing the shared fixture suite."""

    @property
    def enforcement_point(self) -> str:
        """Stable name of this implementation, recorded on every audit event."""
        ...
