"""Errors raised by the identity binding.

Only ``verify`` raises. ``resolve``, ``authorize`` and ``emit_audit`` return
values instead: an unresolvable principal and a denied scope are ordinary
outcomes that must reach the audit trail, not exceptions that skip it.
"""

from __future__ import annotations


class IdentityError(Exception):
    """Base for every error this package raises."""


class CredentialInvalid(IdentityError):
    """The presented credential failed verification.

    Deliberately carries no detail about *why*. The reason is recorded in the
    audit event; it is not handed back to the caller, who is by definition
    unauthenticated at this point.
    """


class IssuerNotTrusted(IdentityError):
    """The credential verified structurally but its issuer is not configured.

    Distinct from CredentialInvalid because it is an operator error, not an
    attacker signal: a correctly-signed token from a Clerk tenant this
    enforcement point was never told about.
    """
