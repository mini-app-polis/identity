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

    Raised with a short reason ("malformed JWT", "no JWK for kid ...") for
    the enforcement point's logs. The reason is not for the response: an
    adapter maps this to a bare 401 and hands nothing more back to the
    caller, who is by definition unauthenticated at this point.
    """


class IssuerNotTrusted(IdentityError):
    """The credential verified structurally but its issuer is not configured.

    Distinct from CredentialInvalid because it is an operator error, not an
    attacker signal: a correctly-signed token from a Clerk tenant this
    enforcement point was never told about.
    """


class IssuerUnavailable(IdentityError):
    """A trusted issuer could not be consulted to verify the credential.

    The JWKS fetch failed: the issuer was unreachable, answered with an
    error status, or served something that is not a key set. Distinct from
    CredentialInvalid because it says nothing about the credential — the
    same token may verify a minute later — so an adapter maps it to a 503,
    not a 401. Left unmapped it would surface as a 500.
    """
