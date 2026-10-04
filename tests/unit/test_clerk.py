"""ClerkVerifier — the security properties, not the happy path.

The happy path needs a real Clerk tenant. These cover the behaviours that are
easy to get wrong and expensive to get wrong: issuer trust, and the fact that
issuer trust is decided *before* signature verification.
"""

from __future__ import annotations

import base64
import json

import pytest

from identity.clerk import ClerkIssuer, ClerkVerifier
from identity.errors import CredentialInvalid, IssuerNotTrusted

TRUSTED = "https://clerk.kaianolevine.com"
OTHER = "https://clerk.deejaytools.com"


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _unsigned_jwt(*, iss: str, sub: str, kid: str = "kid-1") -> str:
    """A structurally valid JWT with a junk signature."""
    return f"{_b64({'alg': 'RS256', 'kid': kid})}.{_b64({'iss': iss, 'sub': sub})}.bm90YXNpZw"


def _verifier() -> ClerkVerifier:
    return ClerkVerifier(
        [
            ClerkIssuer(issuer=TRUSTED, jwks_url=f"{TRUSTED}/.well-known/jwks.json"),
        ]
    )


def test_requires_at_least_one_issuer() -> None:
    with pytest.raises(ValueError):
        ClerkVerifier([])


async def test_empty_credential_rejected() -> None:
    with pytest.raises(CredentialInvalid):
        await _verifier().verify("")


async def test_malformed_jwt_rejected() -> None:
    with pytest.raises(CredentialInvalid):
        await _verifier().verify("not.a.jwt")


async def test_untrusted_issuer_rejected_before_any_network_call() -> None:
    """A correctly-signed token from an unconfigured tenant must not resolve.

    If this ever starts making a JWKS request, the ordering has regressed:
    issuer trust is checked first precisely so an untrusted tenant's token
    never reaches key fetching or the resolve step.
    """
    v = _verifier()

    async def _explode(*_args: object, **_kwargs: object) -> dict:
        raise AssertionError("JWKS fetched for an untrusted issuer")

    v._jwks = _explode  # type: ignore[method-assign]

    with pytest.raises(IssuerNotTrusted) as exc:
        await v.verify(_unsigned_jwt(iss=OTHER, sub="user_1"))
    assert OTHER in str(exc.value)


async def test_jwt_without_issuer_rejected() -> None:
    token = f"{_b64({'alg': 'RS256', 'kid': 'k'})}.{_b64({'sub': 'user_1'})}.sig"
    with pytest.raises(CredentialInvalid):
        await _verifier().verify(token)


async def test_opaque_token_without_configured_secret_is_rejected() -> None:
    """An opaque token needs a tenant with a secret key; without one there is
    nothing to ask, and a verifier must not fall through to allowing it."""
    with pytest.raises(CredentialInvalid):
        await _verifier().verify("opaquetokenwithnodots")


def test_trusted_issuers_exposed() -> None:
    assert _verifier().trusted_issuers == (TRUSTED,)
