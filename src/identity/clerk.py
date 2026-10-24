"""``verify`` for Clerk-issued credentials — the Clerk half of the binding.

Clerk verification lives here because more than one service enforces the
identity contract: each verifies tokens through this module rather than
keeping its own copy. It sits with the contract it serves rather than in a
general-purpose utility library.

One credential shape: RS256 JWTs (human sessions, and M2M JWTs), verified
locally against the issuer's JWKS. Machines authenticate with named keys
(``identity.apikey``); Clerk M2M opaque tokens are not accepted.

Multi-issuer is the default, not an option. The two Clerk tenants are
different products with different audiences; a verifier that assumes one
issuer cannot serve both, and one that accepts any issuer serves attackers.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from jwt import PyJWK

from .errors import CredentialInvalid, IssuerNotTrusted, IssuerUnavailable
from .types import PrincipalKind, VerifiedSubject

_JWKS_TTL_SECS = 300.0
# The least time between two JWKS fetches forced by an unknown ``kid``. The
# kid is attacker-chosen and the forced fetch happens before any signature
# work, so without a floor every forged token would cost an outbound request.
_KID_MISS_REFETCH_SECS = 60.0
# Claims a token must carry for its signature check to mean anything: without
# ``exp`` a leaked token is valid forever.
_REQUIRED_CLAIMS = ["exp", "iat", "sub", "iss"]


@dataclass(frozen=True, slots=True)
class ClerkIssuer:
    """One trusted Clerk tenant.

    ``authorized_parties`` pins the origins a session token may have been
    minted for, checked against the token's ``azp``. Clerk session tokens
    carry ``azp`` rather than ``aud``, so this is the audience check for
    them. Empty means not checked.
    """

    issuer: str
    jwks_url: str
    authorized_parties: tuple[str, ...] = ()


class ClerkVerifier:
    """Verifies Clerk credentials against a fixed set of trusted issuers."""

    def __init__(
        self,
        issuers: list[ClerkIssuer],
        *,
        http_timeout: float = 10.0,
    ) -> None:
        if not issuers:
            raise ValueError("ClerkVerifier requires at least one trusted issuer")
        self._issuers = {i.issuer: i for i in issuers}
        self._http_timeout = http_timeout
        self._jwks_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._kid_miss_refetch_at: dict[str, float] = {}

    @property
    def trusted_issuers(self) -> tuple[str, ...]:
        """The issuers this verifier will accept a token from.

        Built from configuration at startup, not consulted per request.
        A token whose ``iss`` is absent from this set is rejected before
        any signature work — the two Clerk tenants are separate products
        with separate audiences, and a token from one is not a
        credential for the other.
        """
        return tuple(self._issuers)

    async def verify(self, credential: str) -> VerifiedSubject:
        """Verify a Clerk session JWT. Raises; never returns None."""
        if not credential:
            raise CredentialInvalid("empty credential")

        return await self._verify_jwt(credential)

    async def _verify_jwt(self, token: str) -> VerifiedSubject:
        try:
            unverified = jwt.decode(token, options={"verify_signature": False})
            header = jwt.get_unverified_header(token)
        except Exception as exc:
            raise CredentialInvalid("malformed JWT") from exc

        issuer = unverified.get("iss")
        if not isinstance(issuer, str) or not issuer:
            raise CredentialInvalid("JWT has no issuer")

        # Issuer trust is decided before any signature work. Verifying first
        # and checking the issuer afterwards would let an untrusted tenant's
        # correctly-signed token reach the resolve step.
        trusted = self._issuers.get(issuer)
        if trusted is None:
            raise IssuerNotTrusted(issuer)

        kid = header.get("kid")
        if not kid:
            raise CredentialInvalid("JWT has no kid")

        jwk_dict = await self._signing_key(trusted.jwks_url, kid)
        try:
            payload = await asyncio.to_thread(
                self._decode_verified, token, jwk_dict, issuer
            )
        except Exception as exc:
            raise CredentialInvalid("JWT verification failed") from exc

        if trusted.authorized_parties:
            azp = payload.get("azp")
            if azp not in trusted.authorized_parties:
                raise CredentialInvalid(f"JWT azp {azp!r} is not authorized")

        subject = payload.get("sub")
        if not isinstance(subject, str) or not subject:
            raise CredentialInvalid("JWT has no subject")

        # Clerk M2M JWTs carry a machine subject; session JWTs carry a user.
        kind: PrincipalKind = "machine" if subject.startswith("mch_") else "human"
        return VerifiedSubject(
            issuer=issuer, subject=subject, kind=kind, claims=dict(payload)
        )

    @staticmethod
    def _decode_verified(
        token: str, jwk_dict: dict[str, Any], issuer: str
    ) -> dict[str, Any]:
        """Check signature, issuer and lifetime; require the core claims.

        ``aud`` is deliberately not verified: Clerk session tokens carry
        ``azp`` instead, which ``ClerkIssuer.authorized_parties`` checks.
        """
        signing_key = PyJWK.from_dict(jwk_dict)
        decoded: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"verify_aud": False, "require": _REQUIRED_CLAIMS},
        )
        return decoded

    async def _signing_key(self, jwks_url: str, kid: str) -> dict[str, Any]:
        """Find the JWK for ``kid``, refetching at most once a minute on a miss.

        A rotated signing key is the ordinary cause of a kid miss, so a miss
        forces one fetch with a cold cache rather than serving 5 minutes of
        401s. But the kid comes from an unauthenticated caller, so that
        forced fetch is rate-limited per issuer: within
        ``_KID_MISS_REFETCH_SECS`` of the last one — or of the cached
        document being fetched at all — an unknown kid is simply invalid.
        """
        key = self._find_key(await self._jwks(jwks_url), kid)
        if key is not None:
            return key

        now = time.monotonic()
        last = self._kid_miss_refetch_at.get(jwks_url)
        hit = self._jwks_cache.get(jwks_url)
        fetched_at = hit[0] - _JWKS_TTL_SECS if hit is not None else None
        if any(
            t is not None and now - t < _KID_MISS_REFETCH_SECS
            for t in (last, fetched_at)
        ):
            raise CredentialInvalid(f"no JWK for kid {kid}")

        # Stamped before the await, so concurrent misses see it and do not
        # each start a fetch of their own.
        self._kid_miss_refetch_at[jwks_url] = now
        self._jwks_cache.pop(jwks_url, None)
        key = self._find_key(await self._jwks(jwks_url), kid)
        if key is not None:
            return key
        raise CredentialInvalid(f"no JWK for kid {kid}")

    @staticmethod
    def _find_key(doc: dict[str, Any], kid: str) -> dict[str, Any] | None:
        for key in doc["keys"]:
            if isinstance(key, dict) and key.get("kid") == kid:
                return key
        return None

    async def _jwks(self, jwks_url: str) -> dict[str, Any]:
        """The issuer's key set, cached for ``_JWKS_TTL_SECS``.

        Every way the fetch can fail raises IssuerUnavailable: an issuer
        outage says nothing about the credential, and anything that is not
        an IdentityError would escape the Verifier contract as a 500.
        """
        now = time.monotonic()
        hit = self._jwks_cache.get(jwks_url)
        if hit is not None and now < hit[0]:
            return hit[1]
        try:
            async with httpx.AsyncClient(timeout=self._http_timeout) as client:
                resp = await client.get(jwks_url)
                resp.raise_for_status()
                doc = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise IssuerUnavailable(f"JWKS fetch failed: {jwks_url}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
            raise IssuerUnavailable(f"JWKS document has no keys: {jwks_url}")
        self._jwks_cache[jwks_url] = (now + _JWKS_TTL_SECS, doc)
        return doc
