"""``verify`` for Clerk-issued credentials — the Clerk half of the binding.

This is the upstreaming that ``api-kaianolevine-com``'s ``auth.py`` docstring
asked for in as many words: "If a second service ever needs to verify Clerk
tokens, upstream this logic to common-python-utils and convert this module
into a thin consumer rather than copying it." A second enforcement point now
exists, so it lands here instead — with the identity contract it serves,
rather than in a general-purpose utility library.

Two credential shapes, as Clerk issues them:

  - RS256 JWTs (human sessions, and M2M JWTs) — verified locally against the
    issuer's JWKS.
  - M2M opaque tokens (machines) — verified by calling Clerk's BAPI, because
    there is nothing in them to verify locally.

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

from .errors import CredentialInvalid, IssuerNotTrusted
from .types import PrincipalKind, VerifiedSubject

_JWKS_TTL_SECS = 300.0
_CLERK_M2M_VERIFY_URL = "https://api.clerk.com/v1/m2m_tokens/verify"


@dataclass(frozen=True, slots=True)
class ClerkIssuer:
    """One trusted Clerk tenant."""

    issuer: str
    jwks_url: str
    # Present only for tenants that mint M2M opaque tokens. A tenant without
    # one can still verify JWTs; it simply cannot authenticate machines.
    secret_key: str | None = None


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

    @property
    def trusted_issuers(self) -> tuple[str, ...]:
        return tuple(self._issuers)

    async def verify(self, credential: str) -> VerifiedSubject:
        """Verify a credential. Raises; never returns None.

        The shape test is structural: a JWT has exactly two dots, an opaque
        token has none. This is Clerk's own distinction, not a heuristic.
        """
        if not credential:
            raise CredentialInvalid("empty credential")

        if credential.count(".") == 2:
            return await self._verify_jwt(credential)
        return await self._verify_opaque(credential)

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
        signing_key = PyJWK.from_dict(jwk_dict)
        decoded: dict[str, Any] = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"verify_aud": False},
        )
        return decoded

    async def _signing_key(self, jwks_url: str, kid: str) -> dict[str, Any]:
        doc = await self._jwks(jwks_url)
        keys = doc.get("keys")
        if not isinstance(keys, list):
            raise CredentialInvalid("JWKS document has no keys")
        for key in keys:
            if isinstance(key, dict) and key.get("kid") == kid:
                return key
        # One retry with a cold cache: a rotated signing key is the ordinary
        # cause of a kid miss, and the alternative is 5 minutes of 401s.
        self._jwks_cache.pop(jwks_url, None)
        doc = await self._jwks(jwks_url)
        for key in doc.get("keys", []):
            if isinstance(key, dict) and key.get("kid") == kid:
                return key
        raise CredentialInvalid(f"no JWK for kid {kid}")

    async def _jwks(self, jwks_url: str) -> dict[str, Any]:
        now = time.monotonic()
        hit = self._jwks_cache.get(jwks_url)
        if hit is not None and now < hit[0]:
            return hit[1]
        async with httpx.AsyncClient(timeout=self._http_timeout) as client:
            resp = await client.get(jwks_url)
            resp.raise_for_status()
            doc: dict[str, Any] = resp.json()
        self._jwks_cache[jwks_url] = (now + _JWKS_TTL_SECS, doc)
        return doc

    async def _verify_opaque(self, token: str) -> VerifiedSubject:
        """Verify an M2M opaque token via Clerk's BAPI.

        Tried against each tenant configured with a secret key. An opaque
        token carries no issuer claim, so which tenant minted it can only be
        discovered by asking.
        """
        candidates = [i for i in self._issuers.values() if i.secret_key]
        if not candidates:
            raise CredentialInvalid("no issuer is configured for machine tokens")

        for issuer in candidates:
            try:
                async with httpx.AsyncClient(timeout=self._http_timeout) as client:
                    resp = await client.post(
                        _CLERK_M2M_VERIFY_URL,
                        headers={
                            "Authorization": f"Bearer {issuer.secret_key}",
                            "Content-Type": "application/json",
                        },
                        json={"token": token},
                    )
            except httpx.HTTPError:
                continue
            if not resp.is_success:
                continue
            data = resp.json()
            subject = data.get("subject") or data.get("sub")
            if isinstance(subject, str) and subject:
                return VerifiedSubject(
                    issuer=issuer.issuer,
                    subject=subject,
                    kind="machine",
                    claims=dict(data) if isinstance(data, dict) else {},
                )

        raise CredentialInvalid("opaque token rejected by every trusted issuer")
