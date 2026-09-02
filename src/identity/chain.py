"""Routing a credential to the verifier that can prove it.

An enforcement point serves populations that authenticate differently:
machines holding named keys, humans holding issuer sessions, and — during a
migration — machines still holding issuer-minted opaque tokens. This decides
which mechanism a given credential belongs to.

Routing is structural where it can be. A JWT is the only shape with two dots,
so it goes straight to the issuer and never touches the key path.

Anything else is tried against the configured keys first, because that check
is local and cheap. Only a credential matching no key falls through to the
issuer, which is the one shape that costs a network call. That ordering
matters: it means a fleet fully migrated to keys never leaves the process to
authenticate, while one still part-way through keeps working.

The fallback is deliberately last and deliberately temporary. Every machine
that gains its own key stops reaching it, and when none are left the issuer
can be dropped from the machine path entirely.
"""

from __future__ import annotations

from typing import Protocol

from .apikey import ApiKeyVerifier
from .errors import CredentialInvalid, IdentityError
from .types import VerifiedSubject


class SubjectVerifier(Protocol):
    """Anything that can turn a credential into a verified subject."""

    async def verify(self, credential: str) -> VerifiedSubject: ...


class ChainVerifier:
    """Route a credential to the mechanism that can prove it."""

    def __init__(
        self,
        api_keys: ApiKeyVerifier | None,
        issuer_verifier: SubjectVerifier | None,
    ) -> None:
        self._api_keys = api_keys
        self._issuer = issuer_verifier

    async def verify(self, credential: str) -> VerifiedSubject:
        if not credential:
            raise CredentialInvalid("empty credential")

        # A JWT is the only shape with two dots — a session, or an M2M JWT.
        if credential.count(".") == 2:
            if self._issuer is None:
                raise CredentialInvalid("no issuer is configured")
            return await self._issuer.verify(credential)

        # Otherwise: a named key, or an issuer-minted opaque token. Keys first
        # because they are verified locally; the issuer costs a round trip.
        if self._api_keys is not None:
            try:
                return await self._api_keys.verify(credential)
            except IdentityError:
                pass

        if self._issuer is None:
            raise CredentialInvalid("no configured machine holds this key")
        return await self._issuer.verify(credential)
