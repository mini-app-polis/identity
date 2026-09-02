"""Routing a credential to the verifier that can prove it.

An enforcement point serves two populations with genuinely different
authentication: machines holding named keys, and humans holding Clerk
sessions. They are not two implementations of one mechanism, so this does not
try to unify them — it decides which one a given credential belongs to and
hands it over.

Routing is structural, not trial-and-error. A Clerk JWT has exactly two dots;
a key has none. Trying each verifier in turn and keeping whichever succeeded
would mean a failed Clerk verification for every machine request, filling the
logs with rejections that are not failures and making a real attack harder
to see.
"""

from __future__ import annotations

from .apikey import ApiKeyVerifier
from .errors import CredentialInvalid
from .types import VerifiedSubject


class ChainVerifier:
    """Route to the API-key verifier or the issuer verifier."""

    def __init__(self, api_keys: ApiKeyVerifier | None, issuer_verifier: object | None):
        self._api_keys = api_keys
        self._issuer = issuer_verifier

    async def verify(self, credential: str) -> VerifiedSubject:
        if not credential:
            raise CredentialInvalid("empty credential")

        # A JWT is the only shape with two dots. Anything else is a key.
        if credential.count(".") == 2:
            if self._issuer is None:
                raise CredentialInvalid("no issuer is configured")
            return await self._issuer.verify(credential)  # type: ignore[attr-defined]

        if self._api_keys is None:
            raise CredentialInvalid("no machine keys are configured")
        return await self._api_keys.verify(credential)
