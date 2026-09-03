"""Routing a credential to the verifier that can prove it.

An enforcement point serves populations that authenticate differently:
machines holding named keys, humans holding issuer sessions, and — during a
migration — machines still holding issuer-minted opaque tokens. This decides
which mechanism a given credential belongs to.

Routing is structural where it can be. A JWT is the only shape with two dots,
so it goes straight to the issuer and never touches the key path.

Anything else is a machine key, matched locally against configuration. There
is no fallback to the issuer: every machine holds its own key, so a credential
matching none of them is simply not one of ours. Authenticating machines
through an issuer would mean a network call per request, which is the thing
this design keeps off the request path.
"""

from __future__ import annotations

from typing import Protocol

from .apikey import ApiKeyVerifier
from .errors import CredentialInvalid
from .types import VerifiedSubject


class SubjectVerifier(Protocol):
    """Anything that can turn a credential into a verified subject."""

    async def verify(self, credential: str) -> VerifiedSubject:
        """Prove a credential and return the subject it names.

        Raises rather than returning None: a verifier that cannot prove
        a credential has not identified anyone, and an optional return
        invites a caller to treat "unproven" as "anonymous but fine".
        """
        ...


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
        """Route a credential to the mechanism that can prove it.

        Routing is structural, by dot count, with no fallback between
        the two paths: two dots is a JWT and goes to the issuer
        verifier; anything else is a named machine key and is compared
        in process against configuration.

        No fallback is the point. If a JWT fails verification the answer
        is denial, not "try it as a machine key" — a credential that
        could be retried down the other path would let a caller who
        controls its shape choose which check it faces.
        """
        if not credential:
            raise CredentialInvalid("empty credential")

        # A JWT is the only shape with two dots — a session, or an M2M JWT.
        if credential.count(".") == 2:
            if self._issuer is None:
                raise CredentialInvalid("no issuer is configured")
            return await self._issuer.verify(credential)

        # Otherwise it is a machine key, verified locally against config.
        if self._api_keys is None:
            raise CredentialInvalid("no machine keys are configured")
        return await self._api_keys.verify(credential)
