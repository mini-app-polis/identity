"""``verify`` for named API keys — machine authentication without an issuer.

A machine presents a key it holds; the key *is* its name. There is no token to
mint, no issuer to call, and nothing for the caller to assert. Matching a key
identifies the machine, so impersonation requires possessing the key rather
than merely claiming a name.

That is the whole reason this exists alongside ``identity.clerk``. Delegating
machine identity to an issuer means either a network call on every request
(opaque tokens) or a name the caller asserts (a claim in a body or header).
A key held in configuration avoids both: verification is local, and identity
is proven rather than declared.

**Key material never reaches the database.** Keys live in configuration —
Doppler, read into the process environment — and this verifier compares
against what it was given at construction. The principal store holds names,
status and roles; a database dump exposes no credentials, and rotation is a
configuration change rather than a migration.

Humans are not authenticated this way. A person has an identity provider with
sessions, expiry and revocation; a long-lived shared string has none of that.
Machines are the case where a static credential is appropriate, because there
is no human to phish and the credential lives only in deployment config.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from .errors import CredentialInvalid
from .types import VerifiedSubject

#: Issuer recorded for key-authenticated principals. The principal store is
#: multi-issuer by design, so key-authenticated machines and Clerk-authenticated
#: humans coexist in one table without either path branching on the other.
API_KEY_ISSUER = "apikey"


@dataclass(frozen=True, slots=True)
class MachineKey:
    """One machine's name and the key that proves it."""

    name: str
    key: str


class ApiKeyVerifier:
    """Verifies a machine by matching its key against a configured set."""

    def __init__(self, machines: list[MachineKey]) -> None:
        # A blank key would match a caller sending nothing, so a machine
        # configured without one is dropped rather than silently made
        # impersonable by anybody.
        self._machines = [m for m in machines if m.key]

    @property
    def known_names(self) -> tuple[str, ...]:
        """The machine names this verifier can recognise.

        Names only. Key material is never returned, logged, or stored —
        keys live in Doppler, reach the process as
        ``<MACHINE_NAME>_API_KEY`` environment variables, and exist here
        only as comparison targets.
        """
        return tuple(m.name for m in self._machines)

    def _match(self, credential: str) -> str | None:
        """Return the matching machine name, in constant time.

        Every configured key is compared and no comparison short-circuits.
        Returning early on the first match would make response time depend on
        the key's position, and `==` on the strings would make it depend on
        how many leading characters were correct — either leaks information
        about a secret to whoever is guessing it.
        """
        # Encoded to bytes: compare_digest raises TypeError on a str
        # containing non-ASCII, which in the auth path would be a crash where
        # a rejection belongs.
        presented = credential.encode("utf-8", "surrogatepass")
        found: str | None = None
        for machine in self._machines:
            if hmac.compare_digest(
                presented, machine.key.encode("utf-8", "surrogatepass")
            ):
                found = machine.name
        return found

    async def verify(self, credential: str) -> VerifiedSubject:
        """Identify the machine holding this key.

        The subject is the machine's name. There is no external issuer, so
        nothing has to be discovered at runtime: every machine's identity is
        known from configuration before any request arrives.
        """
        if not credential:
            raise CredentialInvalid("empty credential")
        name = self._match(credential)
        if name is None:
            raise CredentialInvalid("no configured machine holds this key")
        return VerifiedSubject(
            issuer=API_KEY_ISSUER, subject=name, kind="machine", claims={}
        )
