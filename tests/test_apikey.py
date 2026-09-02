"""Named API keys — machine identity proven, not asserted."""

from __future__ import annotations

import pytest

from identity.apikey import API_KEY_ISSUER, ApiKeyVerifier, MachineKey
from identity.chain import ChainVerifier
from identity.errors import CredentialInvalid


def _verifier() -> ApiKeyVerifier:
    return ApiKeyVerifier(
        [
            MachineKey(name="deejay-cog", key="k_deejay_aaaa"),
            MachineKey(name="watcher-cog", key="k_watcher_bbbb"),
        ]
    )


async def test_key_identifies_its_machine() -> None:
    subject = await _verifier().verify("k_deejay_aaaa")
    assert subject.subject == "deejay-cog"
    assert subject.kind == "machine"
    assert subject.issuer == API_KEY_ISSUER


async def test_each_key_maps_to_only_its_own_machine() -> None:
    """Holding one key must never identify you as another machine."""
    assert (await _verifier().verify("k_watcher_bbbb")).subject == "watcher-cog"


async def test_unknown_key_is_rejected() -> None:
    with pytest.raises(CredentialInvalid):
        await _verifier().verify("k_not_a_real_key")


async def test_empty_credential_is_rejected() -> None:
    with pytest.raises(CredentialInvalid):
        await _verifier().verify("")


async def test_machine_configured_without_a_key_is_dropped() -> None:
    """A blank key would be matched by a caller sending nothing.

    Dropping the machine is the safe reading of a missing secret: it cannot
    authenticate, rather than being impersonable by anyone.
    """
    v = ApiKeyVerifier([MachineKey(name="unconfigured", key="")])
    assert v.known_names == ()
    with pytest.raises(CredentialInvalid):
        await v.verify("")


async def test_a_prefix_of_a_real_key_does_not_match() -> None:
    with pytest.raises(CredentialInvalid):
        await _verifier().verify("k_deejay_aaa")


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------


class _FakeIssuer:
    def __init__(self) -> None:
        self.calls: list[str] = []

    async def verify(self, credential: str):
        from identity.types import VerifiedSubject

        self.calls.append(credential)
        return VerifiedSubject(
            issuer="https://clerk.example", subject="user_1", kind="human"
        )


async def test_jwt_shaped_credential_goes_to_the_issuer() -> None:
    issuer = _FakeIssuer()
    chain = ChainVerifier(_verifier(), issuer)
    subject = await chain.verify("aaa.bbb.ccc")
    assert subject.kind == "human"
    assert issuer.calls == ["aaa.bbb.ccc"]


async def test_key_shaped_credential_never_reaches_the_issuer() -> None:
    """Machine traffic must not produce a failed issuer verification per call."""
    issuer = _FakeIssuer()
    chain = ChainVerifier(_verifier(), issuer)
    subject = await chain.verify("k_deejay_aaaa")
    assert subject.subject == "deejay-cog"
    assert issuer.calls == []


async def test_unknown_key_is_not_retried_against_the_issuer() -> None:
    issuer = _FakeIssuer()
    chain = ChainVerifier(_verifier(), issuer)
    with pytest.raises(CredentialInvalid):
        await chain.verify("k_bogus")
    assert issuer.calls == []
