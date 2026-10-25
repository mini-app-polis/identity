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
# Rotation: a current and a previous key per machine
# ---------------------------------------------------------------------------


def _rotating() -> ApiKeyVerifier:
    return ApiKeyVerifier(
        [
            MachineKey(name="deejay-cog", key="k_deejay_new", previous="k_deejay_old"),
            MachineKey(name="watcher-cog", key="k_watcher_bbbb"),
        ]
    )


async def test_current_key_reports_the_current_slot() -> None:
    subject = await _rotating().verify("k_deejay_new")
    assert subject.subject == "deejay-cog"
    assert subject.key_slot == "current"


async def test_previous_key_is_accepted_and_reports_the_previous_slot() -> None:
    """The old key keeps working until it is retired, and says it is the old one."""
    subject = await _rotating().verify("k_deejay_old")
    assert subject.subject == "deejay-cog"
    assert subject.kind == "machine"
    assert subject.issuer == API_KEY_ISSUER
    assert subject.key_slot == "previous"


async def test_a_key_in_neither_slot_is_rejected() -> None:
    with pytest.raises(CredentialInvalid):
        await _rotating().verify("k_deejay_older")


async def test_without_a_previous_key_only_the_current_one_matches() -> None:
    """Unset previous is today's behaviour: one key, reported as current."""
    v = _rotating()
    subject = await v.verify("k_watcher_bbbb")
    assert subject.subject == "watcher-cog"
    assert subject.key_slot == "current"
    assert subject.claims == {}


async def test_a_blank_previous_key_is_no_previous_key() -> None:
    """A blank previous would otherwise be a second way to match nothing."""
    v = ApiKeyVerifier([MachineKey(name="deejay-cog", key="k_deejay", previous="")])
    assert (await v.verify("k_deejay")).key_slot == "current"
    with pytest.raises(CredentialInvalid):
        await v.verify("")


async def test_a_previous_key_alone_does_not_keep_a_machine() -> None:
    """Rotation adds a key before retiring one; a blank current key is missing."""
    v = ApiKeyVerifier([MachineKey(name="deejay-cog", key="", previous="k_old")])
    assert v.known_names == ()
    with pytest.raises(CredentialInvalid):
        await v.verify("k_old")


async def test_a_key_held_in_both_slots_reports_current() -> None:
    v = ApiKeyVerifier([MachineKey(name="deejay-cog", key="k_same", previous="k_same")])
    assert (await v.verify("k_same")).key_slot == "current"


async def test_both_slots_are_compared_whether_or_not_a_previous_key_exists(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Comparison count must not say which machines are mid-rotation.

    Every machine costs two comparisons on every call, so a caller timing
    responses cannot tell a machine with a previous key from one without.
    """
    from identity import apikey

    calls: list[int] = []
    real = apikey.hmac.compare_digest

    def counting(a: bytes, b: bytes) -> bool:
        calls.append(1)
        return real(a, b)

    monkeypatch.setattr(apikey.hmac, "compare_digest", counting)

    with_previous = ApiKeyVerifier(
        [MachineKey(name="deejay-cog", key="k_new", previous="k_old")]
    )
    without_previous = ApiKeyVerifier([MachineKey(name="deejay-cog", key="k_new")])
    for verifier in (with_previous, without_previous):
        calls.clear()
        with pytest.raises(CredentialInvalid):
            await verifier.verify("k_bogus")
        assert len(calls) == 2


async def test_no_key_material_in_rejections_or_repr() -> None:
    machine = MachineKey(name="deejay-cog", key="k_secret_new", previous="k_secret_old")
    assert "k_secret" not in repr(machine)
    with pytest.raises(CredentialInvalid) as exc:
        await ApiKeyVerifier([machine]).verify("k_secret_older")
    assert "k_secret" not in str(exc.value)
    assert "k_secret" not in repr(exc.value)


async def test_issuer_subjects_carry_no_key_slot() -> None:
    from identity.types import VerifiedSubject

    subject = VerifiedSubject(issuer="https://clerk.example", subject="u", kind="human")
    assert subject.key_slot is None


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


async def test_a_machine_key_never_reaches_the_issuer() -> None:
    """Machines authenticate locally; nothing about them leaves the process."""
    issuer = _FakeIssuer()
    chain = ChainVerifier(_verifier(), issuer)
    assert (await chain.verify("k_deejay_aaaa")).subject == "deejay-cog"
    assert issuer.calls == []


async def test_the_chain_carries_the_matched_slot() -> None:
    """The slot has to survive routing to reach the audit trail."""
    issuer = _FakeIssuer()
    chain = ChainVerifier(_rotating(), issuer)
    assert (await chain.verify("k_deejay_old")).key_slot == "previous"
    assert (await chain.verify("aaa.bbb.ccc")).key_slot is None


async def test_unknown_key_is_rejected_not_retried_upstream() -> None:
    """A credential matching no configured key is simply not one of ours.

    There is no issuer fallback: every machine holds a key, so retrying
    upstream would only add a network call to a request already known bad.
    """
    issuer = _FakeIssuer()
    chain = ChainVerifier(_verifier(), issuer)
    with pytest.raises(CredentialInvalid):
        await chain.verify("k_bogus")
    assert issuer.calls == []


async def test_non_ascii_credential_is_rejected_not_a_crash() -> None:
    """compare_digest raises TypeError on non-ASCII str.

    In the auth path that is a 500 where a 401 belongs, and it is reachable by
    anyone who can send a header.
    """
    with pytest.raises(CredentialInvalid):
        await _verifier().verify("k_déjà_vu_ключ")


async def test_non_ascii_configured_key_still_matches() -> None:
    v = ApiKeyVerifier([MachineKey(name="odd-cog", key="k_ключ")])
    assert (await v.verify("k_ключ")).subject == "odd-cog"
