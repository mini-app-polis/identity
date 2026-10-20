"""ClerkVerifier — the security properties, not the happy path.

These cover the behaviours that are easy to get wrong and expensive to get
wrong: issuer trust, and the fact that issuer trust is decided *before*
signature verification; required claims; what an issuer outage raises; and
how often an unauthenticated caller can make this reach the network.

Signed tokens use a key generated per run and a JWKS served through
``httpx.MockTransport`` — nothing here talks to a real Clerk tenant.
"""

from __future__ import annotations

import base64
import json
import time
import types
from collections.abc import Callable
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import identity.clerk as clerk_module
from identity.clerk import ClerkIssuer, ClerkVerifier
from identity.errors import (
    CredentialInvalid,
    IdentityError,
    IssuerNotTrusted,
    IssuerUnavailable,
)

TRUSTED = "https://clerk.kaianolevine.com"
OTHER = "https://clerk.deejaytools.com"


def _b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


def _unsigned_jwt(*, iss: str, sub: str, kid: str = "kid-1") -> str:
    """A structurally valid JWT with a junk signature."""
    return f"{_b64({'alg': 'RS256', 'kid': kid})}.{_b64({'iss': iss, 'sub': sub})}.bm90YXNpZw"


JWKS_URL = f"{TRUSTED}/.well-known/jwks.json"
APP = "https://app.kaianolevine.com"

_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _verifier(*, authorized_parties: tuple[str, ...] = ()) -> ClerkVerifier:
    return ClerkVerifier(
        [
            ClerkIssuer(
                issuer=TRUSTED,
                jwks_url=JWKS_URL,
                authorized_parties=authorized_parties,
            ),
        ]
    )


def _jwk(kid: str) -> dict[str, Any]:
    jwk: dict[str, Any] = jwt.algorithms.RSAAlgorithm.to_jwk(
        _KEY.public_key(), as_dict=True
    )
    return {**jwk, "kid": kid, "alg": "RS256", "use": "sig"}


def _signed_jwt(
    *, kid: str = "kid-1", drop: tuple[str, ...] = (), **claims: Any
) -> str:
    """A correctly-signed token from TRUSTED, minus any claims in ``drop``."""
    now = int(time.time())
    payload = {"iss": TRUSTED, "sub": "user_1", "iat": now, "exp": now + 60}
    payload.update(claims)
    for name in drop:
        payload.pop(name)
    return jwt.encode(payload, _KEY, algorithm="RS256", headers={"kid": kid})


def _serve(
    monkeypatch: pytest.MonkeyPatch,
    handler: Callable[[httpx.Request], httpx.Response],
) -> list[httpx.Request]:
    """Route the verifier's JWKS fetches to ``handler``; return the requests."""
    seen: list[httpx.Request] = []
    real_client = httpx.AsyncClient

    def _record(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    def _client(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
        return real_client(*args, transport=httpx.MockTransport(_record), **kwargs)

    monkeypatch.setattr(clerk_module.httpx, "AsyncClient", _client)
    return seen


def _serve_keys(monkeypatch: pytest.MonkeyPatch, *kids: str) -> list[httpx.Request]:
    return _serve(
        monkeypatch,
        lambda _req: httpx.Response(200, json={"keys": [_jwk(k) for k in kids]}),
    )


class _Clock:
    """Stands in for the ``time`` module inside identity.clerk only.

    Patching ``time.monotonic`` itself would also move the event loop's
    clock, which the test runner depends on.
    """

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr(
        clerk_module, "time", types.SimpleNamespace(monotonic=c.monotonic)
    )
    return c


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


async def test_valid_signed_token_verifies(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve_keys(monkeypatch, "kid-1")
    got = await _verifier().verify(_signed_jwt())
    assert got.issuer == TRUSTED
    assert got.subject == "user_1"
    assert got.kind == "human"


@pytest.mark.parametrize("claim", ["exp", "iat", "sub", "iss"])
async def test_signed_token_missing_required_claim_rejected(
    claim: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Without ``exp`` a leaked token is valid forever; a good signature
    over it proves nothing about now."""
    _serve_keys(monkeypatch, "kid-1")
    with pytest.raises(CredentialInvalid):
        await _verifier().verify(_signed_jwt(drop=(claim,)))


async def test_authorized_parties_unset_ignores_azp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _serve_keys(monkeypatch, "kid-1")
    got = await _verifier().verify(_signed_jwt(azp="https://anything.example"))
    assert got.subject == "user_1"


async def test_authorized_party_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    _serve_keys(monkeypatch, "kid-1")
    v = _verifier(authorized_parties=(APP,))
    got = await v.verify(_signed_jwt(azp=APP))
    assert got.subject == "user_1"


@pytest.mark.parametrize("azp", ["https://evil.example", None])
async def test_unauthorized_party_rejected(
    azp: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session minted for another origin, or for none, is not one of ours."""
    _serve_keys(monkeypatch, "kid-1")
    v = _verifier(authorized_parties=(APP,))
    token = _signed_jwt(azp=azp) if azp else _signed_jwt()
    with pytest.raises(CredentialInvalid):
        await v.verify(token)


def _refuse_connection(request: httpx.Request) -> httpx.Response:
    raise httpx.ConnectError("connection refused", request=request)


@pytest.mark.parametrize(
    "handler",
    [
        _refuse_connection,
        lambda _req: httpx.Response(503, text="upstream down"),
        lambda _req: httpx.Response(200, text="<html>not json</html>"),
        lambda _req: httpx.Response(200, json={"no": "keys"}),
        lambda _req: httpx.Response(200, json=["not", "an", "object"]),
    ],
    ids=["transport-error", "error-status", "bad-json", "no-keys", "not-an-object"],
)
async def test_jwks_fetch_failure_raises_issuer_unavailable(
    handler: Callable[[httpx.Request], httpx.Response],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An issuer outage must stay inside the Verifier contract.

    Anything that is not an IdentityError escapes an adapter's mapping and
    becomes a 500; and it must not be CredentialInvalid either, because the
    credential was never judged.
    """
    _serve(monkeypatch, handler)
    with pytest.raises(IssuerUnavailable) as exc:
        await _verifier().verify(_signed_jwt())
    assert isinstance(exc.value, IdentityError)
    assert not isinstance(exc.value, CredentialInvalid)


async def test_unknown_kid_refetch_is_rate_limited(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    """An attacker-chosen kid must not buy an outbound request per call."""
    seen = _serve_keys(monkeypatch, "kid-1")
    v = _verifier()
    await v.verify(_signed_jwt())
    assert len(seen) == 1

    # The document is fresh, so a miss now is just invalid.
    clock.now += 1
    for _ in range(20):
        with pytest.raises(CredentialInvalid):
            await v.verify(_signed_jwt(kid="forged"))
    assert len(seen) == 1

    # Past the floor, one miss buys one refetch, and the next ones wait again.
    clock.now += clerk_module._KID_MISS_REFETCH_SECS
    for _ in range(20):
        with pytest.raises(CredentialInvalid):
            await v.verify(_signed_jwt(kid="forged"))
    assert len(seen) == 2


async def test_rotated_key_is_picked_up_after_the_floor(
    monkeypatch: pytest.MonkeyPatch, clock: _Clock
) -> None:
    """The rate limit must not turn a real rotation into a 5-minute outage."""
    published = ["kid-1"]
    seen = _serve(
        monkeypatch,
        lambda _req: httpx.Response(200, json={"keys": [_jwk(k) for k in published]}),
    )
    v = _verifier()
    await v.verify(_signed_jwt())

    published.append("kid-2")
    clock.now += clerk_module._KID_MISS_REFETCH_SECS
    got = await v.verify(_signed_jwt(kid="kid-2"))
    assert got.subject == "user_1"
    assert len(seen) == 2
