"""
Personal Agent Protocol (Poppy) support (docs/poppy-extension.md): the discovery document with risk hints, and the
Session ID carried into receipts. A Poppy Session is evidence only; it never grants access.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from valet.bank.poppy import LEVEL_HINTS
from valet.common.crypto import Key
from valet.agent.sdk import ValetError
from valet.common.poppy import make_delegation, make_session, read_session
from valet.harness import BANK, Harness


def run(coro):
    return asyncio.run(coro)


def test_poppy_json_lists_scopes_hints_and_the_valet_extension():
    async def t():
        h = Harness()
        async with httpx.AsyncClient(transport=h.transport, base_url=BANK) as c:
            r = await c.get("/.well-known/poppy.json")
        assert r.status_code == 200
        doc = r.json()
        assert doc["protocol_version"] == "1.1" and doc["organization"]["domain"] == "bank.test"
        hints = doc["auth"]["scope_hints"]
        assert set(hints) == set(doc["auth"]["scopes"])
        assert hints["accounts:read"]["changes"] == "none"
        assert hints["payments:standing"]["changes"] == "irreversible"
        ext = doc["extensions"]["veridact.net/valet"][0]
        assert ext["version"] == "1" and ext["status"] == "draft" and set(ext["levels"]) == set(LEVEL_HINTS)
    run(t())


def poppy_headers(agent_key: Key, client_id: str, sid: str, version: str = "1.1"):
    delegated = Key.generate()
    dlg = make_delegation(agent_key, client_id, delegated)

    def headers(method: str, url: str, token: str):
        return {"Poppy-Session": make_session(delegated, dlg, client_id, BANK, sid, "usr_test", method, url, token),
                "Poppy-Version": version}
    return headers


def last_receipt(h: Harness) -> dict:
    return json.loads(h.bank.store.one("SELECT record FROM receipts ORDER BY seq DESC LIMIT 1")["record"])


def test_verified_session_id_is_recorded_in_receipts():
    async def t():
        h = Harness()
        await h.connect()
        h.kaya.extra_headers = poppy_headers(h.kaya_key, "kaya", "sess_abc123")
        await h.kaya.accounts()
        session = last_receipt(h)["session"]
        assert session == {"protocol": "poppy", "verified": True, "sid": "sess_abc123", "iss": "kaya",
                           "sub": "usr_test", "delegated_key": session["delegated_key"], "version": "1.1"}
    run(t())


def test_session_signed_by_someone_else_is_refused_and_never_recorded():
    async def t():
        h = Harness()
        await h.connect()
        before = h.bank.store.one("SELECT COUNT(*) n FROM receipts")["n"]
        h.kaya.extra_headers = poppy_headers(Key.generate(), "kaya", "sess_forged")   # not Kaya's registered key
        with pytest.raises(ValetError) as e:
            await h.kaya.accounts()               # a good token doesn't rescue a forged Session (Poppy 1.1, 5.3)
        assert (e.value.status, e.value.error) == (400, "invalid_session")
        assert h.bank.store.one("SELECT COUNT(*) n FROM receipts")["n"] == before
        h.kaya.extra_headers = lambda *a: {}
        assert await h.kaya.accounts()            # without a Session header the token still works
    run(t())


def test_session_needs_a_poppy_version_the_bank_serves():
    async def t():
        h = Harness()
        await h.connect()
        for version in ("", "2.0", "0.4", "1.9"):
            h.kaya.extra_headers = poppy_headers(h.kaya_key, "kaya", "sess_v", version=version)
            with pytest.raises(ValetError) as e:
                await h.kaya.accounts()
            assert (e.value.status, e.value.error) == (400, "version_unsupported"), version
        h.kaya.extra_headers = poppy_headers(h.kaya_key, "kaya", "sess_v", version="1.0")
        assert await h.kaya.accounts()
    run(t())


def test_session_checks():
    agent, delegated = Key.generate(), Key.generate()
    dlg = make_delegation(agent, "kaya", delegated)
    url = BANK + "/api/accounts"
    good = make_session(delegated, dlg, "kaya", BANK, "s1", "u1", "GET", url, "tok")
    lookup = lambda iss, kid: {"kaya": agent.jwk}.get(iss)    # noqa: E731
    assert read_session(good, lookup, BANK, "GET", url + "?x=1", "tok")["verified"] is True
    assert read_session(good, lookup, BANK, "POST", url, "tok")["why"] == "htm_htu"
    assert read_session(good, lookup, BANK, "GET", url, "other-token")["why"] == "ath"
    assert read_session(good, lookup, "https://other.bank", "GET", url, "tok")["verified"] is False
    assert read_session(good, lambda iss, kid: None, BANK, "GET", url, "tok")["why"] == "agent_key_unknown"
    assert read_session(good, lookup, BANK, "GET", url)["why"] == "ath"            # ath without a token
    no_ath = make_session(delegated, dlg, "kaya", BANK, "s1", "u1", "GET", url)
    assert read_session(no_ath, lookup, BANK, "GET", url)["verified"] is True
    assert read_session(no_ath, lookup, BANK, "GET", url, "tok")["why"] == "ath"   # token sent, no ath
    assert read_session("not-a-jwt", lookup, BANK, "GET", url)["verified"] is False
