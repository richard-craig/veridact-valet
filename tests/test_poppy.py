"""
Personal Agent Protocol (Poppy) support (docs/poppy-extension.md): the discovery document with risk hints, and the
Session ID carried into receipts. A Poppy Session is evidence only; it never grants access.
"""
from __future__ import annotations

import asyncio
import json

import httpx

from valet.bank.poppy import LEVEL_HINTS
from valet.common.crypto import Key
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


def poppy_headers(agent_key: Key, client_id: str, sid: str):
    delegated = Key.generate()
    dlg = make_delegation(agent_key, client_id, delegated)

    def headers(method: str, url: str, token: str):
        return {"Poppy-Session": make_session(delegated, dlg, client_id, BANK, sid, "usr_test", method, url, token)}
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
                           "sub": "usr_test", "delegated_key": session["delegated_key"]}
    run(t())


def test_session_signed_by_someone_else_is_recorded_unverified_and_grants_nothing():
    async def t():
        h = Harness()
        await h.connect()
        h.kaya.extra_headers = poppy_headers(Key.generate(), "kaya", "sess_forged")   # not Kaya's registered key
        await h.kaya.accounts()                                                           # access comes from the token
        session = last_receipt(h)["session"]
        assert session["verified"] is False and session["sid"] == "sess_forged"
    run(t())


def test_session_checks():
    agent, delegated = Key.generate(), Key.generate()
    dlg = make_delegation(agent, "kaya", delegated)
    url = BANK + "/api/accounts"
    good = make_session(delegated, dlg, "kaya", BANK, "s1", "u1", "GET", url, "tok")
    lookup = {"kaya": agent.jwk}.get
    assert read_session(good, lookup, BANK, "GET", url + "?x=1", "tok")["verified"] is True
    assert read_session(good, lookup, BANK, "POST", url, "tok")["why"] == "htm_htu"
    assert read_session(good, lookup, BANK, "GET", url, "other-token")["why"] == "ath"
    assert read_session(good, lookup, "https://other.bank", "GET", url, "tok")["verified"] is False
    assert read_session(good, {}.get, BANK, "GET", url, "tok")["why"] == "agent_key_unknown"
    assert read_session("not-a-jwt", lookup, BANK, "GET", url)["verified"] is False
