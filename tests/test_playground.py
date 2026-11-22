"""The playground and the doctor: both run against an in-process demo bank and must pass end to end."""
from __future__ import annotations

import asyncio

import httpx

from valet.apps.playground import WITHOUT, get_app
from valet.doctor import Report, render, self_test


def run(coro):
    return asyncio.run(coro)


def test_doctor_passes_on_the_demo_bank():
    rep = run(self_test())
    assert rep.ok, render(rep)
    assert rep.as_dict()["total"] >= 15


def test_doctor_report_shows_fixes_for_failures():
    rep = Report("https://bank.example")
    rep.add("Discovery", "poppy.json is served", False, "HTTP 404", "Serve /.well-known/poppy.json")
    assert not rep.ok and "fix: Serve /.well-known/poppy.json" in render(rep)


def test_playground_with_valet_passes_every_step_and_without_fails_every_step():
    async def t():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=get_app()), base_url="http://pg.test") as c:
            assert (await c.get("/")).status_code == 200
            with_ = (await c.get("/api/with")).json()
            without = (await c.get("/api/without")).json()
            doctor = (await c.get("/api/doctor")).json()
        assert with_ and all(s["ok"] for s in with_), [s for s in with_ if not s["ok"]]
        assert without == WITHOUT and not any(s["ok"] for s in without)
        assert doctor["ok"]
    run(t())
