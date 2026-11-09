#!/usr/bin/env python3
"""
Veridact Valet, end to end, in one process. Exits 0 only if every check behaves as designed.

Thandi (PERSON) connects Kaya (AGENT) to Marula Bank (BANK) without sharing her password,
then we try everything that should and should not work.
"""
from __future__ import annotations

import asyncio
import os
import sys

from valet.agent.sdk import ValetError
from valet.common.crypto import Key
from valet.common.dpop import make_proof
from valet.harness import BANK, Harness

_C = (sys.stdout.isatty() and not os.environ.get("NO_COLOR")) or os.environ.get("FORCE_COLOR")
def c(code, s): return f"\033[{code}m{s}\033[0m" if _C else s
TAG = {"PERSON": "33", "AGENT": "35", "BANK": "32", "ATTACK": "31"}
checks: list[tuple[str, bool]] = []


def step(n: int, title: str) -> None:
    print("\n" + c("1;36", f"━━ {n}. {title} " + "━" * max(0, 70 - len(title))))


def say(who: str, text: str) -> None:
    print(f"  {c(TAG[who], f'{who:<6}')} {text}")


def check(name: str, ok: bool) -> None:
    checks.append((name, ok))
    print(f"  {c('32', '✔') if ok else c('31', '✘')} {c('2', name)}")


async def expect_error(coro, error: str) -> ValetError | None:
    try:
        await coro
    except ValetError as e:
        return e if e.error == error else None
    return None


async def main() -> int:
    h = Harness()
    kaya = h.kaya

    step(1, "A copycat agent tries to connect")
    copycat = h.agent("copycat", h.copycat_key)
    e = await expect_error(copycat.start_connect(), "unauthorized_client")
    say("BANK", f"refused at PAR: {e.body['error_description'] if e else 'NOT REFUSED'}")
    check("Unverified agent refused before the customer sees anything", e is not None)

    step(2, "Thandi connects Kaya, without sharing her password")
    url, pending = await kaya.start_connect("bill_payer")
    say("AGENT", "pushes its request to the bank (PAR) and sends Thandi to Marula's own screen")
    await h.login()
    say("PERSON", "signs in to Marula Bank (in the real app: fingerprint)")
    html, back = await h.consent(url, "bill_payer", 2_000_00)
    say("PERSON", "sees 'Kaya · Kaya Labs (Pty) Ltd · Verified by Veridact', picks Bill payer, R2,000 a month, confirms")
    check("Consent screen shows the verified operator from the registry", "Verified by Veridact" in html and "Kaya Labs" in html)
    await kaya.finish_connect(back["code"][0], pending, back["state"][0])
    say("AGENT", f"swaps the one-time code for a key-bound token (grant {kaya.session.grant_id})")
    check("Token is DPoP-bound and carries Bill payer details",
          any(d["type"] == "valet_payments" for d in kaya.session.details))

    step(3, "Someone steals Kaya's token")
    thief = Key.generate()
    url_ = BANK + "/api/accounts"
    r = await kaya.http.get(url_, headers={"Authorization": f"DPoP {kaya.session.access_token}",
                                           "DPoP": make_proof(thief, "GET", url_, kaya.session.access_token)})
    say("ATTACK", f"uses the stolen token with their own key -> {r.status_code} {r.json()['error']}")
    check("Stolen token useless without Kaya's private key", r.status_code == 401)
    proof = make_proof(kaya.key, "GET", url_, kaya.session.access_token)
    hdrs = {"Authorization": f"DPoP {kaya.session.access_token}", "DPoP": proof}
    await kaya.http.get(url_, headers=hdrs)
    r = await kaya.http.get(url_, headers=hdrs)
    say("ATTACK", f"replays a captured request -> {r.status_code} {r.json()['error']}")
    check("Replayed DPoP proof refused", r.status_code == 401)

    step(4, "Kaya works inside the limit")
    accts = await kaya.accounts()
    say("AGENT", f"reads balances: {accts[0]['name']} R{accts[0]['balance']}")
    res = await kaya.pay("acc_4821", "Water & Sanitation", "40021187", "640.00", "Water Oct")
    say("AGENT", f"pays the water bill: {res['outcome']} R{res['amount']} (this month R{res['spent_this_month']} of R{res['monthly_limit']})")
    check("Existing beneficiary inside the limit is paid without a prompt", res["outcome"] == "paid")

    step(5, "A new recipient: Thandi decides in her bank app")
    res = await kaya.pay("acc_4821", "City Power", "30087712", "1250.00", "Electricity Oct", "Due on Friday")
    say("BANK", f"holds it: {res.get('reason')}")
    check("New recipient triggers an approval, not a payment", res["outcome"] == "approval_pending")
    aid = res["auth_req_id"]
    page = await h.decide(aid, approve=True)
    say("PERSON", "gets a push from Marula: 'Kaya wants to pay R1,250.00 to City Power (new recipient)', approves")
    check("Approval screen is built by the bank and shows the scam warning",
          "R1,250.00" in page and "New recipient" in page and "never ask you to approve" in page)
    done = await kaya.check_approval(aid)
    say("AGENT", f"collects a one-time token and pays: {done['outcome']} R{done['amount']}")
    check("Approved payment goes through once", done["outcome"] == "paid")

    step(6, "Trying to misuse an approval")
    once = done["once_token"]
    e = await expect_error(kaya.call("POST", "/api/payments", kaya.approvals[aid], token=once), "approval_invalid")
    say("AGENT", f"reuses the approval -> refused: {e.body['error_description'] if e else 'NOT REFUSED'}")
    check("An approval cannot be used twice", e is not None)
    res2 = await kaya.pay("acc_4821", "City Power", "30087712", "1250.00", "Electricity Oct")
    await h.decide(res2["auth_req_id"], approve=True)
    tok = (await kaya._post_form("/token", {"grant_type": "urn:openid:params:grant-type:ciba",
                                            "auth_req_id": res2["auth_req_id"]}, dpop=True))["access_token"]
    bigger = {**kaya.approvals[res2["auth_req_id"]], "amount": "12500.00"}
    e = await expect_error(kaya.call("POST", "/api/payments", bigger, token=tok), "approval_invalid")
    say("AGENT", f"uses an approval for R12,500 instead of R1,250 -> refused: {e.body['error_description'] if e else 'NOT REFUSED'}")
    check("An approval cannot be used for a different amount", e is not None)

    step(7, "Over the monthly limit, and Thandi says no")
    res = await kaya.pay("acc_4821", "Sunrise Primary School", "62114930", "1500.00", "Term 4", "Term 4 fees")
    say("BANK", f"holds it: {res.get('reason')}")
    check("Payment over the monthly limit needs approval", res["outcome"] == "approval_pending")
    await h.decide(res["auth_req_id"], approve=False)
    say("PERSON", "declines in the Marula app")
    done = await kaya.check_approval(res["auth_req_id"])
    say("AGENT", f"-> {done['outcome']}; nothing paid")
    check("Declined approval pays nothing", done["outcome"] == "declined")

    step(8, "Kaya is tricked into adding a beneficiary")
    e = await expect_error(kaya.call("POST", "/api/beneficiaries", {"name": "QuickLoans", "account": "99887766"}),
                           "insufficient_authorization")
    say("BANK", f"refused: {e.body['error_description'] if e else 'NOT REFUSED'}")
    check("Agents can never add beneficiaries", e is not None)

    step(9, "Thandi pauses Kaya, then resumes")
    gid = kaya.session.grant_id
    await h.grant_action(gid, "pause")
    say("PERSON", "taps Pause Kaya")
    e = await expect_error(kaya.accounts(), "grant_paused")
    say("AGENT", f"next call -> {e.error if e else 'NOT REFUSED'}")
    check("Pause takes effect on the very next call", e is not None)
    e = await expect_error(kaya.refresh(), "invalid_grant")
    check("A paused grant cannot be refreshed", e is not None)
    await h.grant_action(gid, "resume")
    ok = bool(await kaya.accounts())
    say("PERSON", "taps Resume; Kaya works again")
    check("Resume restores access", ok)

    step(10, "A copy of Kaya's refresh token is used")
    stolen_rt = kaya.session.refresh_token
    await kaya.refresh()
    kaya.session.refresh_token = stolen_rt
    e = await expect_error(kaya.refresh(), "invalid_grant")
    say("BANK", f"detects reuse: {e.body['error_description'] if e else 'NOT DETECTED'}")
    check("Refresh-token reuse pauses the grant", e is not None and h.bank.store.grant(gid)["status"] == "paused")
    await h.grant_action(gid, "resume")

    step(11, "The bank (or Veridact) stops trusting Kaya's operator")
    h.bank.registry.set_trust("kaya", False)
    e = await expect_error(kaya.accounts(), "agent_untrusted")
    say("BANK", f"every grant for Kaya stops -> {e.error if e else 'NOT REFUSED'}")
    check("Withdrawn operator trust stops the agent everywhere", e is not None)
    h.bank.registry.set_trust("kaya", True)

    step(12, "Thandi disconnects Kaya")
    await h.grant_action(gid, "revoke")
    e = await expect_error(kaya.call("GET", "/api/accounts", token=kaya.session.access_token), "grant_revoked")
    say("AGENT", f"-> {e.error if e else 'NOT REFUSED'}")
    check("Disconnect is immediate and final", e is not None)

    step(13, "Every decision has a signed receipt")
    chain = h.bank.receipts.verify_chain()
    say("BANK", f"{chain['count']} receipts, chain intact: {chain['ok']}")
    check("Receipt chain verifies", chain["ok"])
    row = h.bank.store.one("SELECT seq, record FROM receipts WHERE record LIKE '%Water & Sanitation%' AND record LIKE '%allowed%'")
    h.bank.store.x("UPDATE receipts SET record=? WHERE seq=?", row["record"].replace("640.00", "64.00"), row["seq"])
    broken = h.bank.receipts.verify_chain()
    say("ATTACK", f"changes the water payment in receipt {row['seq']} from R640 to R64 -> {broken['why']} at {broken.get('broken_at')}")
    check("Tampering with a receipt is detected", not broken["ok"] and broken["broken_at"] == row["seq"])
    h.bank.store.x("UPDATE receipts SET record=? WHERE seq=?", row["record"], row["seq"])

    print("\n" + c("1;36", "━━ Summary " + "━" * 66))
    good = all(ok for _, ok in checks)
    print(f"  {sum(ok for _, ok in checks)}/{len(checks)} checks passed")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
