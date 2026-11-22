"""
Valet Playground: watch an AI agent reach a bank account without Valet, then with it, step by step, with what the
bank checked at each step and whether it passed. Plus the doctor (valet/doctor.py) against the demo bank.

Every run uses a fresh, in-process demo bank (Marula Bank, fictional) and a fictional agent (Kaya). Nothing leaves
the process: no real bank, no network calls, no personal data. Safe to host publicly.

    uvicorn valet.apps.playground:get_app --factory --port 8003
"""
from __future__ import annotations

import time
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from ..agent.sdk import ValetError
from ..common.crypto import Key
from ..common.dpop import make_proof
from ..doctor import self_test
from ..harness import BANK, Harness

WITHOUT = [
    {"title": "The agent asks for the customer's banking password", "actor": "AGENT",
     "what": "Thandi types her username and password into the assistant.",
     "check": "Is the password still a secret only Thandi knows?", "ok": False,
     "note": "Now the agent, its operator and anyone who breaches them hold it."},
    {"title": "The agent signs in to web banking as Thandi", "actor": "AGENT",
     "what": "It drives a browser through the bank's login, including the OTP Thandi forwards.",
     "check": "Can the bank tell an agent from Thandi?", "ok": False,
     "note": "The bank sees Thandi. Its fraud team may block it as an attack, or miss a real one."},
    {"title": "The agent pays the water bill", "actor": "AGENT",
     "what": "It pays R640 to Water & Sanitation.",
     "check": "Was the payment checked against what Thandi allowed?", "ok": False,
     "note": "There is nothing to check against: the agent has everything Thandi has."},
    {"title": "The agent is tricked by a malicious web page", "actor": "ATTACK",
     "what": "A prompt injection tells it to add 'QuickLoans' as a beneficiary and pay R9,000.",
     "check": "Does anything outside the model stop it?", "ok": False,
     "note": "Only the bank's normal fraud rules, which see Thandi doing it."},
    {"title": "Thandi wants the agent to stop", "actor": "PERSON",
     "what": "She has to change her password, and every other place she reused it.",
     "check": "Can she stop just the agent, at once?", "ok": False,
     "note": "Stopping the agent means locking herself out too."},
    {"title": "There is a dispute about a payment", "actor": "BANK",
     "what": "Thandi says she never asked for the R9,000 payment.",
     "check": "Is there a record of who decided what?", "ok": False,
     "note": "The logs show Thandi's login. The agent is never its own witness here; it's no witness at all."},
]


async def with_valet() -> list[dict[str, Any]]:
    h = Harness()
    kaya, steps = h.kaya, []

    def add(title: str, actor: str, what: str, check: str, ok: bool, note: str = "", receipt: int | None = None):
        steps.append({"title": title, "actor": actor, "what": what, "check": check, "ok": bool(ok), "note": note,
                      "receipt": receipt})

    def last_seq() -> int:
        return h.bank.store.one("SELECT MAX(seq) AS s FROM receipts")["s"] or 0

    async with httpx.AsyncClient(transport=h.transport, base_url=BANK) as c:
        doc = (await c.get("/.well-known/poppy.json")).json()
    hints = doc["auth"]["scope_hints"]
    add("The agent finds the bank's front door", "AGENT",
        "GET /.well-known/poppy.json: what agents may ask for, with a risk hint on each scope: "
        + ", ".join(f"{s} ({v['changes']})" for s, v in hints.items()),
        "Does every permission say whether it changes anything?", all("changes" in v for v in hints.values()))

    url, pending = await kaya.start_connect("bill_payer")
    await h.login()
    html, back = await h.consent(url, "bill_payer", 2_000_00)
    await kaya.finish_connect(back["code"][0], pending, back["state"][0], back["iss"][0])
    add("Thandi connects Kaya on the bank's own screen", "PERSON",
        "Kaya pushes its request (PAR); Thandi signs in to Marula Bank, sees the verified operator, picks Bill payer "
        "with R2,000 a month, and confirms. Kaya gets a token bound to its own key.",
        "Did Thandi keep her password to herself?", "Kaya Labs" in html, "Yes. The agent never sees a password, PIN or OTP.",
        last_seq())

    accts = await kaya.accounts()
    add("Kaya reads the balance", "AGENT", f"GET /api/accounts → {accts[0]['name']} R{accts[0]['balance']}",
        "Allowed by the mandate, and recorded?", bool(accts), receipt=last_seq())

    key = f"water-{int(time.time())}"
    paid = await kaya.pay("acc_4821", "Water & Sanitation", "40021187", "640.00", "Water Oct", idempotency_key=key)
    add("Kaya pays the water bill, inside the limit", "AGENT",
        f"POST /api/payments R640 → {paid['outcome']} (this month R{paid['spent_this_month']} of "
        f"R{paid['monthly_limit']})",
        "Checked against Thandi's mandate on this call?", paid["outcome"] == "paid", receipt=last_seq())

    again = await kaya.pay("acc_4821", "Water & Sanitation", "40021187", "640.00", "Water Oct", idempotency_key=key)
    debits = len(h.bank.store.q("SELECT 1 FROM transactions WHERE description LIKE 'To Water%'"))
    add("The network drops and Kaya retries", "AGENT",
        f"Same request, same Idempotency-Key → {again['outcome']}, {debits} debit at the bank",
        "Paid exactly once?", debits == 1 and again.get("payment_intent_id") == paid.get("payment_intent_id"))

    thief = Key.generate()
    u = BANK + "/api/accounts"
    r = await kaya.http.get(u, headers={"Authorization": f"DPoP {kaya.session.access_token}",
                                        "DPoP": make_proof(thief, "GET", u, kaya.session.access_token)})
    add("Someone steals Kaya's token", "ATTACK", f"Uses it with their own key → HTTP {r.status_code}",
        "Is a stolen token useless?", r.status_code == 401)

    try:
        await kaya.call("POST", "/api/beneficiaries", {"name": "QuickLoans", "account": "99887766"})
        blocked, why = False, "added"
    except ValetError as e:
        blocked, why = True, e.error
    add("Kaya is tricked into adding 'QuickLoans'", "ATTACK", f"POST /api/beneficiaries → refused ({why})",
        "Stopped by the bank, outside the model?", blocked, "Agents can never add beneficiaries.", last_seq())

    held = await kaya.pay("acc_4821", "City Power", "30087712", "1250.00", "Electricity Oct", "Due on Friday")
    add("Kaya tries to pay someone new", "AGENT",
        f"R1,250 to City Power → {held['outcome']} (reason: {held.get('reason_code') or held.get('reason')})",
        "Held for Thandi instead of paid?", held["outcome"] == "approval_pending", receipt=last_seq())

    await h.decide(held["auth_req_id"], approve=True)
    done = await kaya.check_approval(held["auth_req_id"])
    add("Thandi approves in her bank app", "PERSON",
        f"The bank, not the agent, shows her the exact payment. She approves → {done['outcome']} R{done['amount']}",
        "Approved by the customer, for this exact payment only?", done["outcome"] == "paid", receipt=last_seq())

    await h.grant_action(kaya.session.grant_id, "pause")
    try:
        await kaya.accounts()
        stopped = False
    except ValetError as e:
        stopped = e.error == "grant_paused"
    add("Thandi pauses Kaya", "PERSON", "One tap in the bank app. Kaya's next call → refused (grant_paused)",
        "Stopped at once, without changing her password?", stopped, receipt=last_seq())

    chain = h.bank.receipts.verify_chain()
    add("A dispute: who decided what?", "BANK",
        f"{chain['count']} signed, chained receipts: every read, payment, hold, approval and stop",
        "Does the evidence verify, independently of the agent?", chain["ok"],
        "The agent is never its own witness.")
    return steps


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Valet Playground</title>
<style>
:root{--ink:#14213D;--soft:#4A5568;--bg:#F6F4EF;--card:#FBFAF6;--line:#D9D3C7;--ok:#0F7A5C;--okbg:#E3F3EC;--bad:#A32D2D;--badbg:#FBEAEA}
*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--soft)}
header{background:var(--ink);color:#F6F4EF;padding:32px 24px}header h1{margin:0 0 6px;font-size:28px}header p{margin:0;color:#C9D3E3;max-width:760px}
main{max-width:1200px;margin:0 auto;padding:24px}.cols{display:grid;grid-template-columns:1fr 1fr;gap:24px}
@media(max-width:900px){.cols{grid-template-columns:1fr}}
h2{color:var(--ink);font-size:20px;margin:0 0 12px}button{font:inherit;background:var(--ink);color:#fff;border:0;border-radius:8px;padding:10px 18px;cursor:pointer}
button:disabled{opacity:.5;cursor:default}.step{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:0 0 10px}
.step .top{display:flex;justify-content:space-between;gap:12px;align-items:baseline}.step h3{margin:0;color:var(--ink);font-size:16px}
.actor{font-size:12px;font-weight:600;letter-spacing:1px;color:var(--soft)}.what{margin:6px 0;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;color:var(--ink)}
.verdict{border-radius:8px;padding:6px 10px;font-size:14px;margin-top:6px}.pass{background:var(--okbg);color:var(--ok)}.fail{background:var(--badbg);color:var(--bad)}
.note{font-size:14px;margin-top:4px}.rcpt{font-size:12px;color:var(--soft)}.summary{font-weight:600;color:var(--ink);margin:8px 0 16px}
table{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:12px}td{padding:6px 10px;border-top:1px solid var(--line);font-size:14px}
footer{max-width:1200px;margin:0 auto;padding:16px 24px 40px;font-size:13px}
</style></head><body>
<header><h1>Valet Playground</h1><p>An AI agent (Kaya, fictional) pays bills for Thandi at Marula Bank (fictional). Run it without Valet, then with it, and see what the bank can check at each step. Everything runs in a demo bank in this process: no real accounts, no personal data.</p></header>
<main>
<div class="cols">
 <section><h2>Without Valet</h2><button id="b1">Run without Valet</button><div class="summary" id="s1"></div><div id="without"></div></section>
 <section><h2>With Valet</h2><button id="b2">Run with Valet</button><div class="summary" id="s2"></div><div id="with"></div></section>
</div>
<section style="margin-top:32px"><h2>Doctor</h2><p>The checks an agent meets at the bank's front door: discovery, the authorisation server, keys, and the API and MCP server refusing what they must.</p>
<button id="b3">Run the doctor on the demo bank</button><div class="summary" id="s3"></div><div id="doctor"></div></section>
</main>
<footer>Veridact Valet · Apache 2.0 · <a href="https://github.com/richard-craig/veridact-valet">source</a> · <a href="/api/with">JSON</a></footer>
<script>
function el(t,c,x){const e=document.createElement(t);if(c)e.className=c;if(x!==undefined)e.textContent=x;return e}
function card(s){const d=el('div','step');const top=el('div','top');top.append(el('h3','',s.title),el('span','actor',s.actor));d.append(top,el('div','what',s.what));
 d.append(el('div','verdict '+(s.ok?'pass':'fail'),(s.ok?'PASS  ':'FAIL  ')+s.check));if(s.note)d.append(el('div','note',s.note));
 if(s.receipt)d.append(el('div','rcpt','Receipt #'+s.receipt));return d}
async function play(btn,url,box,sum){btn.disabled=true;box.textContent='';sum.textContent='Running…';
 const steps=await (await fetch(url)).json();sum.textContent='';
 for(const s of steps){box.append(card(s));await new Promise(r=>setTimeout(r,350))}
 const n=steps.filter(s=>s.ok).length;sum.textContent=n+' of '+steps.length+' checks passed';btn.disabled=false}
b1.onclick=()=>play(b1,'/api/without',without,s1);b2.onclick=()=>play(b2,'/api/with',document.getElementById('with'),s2);
b3.onclick=async()=>{b3.disabled=true;doctor.textContent='';s3.textContent='Running…';const r=await (await fetch('/api/doctor')).json();
 const t=el('table');for(const c of r.checks){const tr=el('tr');tr.append(el('td','',c.area),el('td','',c.name),el('td',c.ok?'pass':'fail',c.ok?'PASS':'FAIL'),el('td','',c.fix||''));t.append(tr)}
 doctor.append(t);s3.textContent=r.passed+' of '+r.total+' checks passed';b3.disabled=false}
</script></body></html>"""


def get_app() -> FastAPI:
    app = FastAPI(title="Valet Playground", docs_url=None, redoc_url=None)

    @app.get("/", response_class=HTMLResponse)
    def index():
        return PAGE

    @app.get("/api/without")
    def without():
        return WITHOUT

    @app.get("/api/with")
    async def with_():
        return await with_valet()

    @app.get("/api/doctor")
    async def doctor():
        return (await self_test()).as_dict()

    return app
