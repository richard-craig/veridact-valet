"""
`valet doctor`: check a bank's Valet setup from the outside, the way an agent will meet it.

    python -m valet.doctor https://bank.example      # a running deployment
    python -m valet.doctor --self-test               # the in-process demo bank (no network)

Each check prints PASS or FAIL with what to fix. It reads only public metadata and makes unauthenticated calls that
must be refused; it never signs in, never moves money and needs no credentials. Exit code 0 means every check passed.

For the full behaviour (consent, payments, approvals, stopping, receipts) run the conformance tests against the
deployment: `python -m pytest tests/test_profile.py`.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable
from urllib.parse import urlsplit

import httpx


@dataclass
class Check:
    area: str
    name: str
    ok: bool
    detail: str = ""
    fix: str = ""


@dataclass
class Report:
    base: str
    checks: list[Check] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(c.ok for c in self.checks)

    def add(self, area: str, name: str, ok: bool, detail: str = "", fix: str = "") -> None:
        self.checks.append(Check(area, name, bool(ok), detail, "" if ok else fix))

    def as_dict(self) -> dict[str, Any]:
        return {"base": self.base, "ok": self.ok, "passed": sum(c.ok for c in self.checks), "total": len(self.checks),
                "checks": [c.__dict__ for c in self.checks]}


async def _json(c: httpx.AsyncClient, path: str) -> tuple[int, Any]:
    r = await c.get(path)
    try:
        return r.status_code, r.json()
    except (json.JSONDecodeError, ValueError):
        return r.status_code, None


async def run(base: str, client: httpx.AsyncClient) -> Report:
    base = base.rstrip("/")
    rep = Report(base)
    host = urlsplit(base).netloc

    # 1. Poppy discovery
    status, doc = await _json(client, "/.well-known/poppy.json")
    rep.add("Discovery", "poppy.json is served", status == 200 and isinstance(doc, dict), f"HTTP {status}",
            "Serve /.well-known/poppy.json (valet/bank/poppy.py) so personal agents can find the bank")
    doc = doc if isinstance(doc, dict) else {}
    rep.add("Discovery", "organization.domain is this host", (doc.get("organization") or {}).get("domain") == host,
            f"domain={(doc.get('organization') or {}).get('domain')!r}, host={host!r}",
            "Poppy agents reject a document whose domain differs from the host that served it (Poppy 1.1 §3)")
    auth = doc.get("auth") or {}
    scopes, hints = auth.get("scopes") or {}, auth.get("scope_hints") or {}
    missing = [s for s in scopes if s not in hints]
    rep.add("Discovery", "every scope has risk hints", bool(scopes) and not missing,
            f"{len(scopes)} scopes" + (f", no hints for {missing}" if missing else ""),
            "Give each scope `changes` and `personal_data` hints (Poppy 1.1 §4.7; Valet profile §2)")
    bad = [s for s, hnt in hints.items() if hnt.get("changes") not in ("none", "reversible", "irreversible")]
    rep.add("Discovery", "hints use Poppy's values", not bad, f"bad: {bad}" if bad else "",
            "`changes` must be none, reversible or irreversible")
    ext = ((doc.get("extensions") or {}).get("veridact.net/valet") or [{}])[0]
    rep.add("Discovery", "Valet extension advertised", ext.get("version") == "1", json.dumps(ext)[:120],
            "List `veridact.net/valet` version 1 in `extensions` (docs/poppy-extension.md §1)")

    # 2. Authorisation server
    status, md = await _json(client, "/.well-known/oauth-authorization-server")
    md = md if isinstance(md, dict) else {}
    rep.add("Authorisation server", "metadata is served", status == 200 and bool(md), f"HTTP {status}",
            "Publish RFC 8414 metadata at /.well-known/oauth-authorization-server")
    rep.add("Authorisation server", "issuer matches", md.get("issuer", "").rstrip("/") == base,
            f"issuer={md.get('issuer')!r}", "The metadata `issuer` must equal the bank's issuer URL exactly")
    rep.add("Authorisation server", "PAR is required", md.get("require_pushed_authorization_requests") is True,
            "", "Set require_pushed_authorization_requests (FAPI 2.0; Valet technical design §4)")
    rep.add("Authorisation server", "DPoP with ES256", "ES256" in (md.get("dpop_signing_alg_values_supported") or []),
            "", "Advertise dpop_signing_alg_values_supported: [ES256]")
    rep.add("Authorisation server", "Valet permission types", {"valet_accounts", "valet_payments"} <=
            set(md.get("authorization_details_types_supported") or []), "",
            "Advertise valet_accounts and valet_payments in authorization_details_types_supported (profile §1)")
    rep.add("Authorisation server", "issuer in authorisation responses",
            md.get("authorization_response_iss_parameter_supported") is True, "", "Return `iss` (RFC 9207)")
    rep.add("Authorisation server", "PKCE S256", "S256" in (md.get("code_challenge_methods_supported") or []), "",
            "Advertise code_challenge_methods_supported: [S256]")

    # 3. Keys
    jwks_uri = md.get("jwks_uri") or base + "/jwks"
    status, jwks = await _json(client, urlsplit(jwks_uri).path or "/jwks")
    keys = (jwks or {}).get("keys") if isinstance(jwks, dict) else None
    rep.add("Keys", "JWKS is served", bool(keys), f"{len(keys or [])} keys",
            "Publish the bank's signing keys, including the receipt key, at jwks_uri")
    rep.add("Keys", "only EC P-256 signing keys", bool(keys) and all(k.get("kty") == "EC" and k.get("crv") == "P-256"
                                                                     for k in keys or []), "",
            "Valet signs tokens and receipts with ES256 only")

    # 4. Front doors refuse what they must
    r = await client.get("/api/accounts")
    rep.add("API", "unauthenticated call refused", r.status_code == 401, f"HTTP {r.status_code}",
            "The banking API must refuse calls without a DPoP-bound token")
    rep.add("API", "asks for DPoP", "dpop" in r.headers.get("www-authenticate", "").lower(),
            r.headers.get("www-authenticate", ""), "Return WWW-Authenticate: DPoP on 401 (RFC 9449)")
    r = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    wa = r.headers.get("www-authenticate", "")
    rep.add("MCP", "unauthenticated MCP call refused with a metadata pointer",
            r.status_code == 401 and "resource_metadata" in wa, f"HTTP {r.status_code} {wa[:80]}",
            "Answer with 401 and WWW-Authenticate: Bearer resource_metadata=… (Claude needs it to find sign-in)")
    status, prm = await _json(client, "/.well-known/oauth-protected-resource/mcp")
    prm = prm if isinstance(prm, dict) else {}
    rep.add("MCP", "protected resource metadata names the MCP URL",
            status == 200 and prm.get("resource", "").rstrip("/") == base + "/mcp",
            f"resource={prm.get('resource')!r}", "The `resource` must equal the MCP server URL exactly")

    # 5. Readiness
    status, ready = await _json(client, "/readyz")
    rep.add("Operations", "readiness endpoint", status == 200, f"HTTP {status}",
            "Expose /readyz with the registry, denylist and payments adapter state")
    return rep


def render(rep: Report) -> str:
    out, area = [f"Valet doctor: {rep.base}", ""], None
    for c in rep.checks:
        if c.area != area:
            area = c.area
            out.append(area)
        out.append(f"  {'PASS' if c.ok else 'FAIL'}  {c.name}" + (f"  ({c.detail})" if c.detail and not c.ok else ""))
        if c.fix:
            out.append(f"        fix: {c.fix}")
    out += ["", f"{sum(c.ok for c in rep.checks)}/{len(rep.checks)} checks passed"]
    return "\n".join(out)


async def self_test() -> Report:
    from .harness import BANK, Harness
    h = Harness()
    async with httpx.AsyncClient(transport=h.transport, base_url=BANK) as c:
        return await run(BANK, c)


async def remote(base: str) -> Report:
    async with httpx.AsyncClient(base_url=base.rstrip("/"), timeout=10, follow_redirects=False) as c:
        return await run(base, c)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="valet doctor", description=__doc__.split("\n\n")[0])
    p.add_argument("url", nargs="?", help="the bank's issuer URL, e.g. https://bank.example")
    p.add_argument("--self-test", action="store_true", help="check the in-process demo bank")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    a = p.parse_args(argv)
    if not a.url and not a.self_test:
        p.error("give a URL or --self-test")
    rep = asyncio.run(self_test() if a.self_test else remote(a.url))
    print(json.dumps(rep.as_dict(), indent=2) if a.json else render(rep))
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
