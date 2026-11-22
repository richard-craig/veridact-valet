"""
How the bank's own servers (the enforcement points) reach the Valet decision service.

Two transports, one interface:

  InProcessDecisions  Valet in the same process (the PoC's default, and a sidecar that shares the process).
  HttpDecisions       Valet as a separate internal service: VALET_DECISION_URL, authenticated with
                      VALET_DECISION_SECRET (mTLS or private_key_jwt in a bank).

Either way the caller fails closed: if Valet cannot be reached, or answers with something the caller does not
understand, DecisionUnavailable is raised and nothing is done (docs/decision-service.md, "What the enforcement point
must do", steps 2 and 3).
"""
from __future__ import annotations

import os
from typing import Any

import httpx

from .service import BadRequest, Conflict, DecisionService


class DecisionUnavailable(Exception):
    """No usable answer from Valet: refuse the action."""


class NotFound(Exception):
    pass


class DecisionConflict(Exception):
    pass


class Decisions:
    """The calls an enforcement point makes."""

    async def evaluate(self, req: dict[str, Any]) -> dict[str, Any]: ...
    async def evaluations(self, req: dict[str, Any]) -> dict[str, Any]: ...
    async def access_request(self, binding_token: str) -> dict[str, Any]: ...
    async def task(self, task_id: str) -> dict[str, Any]: ...
    async def reservation(self, rid: str) -> dict[str, Any]: ...
    async def sent(self, rid: str) -> dict[str, Any]: ...
    async def commit(self, rid: str, bank_payment_id: str) -> dict[str, Any]: ...
    async def release(self, rid: str, reason: str) -> dict[str, Any]: ...
    async def unknown(self, rid: str, detail: str = "") -> dict[str, Any]: ...
    transport = "abstract"


def _checked(out: Any, kind: str) -> dict[str, Any]:
    """Refuse an answer the enforcement point does not understand (AuthZEN lets it; Valet relies on it)."""
    if not isinstance(out, dict):
        raise DecisionUnavailable(f"{kind}: not a JSON object")
    if kind == "evaluation":
        if not isinstance(out.get("decision"), bool):
            raise DecisionUnavailable("evaluation: no boolean decision")
        if out["decision"] and not isinstance((out.get("context") or {}).get("valet"), dict):
            raise DecisionUnavailable("evaluation: a permit without context.valet")
    return out


class InProcessDecisions(Decisions):
    transport = "in-process"

    def __init__(self, svc: DecisionService):
        self.svc = svc

    async def _do(self, kind: str, fn, *args) -> dict[str, Any]:
        try:
            return _checked(fn(*args), kind)
        except KeyError as e:
            raise NotFound(str(e)) from e
        except Conflict as e:
            raise DecisionConflict(str(e)) from e
        except BadRequest:
            raise
        except DecisionUnavailable:
            raise
        except Exception as e:                        # anything unexpected: fail closed
            raise DecisionUnavailable(f"{kind}: {type(e).__name__}") from e

    async def evaluate(self, req):
        return await self._do("evaluation", self.svc.evaluate, req)

    async def evaluations(self, req):
        return await self._do("evaluations", self.svc.evaluations, req)

    async def access_request(self, binding_token):
        return await self._do("access_request", self.svc.access_request, {"binding_token": binding_token})

    async def task(self, task_id):
        return await self._do("task", self.svc.task, task_id)

    async def reservation(self, rid):
        return await self._do("reservation", self.svc.reservation, rid)

    async def sent(self, rid):
        return await self._do("sent", self.svc.sent, rid)

    async def commit(self, rid, bank_payment_id):
        return await self._do("commit", self.svc.commit, rid, bank_payment_id)

    async def release(self, rid, reason):
        return await self._do("release", self.svc.release, rid, reason)

    async def unknown(self, rid, detail=""):
        return await self._do("unknown", self.svc.unknown, rid, detail)


class HttpDecisions(Decisions):
    transport = "http"

    def __init__(self, base_url: str, secret: str, timeout: float = 3.0, transport: httpx.AsyncBaseTransport | None = None):
        self.base = base_url.rstrip("/")
        self.http = httpx.AsyncClient(base_url=self.base, timeout=timeout, transport=transport,
                                      headers={"Authorization": f"Bearer {secret}"})

    async def _do(self, kind: str, method: str, path: str, json: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            r = await self.http.request(method, path, json=json)
        except httpx.HTTPError as e:
            raise DecisionUnavailable(f"{kind}: {type(e).__name__}") from e
        if r.status_code == 404:
            raise NotFound(path)
        if r.status_code == 409:
            raise DecisionConflict(r.json().get("error_description", "conflict"))
        if r.status_code == 400:
            raise BadRequest(r.json().get("error_description", "bad request"))
        if r.status_code not in (200, 202):
            raise DecisionUnavailable(f"{kind}: HTTP {r.status_code}")
        try:
            return _checked(r.json(), kind)
        except ValueError as e:
            raise DecisionUnavailable(f"{kind}: not JSON") from e

    async def evaluate(self, req):
        return await self._do("evaluation", "POST", "/access/v1/evaluation", req)

    async def evaluations(self, req):
        return await self._do("evaluations", "POST", "/access/v1/evaluations", req)

    async def access_request(self, binding_token):
        return await self._do("access_request", "POST", "/access/v1/access_requests", {"binding_token": binding_token})

    async def task(self, task_id):
        return await self._do("task", "GET", f"/access/v1/access_requests/{task_id}")

    async def reservation(self, rid):
        return await self._do("reservation", "GET", f"/valet/v1/reservations/{rid}")

    async def sent(self, rid):
        return await self._do("sent", "POST", f"/valet/v1/reservations/{rid}/sent")

    async def commit(self, rid, bank_payment_id):
        return await self._do("commit", "POST", f"/valet/v1/reservations/{rid}/commit",
                              {"bank_payment_id": bank_payment_id})

    async def release(self, rid, reason):
        return await self._do("release", "POST", f"/valet/v1/reservations/{rid}/release", {"reason": reason})

    async def unknown(self, rid, detail=""):
        return await self._do("unknown", "POST", f"/valet/v1/reservations/{rid}/unknown", {"detail": detail})


def from_env(svc: DecisionService) -> Decisions:
    """VALET_DECISION_URL set: ask Valet over HTTP (as a bank would). Unset: in-process."""
    url = os.environ.get("VALET_DECISION_URL", "").strip()
    if not url:
        return InProcessDecisions(svc)
    return HttpDecisions(url, os.environ.get("VALET_DECISION_SECRET", ""),
                         timeout=float(os.environ.get("VALET_DECISION_TIMEOUT", "3")))
