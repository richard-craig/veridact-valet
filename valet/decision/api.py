"""
The decision service over HTTP: AuthZEN Authorization API 1.0, the Access Request and Approval Profile, and the
Valet reservation extension (docs/decision-service.md).

Only the bank's own enforcement points may call it. The PoC authenticates them with a shared bearer secret
(VALET_DECISION_SECRET); a bank uses mTLS or private_key_jwt on its internal network. With no secret set, the HTTP
interface is off and the bank's servers use the service in-process.
"""
from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .service import BadRequest, Conflict, DecisionService


def router(svc: DecisionService, secret: str) -> APIRouter:
    r = APIRouter(tags=["Valet decision service"])

    def authorised(request: Request) -> JSONResponse | None:
        if not secret:
            return JSONResponse({"error": "not_found", "error_description": "the decision service's HTTP interface is "
                                 "off (set VALET_DECISION_SECRET)"}, status_code=404)
        if not secrets.compare_digest(request.headers.get("Authorization", ""), f"Bearer {secret}"):
            return JSONResponse({"error": "invalid_client", "error_description": "only the bank's enforcement points "
                                 "may ask for decisions"}, status_code=401,
                                headers={"WWW-Authenticate": 'Bearer realm="valet-decision"'})
        return None

    async def body(request: Request) -> dict[str, Any]:
        try:
            data = await request.json()
        except ValueError:
            raise BadRequest("the body is not JSON")
        if not isinstance(data, dict):
            raise BadRequest("the body must be a JSON object")
        return data

    def bad(e: Exception) -> JSONResponse:
        return JSONResponse({"error": "invalid_request", "error_description": str(e)}, status_code=400)

    def call(fn, *args) -> JSONResponse:
        try:
            return JSONResponse(fn(*args))
        except BadRequest as e:
            return JSONResponse({"error": "invalid_request", "error_description": str(e)}, status_code=400)
        except KeyError:
            return JSONResponse({"error": "not_found"}, status_code=404)
        except Conflict as e:
            return JSONResponse({"error": "conflict", "error_description": str(e)}, status_code=409)

    @r.get("/.well-known/authzen-configuration")
    def configuration():
        """AuthZEN PDP metadata. Public, like any well-known document; the endpoints it names are not."""
        return svc.metadata()

    async def with_body(request: Request, fn):
        denied = authorised(request)
        if denied:
            return denied
        try:
            b = await body(request)
        except BadRequest as e:
            return bad(e)
        return call(fn, b)

    @r.post("/access/v1/evaluation")
    async def evaluation(request: Request):
        return await with_body(request, svc.evaluate)

    @r.post("/access/v1/evaluations")
    async def evaluations(request: Request):
        return await with_body(request, svc.evaluations)

    @r.post("/access/v1/access_requests", status_code=202)
    async def access_request(request: Request):
        resp = await with_body(request, svc.access_request)
        if resp.status_code == 200:
            resp.status_code = 202
        return resp

    @r.get("/access/v1/access_requests/{task_id}")
    def task(request: Request, task_id: str):
        return authorised(request) or call(svc.task, task_id)

    @r.get("/valet/v1/reservations/{rid}")
    def reservation(request: Request, rid: str):
        return authorised(request) or call(svc.reservation, rid)

    @r.post("/valet/v1/reservations/{rid}/sent")
    def sent(request: Request, rid: str):
        return authorised(request) or call(svc.sent, rid)

    @r.post("/valet/v1/reservations/{rid}/commit")
    async def commit(request: Request, rid: str):
        denied = authorised(request)
        if denied:
            return denied
        try:
            b = await body(request)
        except BadRequest as e:
            return bad(e)
        if not b.get("bank_payment_id"):
            return JSONResponse({"error": "invalid_request", "error_description": "bank_payment_id is required"},
                                status_code=400)
        return call(svc.commit, rid, str(b["bank_payment_id"]))

    @r.post("/valet/v1/reservations/{rid}/release")
    async def release(request: Request, rid: str):
        denied = authorised(request)
        if denied:
            return denied
        try:
            b = await body(request)
        except BadRequest as e:
            return bad(e)
        return call(svc.release, rid, str(b.get("reason") or "declined"))

    @r.post("/valet/v1/reservations/{rid}/unknown")
    async def unknown(request: Request, rid: str):
        denied = authorised(request)
        if denied:
            return denied
        try:
            b = await body(request)
        except BadRequest:
            b = {}
        return call(svc.unknown, rid, str(b.get("detail") or ""))

    return r
