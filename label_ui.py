#!/usr/bin/env python3
"""
INTERFATA DE ETICHETARE — omul marcheaza verdictele cu adevarul (attack | benign).

Singura cale prin care ground_truth si label_source="human" ajung in
verdicts-history. Logica de etichetare sta in labeling.py; aici e doar web-ul.

Securitate, pe scurt:
  - parola din mediu (LABEL_UI_PASSWORD, minim 12 caractere), comparata in timp
    constant; limita de incercari esuate per IP
  - sesiune semnata (cookie SameSite=Strict), token CSRF pe orice POST
  - tot textul afisat (naratiuni, nume de reguli, entitati) poate veni din
    telemetrie controlata de atacator: Jinja cu autoescape fortat, fara |safe,
    CSP fara scripturi
  - interogari Query DSL cu term/filter; doc_id validat inainte de orice citire
  - scrie cu ES_WRITER_API_KEY, doar campurile de eticheta, cu control de
    concurenta (if_seq_no), deci doua etichetari simultane nu se calca

    source env.sh   # LABEL_UI_PASSWORD trebuie sa existe acolo
    python3 label_ui.py                       # 172.20.99.220:8088
    python3 label_ui.py --host 127.0.0.1      # doar local
"""

from __future__ import annotations

import argparse
import hmac
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from elasticsearch import ConflictError, Elasticsearch, NotFoundError
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from pydantic import ValidationError
from starlette.middleware.sessions import SessionMiddleware

from labeling import DOC_ID_RE, LabelInput, build_label_update, outcome

VERDICTS_IDX = "verdicts-history"
AUDIT_IDX = "soc-audit"
PAGE_SIZE = 50
MAX_PAGE = 100
MIN_PASSWORD_LEN = 12
LOGIN_MAX_FAILS = 5          # incercari esuate permise...
LOGIN_WINDOW_S = 300         # ...in fereastra asta, per IP
SESSION_MAX_AGE_S = 8 * 3600

STATUSES = ("unlabeled", "labeled", "all")
SOURCES = ("all", "fast", "hunt")

SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                "script-src 'none'; frame-ancestors 'none'; form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}


def _writer() -> Elasticsearch:
    key = os.environ.get("ES_WRITER_API_KEY")
    if not key:
        raise RuntimeError("ES_WRITER_API_KEY lipseste")
    return Elasticsearch(os.environ.get("ES_URL", "http://localhost:9200"),
                         api_key=key, request_timeout=30)


def _list_query(status: str, source: str) -> dict:
    filt: list[dict] = []
    must_not: list[dict] = []
    if status == "unlabeled":
        must_not.append({"exists": {"field": "ground_truth"}})
    elif status == "labeled":
        filt.append({"exists": {"field": "ground_truth"}})
    if source != "all":
        filt.append({"term": {"source_path.keyword": source}})
    return {"bool": {"filter": filt, "must_not": must_not}}


def create_app(password: str | None = None, es: Elasticsearch | None = None,
               session_secret: str | None = None) -> FastAPI:
    password = password if password is not None else os.environ.get("LABEL_UI_PASSWORD", "")
    if len(password) < MIN_PASSWORD_LEN:
        raise RuntimeError(f"LABEL_UI_PASSWORD lipseste sau are sub {MIN_PASSWORD_LEN} caractere")
    es = es or _writer()
    # Fara LABEL_UI_SECRET, cheia sesiunii e noua la fiecare pornire: o repornire
    # delogheaza pe toata lumea. Acceptabil pentru un singur om in laborator.
    secret = session_secret or os.environ.get("LABEL_UI_SECRET") or secrets.token_hex(32)

    env = Environment(loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
                      autoescape=True)   # fortat: tot ce afisam poate veni din telemetrie
    templates = Jinja2Templates(env=env)
    fails: dict[str, deque] = defaultdict(deque)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(SessionMiddleware, secret_key=secret, session_cookie="soc_label",
                       max_age=SESSION_MAX_AGE_S, same_site="strict", https_only=False)

    @app.middleware("http")
    async def _headers(request: Request, call_next):
        resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers[k] = v
        return resp

    def _authed(request: Request) -> bool:
        return request.session.get("auth") is True

    def _csrf_ok(request: Request, token: str) -> bool:
        expected = request.session.get("csrf") or ""
        return bool(expected) and hmac.compare_digest(expected, token or "")

    def _render(request: Request, view: str, status_code: int = 200, **ctx) -> HTMLResponse:
        ctx.update(view=view, csrf=request.session.get("csrf", ""))
        return templates.TemplateResponse(request, "label_ui.html", ctx, status_code=status_code)

    def _to_login() -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    # ---------------- autentificare ----------------

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return _render(request, "login")

    @app.post("/login")
    def login(request: Request, password_in: str = Form("", alias="password")):
        ip = request.client.host if request.client else "?"
        q = fails[ip]
        now = time.monotonic()
        while q and now - q[0] > LOGIN_WINDOW_S:
            q.popleft()
        if len(q) >= LOGIN_MAX_FAILS:
            return _render(request, "login", status_code=429,
                           error="Prea multe incercari. Reincearca peste cateva minute.")
        if not hmac.compare_digest(password_in.encode(), password.encode()):
            q.append(now)
            return _render(request, "login", status_code=401, error="Parola gresita.")
        q.clear()
        request.session.clear()
        request.session.update(auth=True, csrf=secrets.token_urlsafe(32))
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    def logout(request: Request, csrf: str = Form("")):
        if _authed(request) and _csrf_ok(request, csrf):
            request.session.clear()
        return _to_login()

    # ---------------- lista ----------------

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request, status: str = "unlabeled", source: str = "all", page: int = 0):
        if not _authed(request):
            return _to_login()
        status = status if status in STATUSES else "unlabeled"
        source = source if source in SOURCES else "all"
        page = max(0, min(page, MAX_PAGE))
        r = es.search(index=VERDICTS_IDX, size=PAGE_SIZE, from_=page * PAGE_SIZE,
                      query=_list_query(status, source), sort=[{"@timestamp": "desc"}],
                      aggs={"labeled": {"filter": {"exists": {"field": "ground_truth"}},
                                        "aggs": {"out": {"terms": {"field": "label_outcome.keyword"}}}}},
                      track_total_hits=True)
        rows = [dict(h["_source"], _id=h["_id"]) for h in r["hits"]["hits"]]
        agg = r.get("aggregations", {}).get("labeled", {})
        outcomes = {b["key"]: b["doc_count"] for b in agg.get("out", {}).get("buckets", [])}
        return _render(request, "list", rows=rows, total=r["hits"]["total"]["value"],
                       status=status, source=source, page=page, page_size=PAGE_SIZE,
                       labeled_count=agg.get("doc_count", 0), outcomes=outcomes)

    # ---------------- detaliu + etichetare ----------------

    def _load(doc_id: str):
        if not DOC_ID_RE.match(doc_id):
            return None
        try:
            return es.get(index=VERDICTS_IDX, id=doc_id)
        except NotFoundError:
            return None

    def _audit_for(src: dict) -> dict | None:
        inv = src.get("investigation_id")
        if not inv:
            return None
        r = es.search(index=AUDIT_IDX, size=1, sort=[{"@timestamp": "desc"}],
                      query={"bool": {"filter": [{"term": {"investigation_id.keyword": inv}}]}})
        hits = r["hits"]["hits"]
        return hits[0]["_source"] if hits else None

    @app.get("/v/{doc_id}", response_class=HTMLResponse)
    def detail(request: Request, doc_id: str, error: str | None = None):
        if not _authed(request):
            return _to_login()
        doc = _load(doc_id)
        if doc is None:
            return _render(request, "notfound", status_code=404)
        src = doc["_source"]
        return _render(request, "detail", doc_id=doc_id, v=src, audit=_audit_for(src),
                       if_attack=outcome(src, "attack"), if_benign=outcome(src, "benign"),
                       error=error)

    @app.post("/v/{doc_id}/label")
    def label(request: Request, doc_id: str, ground_truth: str = Form(""),
              notes: str = Form(""), csrf: str = Form(""), source: str = Form("all")):
        if not _authed(request):
            return _to_login()
        if not _csrf_ok(request, csrf):
            return Response("CSRF invalid", status_code=403)
        try:
            lab = LabelInput(doc_id=doc_id, ground_truth=ground_truth, notes=notes)
        except ValidationError:
            return Response("Eticheta invalida", status_code=400)
        doc = _load(lab.doc_id)
        if doc is None:
            return _render(request, "notfound", status_code=404)
        fields = build_label_update(doc["_source"], lab, datetime.now(timezone.utc))
        try:
            es.update(index=VERDICTS_IDX, id=lab.doc_id, doc=fields,
                      if_seq_no=doc["_seq_no"], if_primary_term=doc["_primary_term"])
        except ConflictError:
            return RedirectResponse(f"/v/{lab.doc_id}?error=conflict", status_code=303)
        # Urmatorul neetichetat din aceeasi sursa, ca omul sa lucreze in sir.
        source = source if source in SOURCES else "all"
        nxt = es.search(index=VERDICTS_IDX, size=1, sort=[{"@timestamp": "desc"}],
                        query=_list_query("unlabeled", source))["hits"]["hits"]
        return RedirectResponse(f"/v/{nxt[0]['_id']}" if nxt else "/", status_code=303)

    return app


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="172.20.99.220")
    ap.add_argument("--port", type=int, default=8088)
    args = ap.parse_args()
    import uvicorn
    uvicorn.run(create_app(), host=args.host, port=args.port,
                server_header=False, proxy_headers=False, access_log=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
