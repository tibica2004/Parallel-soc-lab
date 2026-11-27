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

Faza 24 (decizia invatata): etichetarea pe GRUP (soc-buckets), unul cate unul sau in bloc, dintr-o
coada ordonata de cod (incertitudine x volum); verdictul sistemului e ascuns pana cand omul curent a
votat. Mai multi oameni: LABEL_UI_USERS="nume:sare:hash,..." (pbkdf2-sha256, generat cu
--hash-parola); fiecare vot poarta numele din sesiune, consensul e votul majoritar. Fara
LABEL_UI_USERS ramane parola unica (utilizatorul "operator"). API JSON autentificat cu token
(LABEL_UI_API_TOKENS="nume:sha256(token),..."): POST /api/feedback, POST /api/train,
GET /api/decision/{bucket_id}. Votul pe grup NU pune ground_truth pe alertele din grup (L2).

    source env.sh   # LABEL_UI_PASSWORD trebuie sa existe acolo
    python3 label_ui.py                       # LABEL_UI_HOST:8088 (es-node-1)
    python3 label_ui.py --host 127.0.0.1      # doar local
    python3 label_ui.py --hash-parola NUME    # intrarea pentru LABEL_UI_USERS (parola citita ascuns)
    python3 label_ui.py --token-nou NUME      # token API nou (afisat o singura data) + intrarea lui
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import re
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from elasticsearch import ConflictError, Elasticsearch, NotFoundError
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from jinja2 import Environment, FileSystemLoader
from pydantic import ValidationError
from starlette.middleware.sessions import SessionMiddleware

from elasticlab.store import cases as C
from elasticlab.eval.labeling import (DOC_ID_RE, BucketLabelInput, LabelInput, USER_RE,
                                     build_bucket_vote, build_label_update, outcome)
from elasticlab.paths import REPO_ROOT
from elasticlab.store import buckets as BK
from elasticlab.store import writer as W

VERDICTS_IDX = "verdicts-history"
AUDIT_IDX = "soc-audit"
TRACES_IDX = "soc-traces"
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


PBKDF2_ITER = 200_000
LEGACY_USER = "operator"


def hash_password(password: str, salt: bytes | None = None) -> str:
    """`sare:hash` (hex) pentru LABEL_UI_USERS. pbkdf2-sha256, 200k iteratii."""
    salt = salt or secrets.token_bytes(16)
    return salt.hex() + ":" + hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITER).hex()


def check_password(password: str, entry: str) -> bool:
    try:
        salt_hex, h = entry.split(":", 1)
        got = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), PBKDF2_ITER).hex()
    except ValueError:
        return False
    return hmac.compare_digest(got, h)


def parse_users(raw: str | None) -> dict[str, str]:
    """LABEL_UI_USERS="nume:sare:hash,..." -> {nume: "sare:hash"}. Intrarile invalide se ignora."""
    out: dict[str, str] = {}
    for part in (raw or "").split(","):
        bits = part.strip().split(":")
        if len(bits) == 3 and USER_RE.match(bits[0]):
            out[bits[0]] = f"{bits[1]}:{bits[2]}"
    return out


def parse_tokens(raw: str | None) -> dict[str, str]:
    """LABEL_UI_API_TOKENS="nume:sha256hex,..." -> {sha256hex: nume}. Tokenul in clar nu se tine."""
    out: dict[str, str] = {}
    for part in (raw or "").split(","):
        bits = part.strip().split(":")
        if len(bits) == 2 and USER_RE.match(bits[0]) and re.fullmatch(r"[0-9a-f]{64}", bits[1]):
            out[bits[1]] = bits[0]
    return out


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
               session_secret: str | None = None, users: dict[str, str] | None = None,
               learning_es=None, api_tokens: dict[str, str] | None = None,
               on_attack_label=None, train=None) -> FastAPI:
    users = users if users is not None else parse_users(os.environ.get("LABEL_UI_USERS"))
    api_tokens = api_tokens if api_tokens is not None else parse_tokens(os.environ.get("LABEL_UI_API_TOKENS"))
    password = password if password is not None else os.environ.get("LABEL_UI_PASSWORD", "")
    if not users and len(password) < MIN_PASSWORD_LEN:
        raise RuntimeError(f"LABEL_UI_PASSWORD lipseste sau are sub {MIN_PASSWORD_LEN} caractere")
    es = es or _writer()
    # Grupurile (soc-buckets): cheia de invatare; fara ea, paginile de grupuri arata ca lipsesc.
    les = learning_es if learning_es is not None else (W.learning_client() or es)
    if on_attack_label is None:
        def on_attack_label(pipeline, doc, label):
            from elasticlab.tier3 import learning
            return learning.on_human_label(pipeline, doc, label)
    if train is None:
        def train(pipeline):
            from elasticlab.tier3 import learning
            return learning.run(write=True, train=True, only=pipeline)
    # Fara LABEL_UI_SECRET, cheia sesiunii e noua la fiecare pornire: o repornire
    # delogheaza pe toata lumea. Acceptabil pentru un singur om in laborator.
    secret = session_secret or os.environ.get("LABEL_UI_SECRET") or secrets.token_hex(32)

    env = Environment(loader=FileSystemLoader(str(REPO_ROOT / "templates")),
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
        ctx.update(view=view, csrf=request.session.get("csrf", ""), user=request.session.get("user"))
        return templates.TemplateResponse(request, "label_ui.html", ctx, status_code=status_code)

    def _to_login() -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    # ---------------- autentificare ----------------

    @app.get("/login", response_class=HTMLResponse)
    def login_form(request: Request):
        return _render(request, "login", multi=bool(users))

    def _throttled(request: Request) -> bool:
        ip = request.client.host if request.client else "?"
        q = fails[ip]
        now = time.monotonic()
        while q and now - q[0] > LOGIN_WINDOW_S:
            q.popleft()
        return len(q) >= LOGIN_MAX_FAILS

    def _fail(request: Request) -> None:
        fails[request.client.host if request.client else "?"].append(time.monotonic())

    @app.post("/login")
    def login(request: Request, password_in: str = Form("", alias="password"),
              username: str = Form("")):
        if _throttled(request):
            return _render(request, "login", status_code=429, multi=bool(users),
                           error="Prea multe incercari. Reincearca peste cateva minute.")
        if users:
            entry = users.get(username.strip())
            ok = entry is not None and check_password(password_in, entry)
            who = username.strip()
        else:
            ok = hmac.compare_digest(password_in.encode(), password.encode())
            who = LEGACY_USER
        if not ok:
            _fail(request)
            return _render(request, "login", status_code=401, multi=bool(users),
                           error="Utilizator sau parola gresita." if users else "Parola gresita.")
        fails[request.client.host if request.client else "?"].clear()
        request.session.clear()
        request.session.update(auth=True, user=who, csrf=secrets.token_urlsafe(32))
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
                      # global: contorul de etichete nu depinde de filtrul listei
                      aggs={"g": {"global": {}, "aggs": {"labeled": {
                          "filter": {"exists": {"field": "ground_truth"}},
                          "aggs": {"out": {"terms": {"field": "label_outcome.keyword"}}}}}}},
                      track_total_hits=True)
        rows = [dict(h["_source"], _id=h["_id"]) for h in r["hits"]["hits"]]
        agg = r.get("aggregations", {}).get("g", {}).get("labeled", {})
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

    def _trace_for(src: dict) -> dict | None:
        inv = src.get("investigation_id")
        if not inv:
            return None
        try:
            r = es.search(index=TRACES_IDX, size=1, sort=[{"@timestamp": "desc"}],
                          query={"bool": {"filter": [{"term": {"investigation_id.keyword": inv}}]}})
        except Exception:
            return None   # indexul lipseste sau cheia n-are drept: pagina merge si fara urma
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
                       trace=_trace_for(src),
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
            W.update_verdict_label(es, lab.doc_id, fields, seq_no=doc["_seq_no"],
                                   primary_term=doc["_primary_term"])
        except ConflictError:
            return RedirectResponse(f"/v/{lab.doc_id}?error=conflict", status_code=303)
        # Urmatorul neetichetat din aceeasi sursa, ca omul sa lucreze in sir.
        source = source if source in SOURCES else "all"
        nxt = es.search(index=VERDICTS_IDX, size=1, sort=[{"@timestamp": "desc"}],
                        query=_list_query("unlabeled", source))["hits"]["hits"]
        return RedirectResponse(f"/v/{nxt[0]['_id']}" if nxt else "/", status_code=303)

    # ---------------- cazuri (plann.md A1): coada omului; inchiderea doar de aici ----------------

    def _cases_es():
        return C.client() or es

    @app.get("/cases", response_class=HTMLResponse)
    def case_list(request: Request, state: str = "escalated"):
        if not _authed(request):
            return _to_login()
        state = state if state in {s.value for s in C.CaseState} | {"all"} else "escalated"
        q = {"match_all": {}} if state == "all" else {"term": {"state": state}}
        try:
            r = _cases_es().search(index=C.INDEX, size=PAGE_SIZE, query=q,
                                   sort=[{"updated_at": "desc"}], track_total_hits=True)
        except Exception:
            return _render(request, "cases", rows=[], total=0, state=state, error="indexul soc-cases lipseste")
        rows = [dict(h["_source"], _id=h["_id"]) for h in r["hits"]["hits"]]
        return _render(request, "cases", rows=rows, total=r["hits"]["total"]["value"], state=state,
                       reasons=[x.value for x in C.CloseReason], error=None)

    @app.post("/cases/{case_id}/close")
    def case_close(request: Request, case_id: str, reason: str = Form(""), notes: str = Form(""),
                   csrf: str = Form("")):
        if not _authed(request):
            return _to_login()
        if not _csrf_ok(request, csrf):
            return Response("CSRF invalid", status_code=403)
        if not re.match(C.CHAIN_ID_RE, case_id):
            return Response("caz invalid", status_code=400)
        try:
            why = C.CloseReason(reason)
        except ValueError:
            return Response("motiv invalid", status_code=400)
        ces = _cases_es()
        rec = C.load(ces, case_id)
        if rec is None:
            return _render(request, "notfound", status_code=404)
        C.save(ces, C.close_by_human(rec, why, notes, datetime.now(timezone.utc)))
        return RedirectResponse("/cases", status_code=303)

    # ---------------- faza 24: grupuri (soc-buckets) ----------------

    def _user(request: Request) -> str:
        return request.session.get("user") or LEGACY_USER

    def _vote(user: str, lab: BucketLabelInput) -> tuple[list[str], list[str]]:
        """Votul unui om autentificat pe grupuri. Intoarce (votate, negasite)."""
        now = datetime.now(timezone.utc)
        done, missing = [], []
        for bid in lab.bucket_ids:
            doc = W.add_bucket_vote(les, bid, build_bucket_vote(user, lab.label, lab.notes, now))
            if doc is None:
                missing.append(bid)
                continue
            done.append(bid)
            if lab.label == "attack":
                try:   # retrogradarea imediata: attack pe un grup inchis de cascada
                    on_attack_label(doc.get("pipeline"), doc, "attack")
                except Exception:  # noqa: BLE001 — votul e scris; controlorul il prinde si la ora
                    pass
        return done, missing

    @app.get("/buckets", response_class=HTMLResponse)
    def bucket_queue(request: Request, pipeline: str = ""):
        if not _authed(request):
            return _to_login()
        pipeline = pipeline if re.fullmatch(r"[a-z][a-z0-9_]{0,39}", pipeline or "") else ""
        try:
            rows = BK.queue(les, pipeline or None)
        except Exception:
            return _render(request, "buckets", rows=[], pipeline=pipeline, error="indexul soc-buckets lipseste")
        return _render(request, "buckets", rows=rows, pipeline=pipeline, error=None)

    @app.get("/b/{bucket_id}", response_class=HTMLResponse)
    def bucket_detail(request: Request, bucket_id: str):
        if not _authed(request):
            return _to_login()
        doc = BK.load(les, bucket_id) if BK.valid_id(bucket_id) else None
        if doc is None:
            return _render(request, "notfound", status_code=404)
        voted = BK.user_voted(doc, _user(request))
        return _render(request, "bucket", b=doc, voted=voted,
                       # verdictul sistemului si voturile celorlalti: ascunse pana la votul omului curent
                       system=doc.get("system") if voted else None,
                       votes=doc.get("votes") if voted else None)

    def _next_in_queue(after: str) -> str:
        try:
            rows = [r for r in BK.queue(les, None, size=5) if r.get("bucket_id") != after]
        except Exception:
            rows = []
        return f"/b/{rows[0]['bucket_id']}" if rows else "/buckets"

    @app.post("/b/{bucket_id}/label")
    def bucket_label(request: Request, bucket_id: str, label: str = Form(""), notes: str = Form(""),
                     csrf: str = Form("")):
        if not _authed(request):
            return _to_login()
        if not _csrf_ok(request, csrf):
            return Response("CSRF invalid", status_code=403)
        try:
            lab = BucketLabelInput(bucket_ids=[bucket_id], label=label, notes=notes)
        except ValidationError:
            return Response("Eticheta invalida", status_code=400)
        done, _missing = _vote(_user(request), lab)
        if not done:
            return _render(request, "notfound", status_code=404)
        return RedirectResponse(_next_in_queue(bucket_id), status_code=303)

    @app.post("/buckets/label")
    async def bucket_bulk(request: Request):
        if not _authed(request):
            return _to_login()
        form = await request.form()
        if not _csrf_ok(request, str(form.get("csrf") or "")):
            return Response("CSRF invalid", status_code=403)
        try:
            lab = BucketLabelInput(bucket_ids=[str(x) for x in form.getlist("bucket_ids")],
                                   label=str(form.get("label") or ""), notes=str(form.get("notes") or ""))
        except ValidationError:
            return Response("Eticheta invalida", status_code=400)
        _vote(_user(request), lab)
        return RedirectResponse("/buckets", status_code=303)

    # ---------------- API JSON (token; fara cookie, deci fara CSRF) ----------------

    def _api_user(request: Request) -> str | None:
        auth = request.headers.get("authorization") or ""
        if not auth.lower().startswith("bearer ") or _throttled(request):
            return None
        tok = auth[7:].strip()
        user = api_tokens.get(hashlib.sha256(tok.encode()).hexdigest()) if tok else None
        if user is None:
            _fail(request)
        return user

    def _denied() -> JSONResponse:
        return JSONResponse({"error": "neautentificat"}, status_code=401)

    @app.post("/api/feedback")
    async def api_feedback(request: Request):
        user = _api_user(request)
        if user is None:
            return _denied()
        try:
            body = await request.json()
            lab = BucketLabelInput.model_validate(body if isinstance(body, dict) else {})
        except Exception:
            return JSONResponse({"error": "cerere invalida"}, status_code=400)
        done, missing = _vote(user, lab)
        return JSONResponse({"voted": done, "missing": missing, "user": user})

    @app.post("/api/train")
    async def api_train(request: Request):
        user = _api_user(request)
        if user is None:
            return _denied()
        try:
            body = await request.json()
        except Exception:
            body = {}
        pid = (body or {}).get("pipeline") if isinstance(body, dict) else None
        if pid is not None and not re.fullmatch(r"[a-z][a-z0-9_]{0,39}", str(pid)):
            return JSONResponse({"error": "pipeline invalid"}, status_code=400)
        try:
            rep = train(pid)
        except Exception as e:
            return JSONResponse({"error": f"antrenare esuata: {type(e).__name__}"}, status_code=500)
        return JSONResponse({"requested_by": user, "report": rep}, status_code=200)

    @app.get("/api/decision/{bucket_id}")
    def api_decision(request: Request, bucket_id: str):
        if _api_user(request) is None:
            return _denied()
        doc = BK.load(les, bucket_id) if BK.valid_id(bucket_id) else None
        if doc is None:
            return JSONResponse({"error": "grup inexistent"}, status_code=404)
        return JSONResponse({k: doc.get(k) for k in (
            "bucket_id", "pipeline", "dp_version", "values", "count", "first_seen", "last_seen",
            "consensus", "votes_attack", "votes_benign", "system", "cascade_closed", "control_samples")})

    return app


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=os.environ.get("LABEL_UI_HOST", "192.168.10.121"))
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--hash-parola", metavar="NUME", help="intrarea LABEL_UI_USERS pentru NUME")
    ap.add_argument("--token-nou", metavar="NUME", help="token API nou pentru NUME")
    args = ap.parse_args()
    if args.hash_parola or args.token_nou:
        name = args.hash_parola or args.token_nou
        if not USER_RE.match(name):
            print("nume invalid (litere mici, cifre, . _ -)")
            return 1
        if args.hash_parola:
            import getpass
            pw = getpass.getpass("parola: ")
            if len(pw) < MIN_PASSWORD_LEN or pw != getpass.getpass("din nou: "):
                print(f"parolele difera sau au sub {MIN_PASSWORD_LEN} caractere")
                return 1
            print(f"{name}:{hash_password(pw)}")
            return 0
        tok = secrets.token_urlsafe(32)
        # Tokenul se afiseaza O SINGURA DATA, omului care l-a cerut; in soc.env intra doar hash-ul.
        print(f"token (pastreaza-l, nu se mai afiseaza): {tok}")
        print(f"intrare LABEL_UI_API_TOKENS: {name}:{hashlib.sha256(tok.encode()).hexdigest()}")
        return 0
    import uvicorn
    uvicorn.run(create_app(), host=args.host, port=args.port,
                server_header=False, proxy_headers=False, access_log=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
