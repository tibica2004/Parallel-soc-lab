#!/usr/bin/env python3
"""
TRAFIC BENIGN (pasul 4) — un utilizator WordPress normal, cu adevar cunoscut, ca sa masuram
rata de fals pozitive a fiecarei reguli (fp_rate.py). Ruleaza pe VM-ul benign-gen
(192.168.10.150), NU pe es-node-1 (A9: traficul SOC-ului nu se amesteca cu cel benign).

Fiecare actiune scrie INAINTE de cerere un document in benign-ground-truth (phase=start), apoi
unul cu rezultatul (phase=end, http_status, duration_ms). Daca scrierea "start" esueaza, actiunea
NU se face: trafic fara adevar inregistrat ar parea atac in masuratoare.

Doar trafic normal (R1): GET-uri publice, login/logout real in browser (Playwright), articole si
imagini ale propriului cont prin REST API-ul pe care il foloseste si editorul Gutenberg (cookie +
nonce din wp-admin), wp-cron. Fara parametri suspecti, fara user-agent de scanner, fara cai cu
caractere speciale (verificat de safe_path inainte de fiecare cerere). Marcaj: antetul
X-SOC-Benign: <run_id> si "soc-benign/1.0" in User-Agent.

Mediu (/etc/soc-benign/benign.env, 600): BENIGN_BASE_URL, BENIGN_WP_USER, BENIGN_WP_PASSWORD,
ES_URL, ES_BENIGN_WRITER_API_KEY, BENIGN_SRC_IP. Optional: BENIGN_ONCE=1 (o sesiune si iesire).
"""
from __future__ import annotations

import io
import json
import logging
import os
import random
import re
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s",
                    stream=sys.stderr)
log = logging.getLogger("soc.benign")

INDEX = "benign-ground-truth"
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/124.0 Safari/537.36 soc-benign/1.0")
MAX_REQUESTS = 30
DAY_START, DAY_END = 8, 20                 # ora locala (TZ din unitatea systemd)
DAY_DELAY_MIN = (2, 6)
NIGHT_DELAY_MIN = (15, 40)
EDITOR_SESSION_P = 0.5                     # jumatate din sesiuni intra si in wp-admin
SEARCH_WORDS = ("test", "wordpress", "despre", "contact", "noutati")

# Caile permise: litere mici, cifre, / . - _ ; interogari doar cheie=valoare alfanumerice.
# Valorile pot contine "/" (rest_route=/wp/v2/posts), dar nu "//" si nu "..".
_SAFE_PATH = re.compile(r"^/[a-z0-9/._\-]*(\?[a-z_]+=[a-zA-Z0-9_/]*(&[a-z_]+=[a-zA-Z0-9_/]*)*)?$")


def rest(route: str, **params) -> str:
    """Cale REST fara permalink-uri (web-prod are permalink-uri "plain": /wp-json/ da 404)."""
    q = "".join(f"&{k}={v}" for k, v in params.items())
    return f"/?rest_route={route}{q}"


class Action:
    BROWSE = "browse_public"
    LOGIN = "login_editor"
    CREATE_POST = "create_post"
    EDIT_POST = "edit_post"
    UPLOAD_MEDIA = "upload_media"
    CRON = "trigger_cron"
    LOGOUT = "logout"


# =============================================================================
# FUNCTII PURE (tests/test_benign_gen.py)
# =============================================================================

def safe_path(path: str) -> bool:
    return bool(_SAFE_PATH.match(path)) and ".." not in path and "//" not in path


def is_day(hour: int) -> bool:
    return DAY_START <= hour < DAY_END


def next_delay_s(hour: int, rnd: random.Random) -> float:
    lo, hi = DAY_DELAY_MIN if is_day(hour) else NIGHT_DELAY_MIN
    return rnd.uniform(lo * 60, hi * 60)


def plan_session(rnd: random.Random) -> list[str]:
    """Ordinea actiunilor dintr-o sesiune. Mereu navigare publica; uneori si editorul."""
    plan = [Action.BROWSE]
    if rnd.random() < EDITOR_SESSION_P:
        work = rnd.choice([Action.CREATE_POST, Action.EDIT_POST, Action.UPLOAD_MEDIA])
        plan += [Action.LOGIN, work, Action.LOGOUT]
    if rnd.random() < 0.3:
        plan.append(Action.CRON)
    return plan


def gt_doc(*, run_id: str, action_id: str, action: str, target: str, src_ip: str,
           phase: str, http_status: int | None = None, duration_ms: int | None = None,
           error: str | None = None) -> dict:
    if phase not in ("start", "end"):
        raise ValueError("phase")
    return {"@timestamp": datetime.now(timezone.utc).isoformat(), "run_id": run_id,
            "action_id": action_id, "action": action, "target": target[:300],
            "expected_alert": False, "src_ip": src_ip, "phase": phase,
            "http_status": http_status, "duration_ms": duration_ms,
            "error": (error or "")[:300] or None, "source": "benign_gen"}


def png_bytes(rnd: random.Random, size: int = 160) -> bytes:
    """Imagine PNG generata local (nu descarcata), cateva zeci de KB."""
    from PIL import Image
    img = Image.effect_noise((size, size), rnd.uniform(20, 80)).convert("RGB")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# =============================================================================
# EFECTE
# =============================================================================

@dataclass
class Cfg:
    base: str
    user: str
    password: str
    es_url: str
    es_key: str
    src_ip: str
    admin_base: str = ""      # login + editor (HTTPS, pasul 10); gol = base

    @classmethod
    def from_env(cls) -> "Cfg":
        miss = [k for k in ("BENIGN_BASE_URL", "BENIGN_WP_USER", "BENIGN_WP_PASSWORD", "ES_URL",
                            "ES_BENIGN_WRITER_API_KEY", "BENIGN_SRC_IP") if not os.environ.get(k)]
        if miss:
            raise RuntimeError(f"lipsesc: {', '.join(miss)}")
        e = os.environ
        base = e["BENIGN_BASE_URL"].rstrip("/")
        return cls(base, e["BENIGN_WP_USER"], e["BENIGN_WP_PASSWORD"],
                   e["ES_URL"].rstrip("/"), e["ES_BENIGN_WRITER_API_KEY"], e["BENIGN_SRC_IP"],
                   (e.get("BENIGN_ADMIN_URL") or base).rstrip("/"))


class Session:
    def __init__(self, cfg: Cfg, rnd: random.Random):
        import requests
        self.cfg, self.rnd = cfg, rnd
        self.run_id = str(uuid.uuid4())
        self.http = requests.Session()
        self.http.headers.update({"User-Agent": UA, "X-SOC-Benign": self.run_id})
        self.es = requests.Session()
        self.es.headers.update({"Authorization": f"ApiKey {cfg.es_key}",
                                "Content-Type": "application/json"})
        self.requests_done = 0
        self.page = None        # Playwright, doar in sesiunile de editor
        self.nonce = None
        self.browser = None
        self._last_json = None
        self.errors = 0

    # --- adevarul inregistrat ---------------------------------------------------
    def _gt(self, doc: dict) -> None:
        r = self.es.post(f"{self.cfg.es_url}/{INDEX}/_doc", data=json.dumps(doc), timeout=10)
        r.raise_for_status()

    def act(self, action: str, target: str, fn, base: str | None = None) -> int | None:
        """start in ES -> cerere -> end in ES. Fara start inregistrat, nu se face cererea."""
        if self.requests_done >= MAX_REQUESTS:
            return None
        if not safe_path(target):
            raise ValueError(f"cale nepermisa: {target!r}")
        aid = str(uuid.uuid4())
        common = dict(run_id=self.run_id, action_id=aid, action=action, target=target,
                      src_ip=self.cfg.src_ip)
        self._gt(gt_doc(phase="start", **common))
        t0 = time.monotonic()
        status, err = None, None
        try:
            status = fn((base or self.cfg.base) + target)
        except Exception as e:  # noqa: BLE001 — eroarea se inregistreaza, sesiunea continua
            err = f"{type(e).__name__}: {e}"
            self.errors += 1
        self.requests_done += 1
        dur = int((time.monotonic() - t0) * 1000)
        if status is not None and status >= 500:
            log.warning("%s %s -> %s", action, target, status)
        self._gt(gt_doc(phase="end", http_status=status, duration_ms=dur, error=err, **common))
        return status

    def _get(self, url: str) -> int:
        return self.http.get(url, timeout=30).status_code

    # --- actiuni ---------------------------------------------------------------
    def browse_public(self) -> None:
        self.act(Action.BROWSE, "/", self._get)
        self.act(Action.BROWSE, f"/?s={self.rnd.choice(SEARCH_WORDS)}", self._get)
        ids: list[int] = []

        def posts(url: str) -> int:
            r = self.http.get(url, timeout=30)
            if r.ok:
                ids.extend(int(p["id"]) for p in r.json() if isinstance(p.get("id"), int))
            return r.status_code
        self.act(Action.BROWSE, rest("/wp/v2/posts", per_page=10), posts)
        for pid in self.rnd.sample(ids, min(3, len(ids))):
            self.act(Action.BROWSE, f"/?p={pid}", self._get)
        self.act(Action.BROWSE, "/?feed=rss2", self._get)
        self.act(Action.BROWSE, "/wp-login.php", self._get)

    def login(self, pw) -> None:
        def do(url: str) -> int:
            self.browser = pw.chromium.launch()
            # certificatul web-prod e self-signed (laborator): acceptat doar in sesiunea de editor
            ctx = self.browser.new_context(user_agent=UA, ignore_https_errors=True,
                                           extra_http_headers={"X-SOC-Benign": self.run_id})
            self.page = ctx.new_page()
            self.page.goto(url, timeout=30000)
            self.page.fill("#user_login", self.cfg.user)
            self.page.fill("#user_pass", self.cfg.password)
            with self.page.expect_navigation(timeout=30000):
                self.page.click("#wp-submit")
            resp = self.page.goto(self.cfg.admin_base + "/wp-admin/post-new.php", timeout=60000)
            self.nonce = self.page.evaluate("() => window.wpApiSettings && wpApiSettings.nonce")
            if not self.nonce:
                raise RuntimeError("login esuat sau nonce REST lipsa")
            return resp.status if resp else 0
        self.act(Action.LOGIN, "/wp-login.php", do, base=self.cfg.admin_base)

    def _rest(self, method: str, url: str, **kw) -> int:
        """Ca Gutenberg: REST cu cookie-ul sesiunii si X-WP-Nonce."""
        headers = {"X-WP-Nonce": self.nonce, **kw.pop("headers", {})}
        r = self.page.request.fetch(url, method=method, headers=headers, timeout=60000, **kw)
        self._last_json = r.json() if r.ok else None
        return r.status

    def create_post(self) -> None:
        n = self.rnd.randint(1, 9999)
        body = {"title": f"Nota de lucru {n}", "status": "publish",
                "content": f"<p>Paragraf de test benign numarul {n}.</p>"}
        self.act(Action.CREATE_POST, rest("/wp/v2/posts"),
                 lambda u: self._rest("POST", u, data=body), base=self.cfg.admin_base)

    def edit_post(self) -> None:
        code = self.act(Action.EDIT_POST, rest("/wp/v2/users/me"), lambda u: self._rest("GET", u),
                        base=self.cfg.admin_base)
        me = self._last_json if code == 200 else None
        if not isinstance(me, dict) or not isinstance(me.get("id"), int):
            return None
        code = self.act(Action.EDIT_POST, rest("/wp/v2/posts", author=me["id"], per_page=5, context="edit"),
                        lambda u: self._rest("GET", u), base=self.cfg.admin_base)
        mine = self._last_json if code == 200 else None
        if not mine:
            return self.create_post()
        pid = int(mine[0]["id"])
        body = {"content": f"<p>Actualizat {datetime.now(timezone.utc):%Y-%m-%d %H:%M}.</p>"}
        self.act(Action.EDIT_POST, rest(f"/wp/v2/posts/{pid}"),
                 lambda u: self._rest("POST", u, data=body), base=self.cfg.admin_base)

    def upload_media(self) -> None:
        name = f"soc-benign-{self.rnd.randint(1, 99999)}.png"
        data = png_bytes(self.rnd)
        self.act(Action.UPLOAD_MEDIA, rest("/wp/v2/media"), lambda u: self._rest(
            "POST", u, data=data, headers={"Content-Type": "image/png",
                                           "Content-Disposition": f'attachment; filename="{name}"'}),
                 base=self.cfg.admin_base)

    def trigger_cron(self) -> None:
        self.act(Action.CRON, "/wp-cron.php?doing_wp_cron=", self._get)

    def logout(self) -> None:
        def do(url: str) -> int:
            # linkul de logout (cu nonce) e in meniul ascuns al barei de admin: il urmam direct
            self.page.goto(self.cfg.admin_base + "/wp-admin/", timeout=30000)
            href = self.page.get_attribute("#wp-admin-bar-logout a", "href", timeout=15000)
            if not href or not href.startswith(self.cfg.admin_base + "/wp-login.php?action=logout"):
                raise RuntimeError("link de logout neasteptat")
            resp = self.page.goto(href, timeout=30000)
            return resp.status if resp else 0
        try:
            self.act(Action.LOGOUT, "/wp-login.php?action=logout", do, base=self.cfg.admin_base)
        finally:
            if self.page is not None:
                self.browser.close()
                self.page = None

    def run(self, plan: list[str]) -> None:
        log.info("sesiune %s: %s", self.run_id, plan)
        needs_browser = Action.LOGIN in plan
        if not needs_browser:
            for a in plan:
                getattr(self, a)()
            return
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            for a in plan:
                if a == Action.LOGIN:
                    self.login(pw)
                    if not self.nonce:
                        log.warning("login esuat, sar peste actiunile de editor")
                        break
                elif a == Action.LOGOUT:
                    self.logout()
                else:
                    getattr(self, a)()
            if self.page is not None:
                self.browser.close()


def main() -> int:
    try:
        cfg = Cfg.from_env()
    except Exception as e:  # noqa: BLE001
        log.error("configuratie: %s", e)
        return 1
    rnd = random.Random()
    once = os.environ.get("BENIGN_ONCE") == "1"
    while True:
        s = Session(cfg, rnd)
        try:
            s.run(plan_session(rnd))
            log.info("sesiune %s gata: %d cereri, %d erori", s.run_id, s.requests_done, s.errors)
        except Exception as e:  # noqa: BLE001 — o sesiune picata nu opreste generatorul
            log.exception("sesiune %s picata: %s", s.run_id, e)
            if once:
                return 1
        if once:
            return 0
        time.sleep(next_delay_s(datetime.now().hour, rnd))


if __name__ == "__main__":
    sys.exit(main())
