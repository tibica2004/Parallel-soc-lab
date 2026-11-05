"""
FERESTRELE DE MENTENANTA din asset-inventory (campul maintenance_windows).

O fereastra NU inchide nimic singura. Ridica doar podeaua "actiune sensibila"
pe Tier 1 si Tier 2, si doar impreuna cu ran_by_known_admin: un admin cunoscut,
in fereastra declarata de om, poate face actiuni sensibile fara ca modelul sa fie
obligat sa le escaladeze. Contul web, momelile, YARA, detectiile EDR raman la om
indiferent de fereastra (podelele lor nu depind de ea).

Ferestrele le scrie OMUL, cu contul elastic, direct in documentul activului din
asset-inventory (deploy/inventory_windows.py a fost sters la curatenia 9b391a1): o
fereastra slabeste o podea, deci e o decizie de acelasi fel ca o exceptie.

  curl -u elastic -H 'Content-Type: application/json' \\
    "$ES_URL/asset-inventory/_update/<id-ul documentului web-prod>" -d '{"doc": {
      "maintenance_windows": [{"days": [6], "start": "02:00", "end": "04:00", "reason": "..."}]}}'

Doua forme, in UTC:
  recurenta: {"days": [6], "start": "02:00", "end": "04:00", "reason": "..."}
             zilele 0 = luni ... 6 = duminica; end < start trece de miezul noptii
             (ziua e cea in care incepe fereastra).
  unica:     {"start_at": "2026-10-20T08:00:00Z", "end_at": "2026-10-20T12:00:00Z",
              "reason": "..."}

Esecul inchide fereastra: o intrare invalida e ignorata, iar un moment
necunoscut (fara timestamp) nu e niciodata "in fereastra". Ora evaluata e cea a
EVENIMENTULUI, nu a procesarii — in modul de restanta, o alerta de la 03:00
procesata la 09:00 trebuie judecata dupa 03:00.

Functii pure: fara Elasticsearch, fara model.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

# Plafoane: o fereastra "mereu deschisa" ar anula podeaua pe tacute.
MAX_RECURRING_H = 8
MAX_ONEOFF_H = 72

_HM_RE = re.compile(r"^([01][0-9]|2[0-3]):[0-5][0-9]$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _minutes(hm: str) -> int:
    h, m = hm.split(":")
    return int(h) * 60 + int(m)


class Window(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    days: list[int] | None = Field(default=None, min_length=1, max_length=7)
    start: str | None = None
    end: str | None = None
    start_at: datetime | None = None
    end_at: datetime | None = None
    reason: str = Field(min_length=3, max_length=200)

    @field_validator("days")
    @classmethod
    def _days(cls, v):
        if v is not None and (len(set(v)) != len(v) or any(d not in range(7) for d in v)):
            raise ValueError("days: valori distincte intre 0 (luni) si 6 (duminica)")
        return sorted(v) if v is not None else v

    @field_validator("start", "end")
    @classmethod
    def _hm(cls, v):
        if v is not None and not _HM_RE.match(v):
            raise ValueError("ora in formatul HH:MM (UTC)")
        return v

    @field_validator("start_at", "end_at")
    @classmethod
    def _aware(cls, v):
        if v is not None and v.tzinfo is None:
            raise ValueError("start_at/end_at cu fus orar explicit (ex. ...Z)")
        return v

    @field_validator("reason")
    @classmethod
    def _reason(cls, v):
        if _CONTROL_RE.search(v):
            raise ValueError("reason fara caractere de control")
        return v

    @model_validator(mode="after")
    def _shape(self):
        recurring = (self.days, self.start, self.end)
        oneoff = (self.start_at, self.end_at)
        if all(x is not None for x in recurring) and all(x is None for x in oneoff):
            if self.duration() > timedelta(hours=MAX_RECURRING_H) or self.start == self.end:
                raise ValueError(f"fereastra recurenta: intre 1 minut si {MAX_RECURRING_H} ore")
            return self
        if all(x is not None for x in oneoff) and all(x is None for x in recurring):
            if not (timedelta(0) < self.duration() <= timedelta(hours=MAX_ONEOFF_H)):
                raise ValueError(f"fereastra unica: end_at dupa start_at, cel mult {MAX_ONEOFF_H} ore")
            return self
        raise ValueError("ori days+start+end (recurenta), ori start_at+end_at (unica)")

    @property
    def recurring(self) -> bool:
        return self.days is not None

    def duration(self) -> timedelta:
        if self.recurring:
            d = _minutes(self.end) - _minutes(self.start)
            return timedelta(minutes=d if d > 0 else d + 24 * 60)
        return self.end_at - self.start_at

    def contains(self, at: datetime) -> bool:
        at = at.astimezone(timezone.utc)
        if not self.recurring:
            return self.start_at <= at < self.end_at
        m = at.hour * 60 + at.minute
        s, e = _minutes(self.start), _minutes(self.end)
        if s < e:
            return at.weekday() in self.days and s <= m < e
        # trece de miezul noptii: partea de seara apartine zilei de start,
        # partea de dupa miezul noptii apartine zilei urmatoare
        if m >= s:
            return at.weekday() in self.days
        return m < e and (at.weekday() - 1) % 7 in self.days

    def expired(self, now: datetime) -> bool:
        return not self.recurring and self.end_at <= now

    def describe(self) -> str:
        if self.recurring:
            zile = ",".join(ZILE[d] for d in self.days)
            return f"{zile} {self.start}-{self.end} UTC — {self.reason}"
        return (f"{self.start_at.astimezone(timezone.utc):%Y-%m-%d %H:%M} -> "
                f"{self.end_at.astimezone(timezone.utc):%Y-%m-%d %H:%M} UTC — {self.reason}")


ZILE = ("lun", "mar", "mie", "joi", "vin", "sam", "dum")


def parse_windows(asset: dict) -> tuple[list[Window], int]:
    """(ferestrele valide, cate intrari au fost respinse). Respinsele se ignora."""
    raw = (asset or {}).get("maintenance_windows") or []
    if not isinstance(raw, list):
        return [], 1
    ok, bad = [], 0
    for w in raw:
        try:
            ok.append(Window.model_validate(w))
        except (ValidationError, TypeError, ValueError):
            bad += 1
    return ok, bad


def parse_time(v) -> datetime | None:
    """Timestamp ISO din telemetrie -> datetime UTC; altfel None (fail closed)."""
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc) if v.tzinfo else None
    if not isinstance(v, str) or not v:
        return None
    try:
        t = datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t.astimezone(timezone.utc) if t.tzinfo else None


def active_window(asset: dict, at) -> Window | None:
    """Fereastra care contine momentul `at`, sau None."""
    t = parse_time(at)
    if t is None:
        return None
    for w in parse_windows(asset)[0]:
        if w.contains(t):
            return w
    return None


def covers(asset: dict, times: list) -> bool:
    """Adevarat doar daca TOATE momentele sunt in ferestre (ex. inceputul si
    sfarsitul unei potriviri de vanatoare). Lista goala sau moment necunoscut -> False."""
    return bool(times) and all(active_window(asset, t) is not None for t in times)
