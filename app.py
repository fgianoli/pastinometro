"""Pastinometro — backend minimale FastAPI + SQLite.

Espone:
- /api/auth/{register,login,logout,me}     auth username+password con cookie di sessione
- /api/kv, /api/kv/list, /api/kv/scan       KV store che replica window.storage
- /                                          serve il frontend (pastinometro.html)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

import bcrypt
from fastapi import FastAPI, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

# ---- Config ----

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "pastinometro.db"
HTML_PATH = BASE_DIR / "pastinometro.html"

COOKIE_NAME = "psm_session"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "true").lower() == "true"
SESSION_TTL_SECONDS = 30 * 24 * 3600

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "gianoli.federico@gmail.com")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_ENV = os.environ.get("ADMIN_PASSWORD") or None

# ---- Email / reset password (SMTP configurabile) ----
SMTP_HOST = os.environ.get("SMTP_HOST", "").strip() or None
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587") or 587)
SMTP_USER = os.environ.get("SMTP_USER", "").strip() or None
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
SMTP_USE_SSL = os.environ.get("SMTP_USE_SSL", "false").lower() == "true"
MAIL_FROM = os.environ.get("MAIL_FROM", "").strip() or None
BASE_URL = os.environ.get("BASE_URL", "").rstrip("/") or None
RESET_TOKEN_TTL = 30 * 60  # 30 minuti

USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,30}$")
MAX_VALUE_BYTES = 6 * 1024 * 1024  # 6 MB per chiave (basta per recensioni con foto compresse)
MAX_PHOTO_BYTES = 4 * 1024 * 1024  # 4 MB per foto (gia' compresse client-side)
PHOTOS_DIR = DATA_DIR / "photos"
PHOTOS_DIR.mkdir(parents=True, exist_ok=True)


# ---- Rate limiter (in-memory sliding window, single-process) ----

import threading
from collections import defaultdict, deque

_rl_lock = threading.Lock()
_rl_buckets: "dict[str, deque[float]]" = defaultdict(deque)


def _real_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check_rate(request: Request, scope: str, max_calls: int, period_sec: int) -> None:
    ip = _real_ip(request)
    key = f"{scope}:{ip}"
    now = time.time()
    with _rl_lock:
        q = _rl_buckets[key]
        # purge expired
        cutoff = now - period_sec
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= max_calls:
            raise HTTPException(429, "troppe richieste, riprova tra qualche secondo")
        q.append(now)


# ---- DB ----

def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    conn = get_db()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                email TEXT,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
            CREATE TABLE IF NOT EXISTS kv_shared (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS kv_private (
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (user_id, key)
            );
            """
        )
        # Migration: aggiunge owner_id a kv_shared se mancante (NULL = legacy/no-owner).
        cols = [r["name"] for r in conn.execute("PRAGMA table_info(kv_shared)").fetchall()]
        if "owner_id" not in cols:
            conn.execute("ALTER TABLE kv_shared ADD COLUMN owner_id TEXT")
        # Tabella per i token di reset password
        conn.execute(
            """CREATE TABLE IF NOT EXISTS password_resets (
                token TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            )"""
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_password_resets_user ON password_resets(user_id)"
        )
    finally:
        conn.close()


def ensure_admin() -> None:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id FROM users WHERE username = ? COLLATE NOCASE",
            (ADMIN_USERNAME,),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE users SET email = ?, is_admin = 1 WHERE id = ?",
                (ADMIN_EMAIL, row["id"]),
            )
            return
        if ADMIN_PASSWORD_ENV:
            pw = ADMIN_PASSWORD_ENV
            generated = False
        else:
            pw = secrets.token_urlsafe(18)
            generated = True
        pw_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
        admin_id = "u_" + secrets.token_hex(6)
        conn.execute(
            "INSERT INTO users(id, username, email, password_hash, is_admin, created_at)"
            " VALUES (?,?,?,?,1,?)",
            (admin_id, ADMIN_USERNAME, ADMIN_EMAIL, pw_hash, int(time.time())),
        )
        if generated:
            pw_file = DATA_DIR / "admin_password.txt"
            pw_file.write_text(
                f"username: {ADMIN_USERNAME}\nemail: {ADMIN_EMAIL}\npassword: {pw}\n",
                encoding="utf-8",
            )
            try:
                os.chmod(pw_file, 0o600)
            except OSError:
                pass
            banner = "=" * 60
            print(banner, flush=True)
            print("ADMIN ACCOUNT CREATED (random password generated)", flush=True)
            print(f"  username: {ADMIN_USERNAME}", flush=True)
            print(f"  email:    {ADMIN_EMAIL}", flush=True)
            print(f"  password: {pw}", flush=True)
            print(f"  saved to: {pw_file}", flush=True)
            print("Set ADMIN_PASSWORD in .env to choose your own next time.", flush=True)
            print(banner, flush=True)
    finally:
        conn.close()


# ---- App ----

app = FastAPI(title="Pastinometro", docs_url="/api/docs", openapi_url="/api/openapi.json")


@app.on_event("startup")
def _startup() -> None:
    init_db()
    ensure_admin()


# ---- Auth helpers ----

def _user_from_token(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    conn = get_db()
    try:
        row = conn.execute(
            """SELECT u.id, u.username, u.email, u.is_admin
               FROM sessions s JOIN users u ON u.id = s.user_id
               WHERE s.token = ? AND s.expires_at > ?""",
            (token, int(time.time())),
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _require_user(request: Request) -> dict:
    user = _user_from_token(request.cookies.get(COOKIE_NAME))
    if not user:
        raise HTTPException(401, "non autenticato")
    return user


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="lax",
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )


def _create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO sessions(token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token, user_id, now, now + SESSION_TTL_SECONDS),
        )
    finally:
        conn.close()
    return token


def _user_payload(row: dict) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row.get("email") if isinstance(row, dict) else row["email"],
        "isAdmin": bool(row["is_admin"]),
    }


# ---- Auth endpoints ----

class RegisterIn(BaseModel):
    username: str = Field(..., min_length=2, max_length=30)
    password: str = Field(..., min_length=6, max_length=200)
    email: Optional[str] = Field(None, max_length=200)


class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/auth/register")
def register(payload: RegisterIn, request: Request, response: Response):
    _check_rate(request, "register", max_calls=5, period_sec=3600)  # 5 / ora / IP
    username = payload.username.strip()
    if not USERNAME_RE.match(username):
        raise HTTPException(400, "username: 2-30 caratteri, solo lettere/numeri/._-")
    conn = get_db()
    try:
        if conn.execute(
            "SELECT 1 FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone():
            raise HTTPException(409, "username già in uso")
        pw_hash = bcrypt.hashpw(payload.password.encode(), bcrypt.gensalt()).decode()
        user_id = "u_" + secrets.token_hex(6)
        conn.execute(
            "INSERT INTO users(id, username, email, password_hash, is_admin, created_at)"
            " VALUES (?,?,?,?,0,?)",
            (user_id, username, payload.email, pw_hash, int(time.time())),
        )
    finally:
        conn.close()
    token = _create_session(user_id)
    _set_session_cookie(response, token)
    return {"id": user_id, "username": username, "email": payload.email, "isAdmin": False}


@app.post("/api/auth/login")
def login(payload: LoginIn, request: Request, response: Response):
    _check_rate(request, "login", max_calls=10, period_sec=60)  # 10 / minuto / IP
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email, password_hash, is_admin FROM users"
            " WHERE username = ? COLLATE NOCASE",
            (payload.username.strip(),),
        ).fetchone()
    finally:
        conn.close()
    if not row or not bcrypt.checkpw(payload.password.encode(), row["password_hash"].encode()):
        raise HTTPException(401, "username o password errati")
    token = _create_session(row["id"])
    _set_session_cookie(response, token)
    return _user_payload(dict(row))


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        conn = get_db()
        try:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        finally:
            conn.close()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@app.get("/api/auth/me")
def me(request: Request):
    user = _user_from_token(request.cookies.get(COOKIE_NAME))
    return {"user": _user_payload(user) if user else None}


class ChangePasswordIn(BaseModel):
    current_password: str = Field(..., min_length=1, max_length=200)
    new_password: str = Field(..., min_length=6, max_length=200)


class ForgotIn(BaseModel):
    email: str = Field(..., min_length=3, max_length=200)


class ResetIn(BaseModel):
    token: str = Field(..., min_length=20, max_length=200)
    new_password: str = Field(..., min_length=6, max_length=200)


def _send_reset_email(to_email: str, username: str, link: str) -> None:
    """Manda l'email di reset via SMTP. Solleva eccezioni se SMTP non configurato o invio fallisce."""
    import smtplib
    from email.message import EmailMessage

    if not SMTP_HOST or not MAIL_FROM:
        raise RuntimeError("SMTP non configurato: imposta SMTP_HOST e MAIL_FROM nel .env")

    msg = EmailMessage()
    msg["Subject"] = "Reset password — Il Pastinometro"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    body_text = (
        f"Ciao {username},\n\n"
        "hai chiesto di reimpostare la password del tuo account su Il Pastinometro.\n\n"
        f"Apri questo link entro 30 minuti per scegliere una nuova password:\n{link}\n\n"
        "Se non sei stato tu, ignora questa email — il tuo account resta com'e'.\n\n"
        "— Il Pastinometro\n"
        f"{BASE_URL or ''}\n"
    )
    msg.set_content(body_text)
    body_html = (
        '<!doctype html><html><body style="font-family:Georgia,serif;color:#2a1e14;'
        'background:#f3ede0;padding:20px;margin:0">'
        '<div style="max-width:520px;margin:auto;background:#faf4e6;border:1px solid #c9b896;'
        'padding:24px;border-radius:4px">'
        '<div style="font-style:italic;color:#8b1e2e;letter-spacing:.18em;text-transform:uppercase;'
        'font-size:11px;margin-bottom:8px">Il Pastin&ograve;metro</div>'
        f'<h2 style="margin:0 0 14px">Ciao {username},</h2>'
        '<p>hai chiesto di reimpostare la password del tuo account.</p>'
        f'<p style="margin:24px 0"><a href="{link}" '
        'style="background:#8b1e2e;color:#faf4e6;padding:11px 22px;text-decoration:none;'
        'border-radius:3px;display:inline-block;font-weight:600">Scegli una nuova password</a></p>'
        '<p style="font-size:12px;color:#5a4735">Il link e&apos; valido per 30 minuti. '
        'Se non sei stato tu, ignora questa email.</p>'
        f'<p style="font-size:11px;color:#5a4735;margin-top:24px;border-top:1px dashed #c9b896;'
        f'padding-top:12px">&mdash; Il Pastin&ograve;metro<br/>'
        f'<a href="{BASE_URL or "#"}" style="color:#8b1e2e">{BASE_URL or ""}</a></p>'
        '</div></body></html>'
    )
    msg.add_alternative(body_html, subtype="html")

    if SMTP_USE_SSL:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as s:
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as s:
            s.ehlo()
            if SMTP_USE_TLS:
                s.starttls()
                s.ehlo()
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASSWORD)
            s.send_message(msg)


@app.get("/api/auth/email-config")
def email_config():
    """Per il frontend: dice se il reset via email e' abilitato."""
    return {"enabled": bool(SMTP_HOST and MAIL_FROM)}


@app.post("/api/auth/forgot")
def forgot_password(payload: ForgotIn, request: Request):
    _check_rate(request, "forgot", max_calls=5, period_sec=600)
    if not SMTP_HOST or not MAIL_FROM:
        raise HTTPException(503, "il reset password via email non e' configurato")
    email = payload.email.strip().lower()
    if not email or "@" not in email:
        return {"ok": True}  # 200 generico — non rivelare se l'email esiste
    base_url = BASE_URL or str(request.base_url).rstrip("/")
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email FROM users WHERE LOWER(email) = ?", (email,)
        ).fetchone()
        if row:
            token = secrets.token_urlsafe(32)
            now = int(time.time())
            conn.execute(
                "INSERT INTO password_resets(token, user_id, created_at, expires_at)"
                " VALUES (?,?,?,?)",
                (token, row["id"], now, now + RESET_TOKEN_TTL),
            )
            link = f"{base_url}/?reset={token}"
            try:
                _send_reset_email(row["email"], row["username"], link)
            except Exception as e:
                # log dell'errore — non riveliamo dettagli al client
                print(f"[forgot] errore invio email a {row['email']}: {e!r}", flush=True)
                raise HTTPException(500, "errore nell'invio dell'email — contatta l'admin")
    finally:
        conn.close()
    return {"ok": True}


@app.post("/api/auth/reset")
def reset_password(payload: ResetIn, request: Request, response: Response):
    _check_rate(request, "reset", max_calls=10, period_sec=600)
    conn = get_db()
    try:
        now = int(time.time())
        row = conn.execute(
            "SELECT user_id FROM password_resets"
            " WHERE token = ? AND used = 0 AND expires_at > ?",
            (payload.token, now),
        ).fetchone()
        if not row:
            raise HTTPException(400, "token non valido o scaduto")
        user_id = row["user_id"]
        new_hash = bcrypt.hashpw(payload.new_password.encode(), bcrypt.gensalt()).decode()
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.execute("UPDATE password_resets SET used = 1 WHERE token = ?", (payload.token,))
        # invalida tutte le sessioni dell'utente — rifara' login con la nuova password
        conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
    finally:
        conn.close()
    return {"ok": True}


@app.post("/api/auth/change-password")
def change_password(payload: ChangePasswordIn, request: Request, response: Response):
    _check_rate(request, "change-pw", max_calls=10, period_sec=60)
    user = _require_user(request)
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT password_hash FROM users WHERE id = ?", (user["id"],)
        ).fetchone()
        if not row or not bcrypt.checkpw(
            payload.current_password.encode(), row["password_hash"].encode()
        ):
            raise HTTPException(401, "password attuale errata")
        new_hash = bcrypt.hashpw(payload.new_password.encode(), bcrypt.gensalt()).decode()
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))
        # invalida tutte le altre sessioni (best practice di sicurezza),
        # mantiene solo quella corrente
        current_token = request.cookies.get(COOKIE_NAME)
        conn.execute(
            "DELETE FROM sessions WHERE user_id = ? AND token != ?",
            (user["id"], current_token or ""),
        )
    finally:
        conn.close()
    return {"ok": True}


# ---- KV endpoints ----

class KvPut(BaseModel):
    value: str


def _validate_key(key: str) -> None:
    if not key or len(key) > 500:
        raise HTTPException(400, "chiave non valida")


@app.get("/api/kv")
def kv_get(request: Request, key: str = Query(...), shared: bool = Query(True)):
    _validate_key(key)
    conn = get_db()
    try:
        if shared:
            row = conn.execute(
                "SELECT value, updated_at FROM kv_shared WHERE key = ?", (key,)
            ).fetchone()
        else:
            user = _require_user(request)
            row = conn.execute(
                "SELECT value, updated_at FROM kv_private WHERE user_id = ? AND key = ?",
                (user["id"], key),
            ).fetchone()
    finally:
        conn.close()
    if not row:
        raise HTTPException(404, "non trovato")
    return {"value": row["value"], "updatedAt": row["updated_at"]}


@app.put("/api/kv")
def kv_put(payload: KvPut, request: Request, key: str = Query(...), shared: bool = Query(True)):
    _validate_key(key)
    if len(payload.value.encode("utf-8")) > MAX_VALUE_BYTES:
        raise HTTPException(413, "valore troppo grande")
    user = _require_user(request)
    now = int(time.time())
    conn = get_db()
    try:
        if shared:
            # ON CONFLICT non aggiorna owner_id: il primo writer rimane il proprietario.
            # Per chiavi avail:* (multi-writer per design) altri utenti possono PUT
            # nuovi valori, ma solo il primo writer (o admin) puo' DELETE.
            conn.execute(
                "INSERT INTO kv_shared(key, value, owner_id, updated_at) VALUES (?,?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, payload.value, user["id"], now),
            )
        else:
            conn.execute(
                "INSERT INTO kv_private(user_id, key, value, updated_at) VALUES (?,?,?,?) "
                "ON CONFLICT(user_id, key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (user["id"], key, payload.value, now),
            )
    finally:
        conn.close()
    return {"ok": True}


def _can_delete_shared(user: dict, key: str, owner_id: Optional[str], conn: sqlite3.Connection) -> bool:
    """Regole di autorizzazione per la DELETE su kv_shared.

    1. admin: sempre.
    2. owner_id NULL (chiavi pre-migration): chiunque loggato (legacy).
    3. owner_id == utente: si'.
    4. Cascade: il proprietario di un place puo' cancellare review:/avail: di quel place;
       il proprietario di una pastry puo' cancellare avail:*:<pastryKey>.
    """
    if user["is_admin"]:
        return True
    if owner_id is None:
        return True
    if owner_id == user["id"]:
        return True
    parts = key.split(":")
    # review:<placeId>:<reviewId>  o  avail:<placeId>:<pastryKey>
    if (key.startswith("review:") or key.startswith("avail:")) and len(parts) >= 2:
        place_id = parts[1]
        row = conn.execute(
            "SELECT owner_id FROM kv_shared WHERE key = ?", (f"place:{place_id}",)
        ).fetchone()
        if row and row["owner_id"] == user["id"]:
            return True
    # avail:<placeId>:<pastryKey> -> il proprietario della pastry custom puo' cascadere
    if key.startswith("avail:") and len(parts) >= 3:
        pastry_key = parts[2]
        row = conn.execute(
            "SELECT owner_id FROM kv_shared WHERE key = ?", (f"pastry:{pastry_key}",)
        ).fetchone()
        if row and row["owner_id"] == user["id"]:
            return True
    return False


@app.delete("/api/kv")
def kv_delete(request: Request, key: str = Query(...), shared: bool = Query(True)):
    _validate_key(key)
    user = _require_user(request)
    conn = get_db()
    try:
        if shared:
            row = conn.execute(
                "SELECT owner_id FROM kv_shared WHERE key = ?", (key,)
            ).fetchone()
            if not row:
                # delete idempotente: chiave inesistente -> ok
                return {"ok": True}
            if not _can_delete_shared(user, key, row["owner_id"], conn):
                raise HTTPException(403, "solo l'autore o un admin possono cancellare questa risorsa")
            conn.execute("DELETE FROM kv_shared WHERE key = ?", (key,))
        else:
            conn.execute(
                "DELETE FROM kv_private WHERE user_id = ? AND key = ?",
                (user["id"], key),
            )
    finally:
        conn.close()
    return {"ok": True}


@app.get("/api/kv/list")
def kv_list(request: Request, prefix: str = Query(""), shared: bool = Query(True)):
    if len(prefix) > 500:
        raise HTTPException(400, "prefix troppo lungo")
    pat = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    conn = get_db()
    try:
        if shared:
            rows = conn.execute(
                "SELECT key FROM kv_shared WHERE key LIKE ? ESCAPE '\\' ORDER BY key",
                (pat,),
            ).fetchall()
        else:
            user = _require_user(request)
            rows = conn.execute(
                "SELECT key FROM kv_private WHERE user_id = ? AND key LIKE ? ESCAPE '\\' ORDER BY key",
                (user["id"], pat),
            ).fetchall()
    finally:
        conn.close()
    return {"keys": [r["key"] for r in rows]}


@app.get("/api/kv/scan")
def kv_scan(request: Request, prefix: str = Query(""), shared: bool = Query(True)):
    """Come list ma restituisce anche i valori — evita N+1 sui caricamenti."""
    if len(prefix) > 500:
        raise HTTPException(400, "prefix troppo lungo")
    pat = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    conn = get_db()
    try:
        if shared:
            rows = conn.execute(
                "SELECT key, value FROM kv_shared WHERE key LIKE ? ESCAPE '\\' ORDER BY key",
                (pat,),
            ).fetchall()
        else:
            user = _require_user(request)
            rows = conn.execute(
                "SELECT key, value FROM kv_private WHERE user_id = ? AND key LIKE ? ESCAPE '\\' ORDER BY key",
                (user["id"], pat),
            ).fetchall()
    finally:
        conn.close()
    return {"items": [{"key": r["key"], "value": r["value"]} for r in rows]}


# ---- OSM re-import (admin only) ----

OVERPASS_URL = os.environ.get("OVERPASS_URL", "https://overpass-api.de/api/interpreter")
OSM_PLACES_FILE = DATA_DIR / "osm_places.json"

OVERPASS_QUERY = """
[out:json][timeout:60];
area["name"="Padova"]["admin_level"="8"]->.searchArea;
(
  node["amenity"~"^(cafe|bar)$"](area.searchArea);
  way["amenity"~"^(cafe|bar)$"](area.searchArea);
  node["shop"~"^(bakery|pastry|confectionery)$"](area.searchArea);
  way["shop"~"^(bakery|pastry|confectionery)$"](area.searchArea);
);
out center;
""".strip()


def _osm_element_to_place(el: dict) -> Optional[dict]:
    tags = el.get("tags") or {}
    name = (tags.get("name") or "").strip()
    if not name:
        return None
    if "lat" in el and "lon" in el:
        lat, lon = el.get("lat"), el.get("lon")
    elif "center" in el:
        c = el["center"]
        lat, lon = c.get("lat"), c.get("lon")
    else:
        return None
    if lat is None or lon is None:
        return None
    typ = el.get("type")
    osm_id = el.get("id")
    if typ == "node":
        pid = f"n{osm_id}"
    elif typ == "way":
        pid = f"w{osm_id}"
    elif typ == "relation":
        pid = f"r{osm_id}"
    else:
        return None
    shop = tags.get("shop")
    amenity = tags.get("amenity")
    if shop == "bakery":
        cat = "bakery"
    elif shop in ("pastry", "confectionery"):
        cat = "pastry"
    elif amenity == "cafe":
        cat = "cafe"
    elif amenity == "bar":
        cat = "bar"
    else:
        return None
    parts = []
    if tags.get("addr:street"):
        parts.append(str(tags["addr:street"]))
    if tags.get("addr:housenumber"):
        parts.append(str(tags["addr:housenumber"]))
    address = " ".join(parts).strip()
    return {
        "id": pid,
        "name": name,
        "lat": round(float(lat), 6),
        "lon": round(float(lon), 6),
        "category": cat,
        "address": address,
        "phone": tags.get("contact:phone") or tags.get("phone") or "",
        "website": tags.get("contact:website") or tags.get("website") or "",
        "hours": tags.get("opening_hours") or "",
    }


def _load_osm_file() -> dict:
    if not OSM_PLACES_FILE.is_file():
        return {"places": [], "ts": None}
    try:
        return json.loads(OSM_PLACES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"places": [], "ts": None}


@app.post("/api/admin/osm-reimport")
def osm_reimport(request: Request):
    user = _require_user(request)
    if not user["is_admin"]:
        raise HTTPException(403, "solo l'admin puo' eseguire questa operazione")
    _check_rate(request, "osm-reimport", max_calls=3, period_sec=600)
    try:
        body = urllib.parse.urlencode({"data": OVERPASS_QUERY}).encode("utf-8")
        req = urllib.request.Request(
            OVERPASS_URL,
            data=body,
            headers={
                "User-Agent": "Pastinometro/1.0 (admin OSM reimport)",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        with urllib.request.urlopen(req, timeout=90) as resp:
            raw = resp.read()
        payload = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise HTTPException(502, f"Overpass HTTP {e.code}: {e.reason}")
    except urllib.error.URLError as e:
        raise HTTPException(502, f"Overpass network error: {e.reason}")
    except Exception as e:
        raise HTTPException(502, f"errore Overpass: {e!r}")
    elements = payload.get("elements") or []
    new_places = [p for p in (_osm_element_to_place(el) for el in elements) if p]
    if not new_places:
        raise HTTPException(502, "Overpass ha risposto ma senza elementi utilizzabili")
    # ordina per nome per file stabile (utile in caso di backup/diff)
    new_places.sort(key=lambda p: (p["name"].lower(), p["id"]))
    # diff con dataset precedente
    old = _load_osm_file()
    old_ids = {p["id"] for p in old.get("places", [])}
    new_ids = {p["id"] for p in new_places}
    added = new_ids - old_ids
    removed = old_ids - new_ids
    OSM_PLACES_FILE.write_text(
        json.dumps(
            {"places": new_places, "ts": int(time.time())},
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return {
        "total": len(new_places),
        "added": len(added),
        "removed": len(removed),
        "previous_total": len(old.get("places", [])),
    }


@app.get("/api/osm-places")
def get_osm_places():
    """Restituisce i luoghi OSM piu' recenti se l'admin ha mai fatto un reimport,
    altrimenti {places: [], ts: null}. Il frontend in caso di lista vuota usa
    i dati embeddati nell'HTML come fallback."""
    return _load_osm_file()


# ---- Photos ----

def _detect_image_ext(data: bytes) -> Optional[str]:
    """Riconosce JPG/PNG/WebP dai magic bytes. Tornaa l'estensione (es. '.jpg')."""
    if data.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    return None


@app.post("/api/photos")
async def upload_photo(request: Request, file: UploadFile = File(...)):
    user = _require_user(request)
    _check_rate(request, "photo", max_calls=30, period_sec=60)
    contents = await file.read()
    if not contents:
        raise HTTPException(400, "file vuoto")
    if len(contents) > MAX_PHOTO_BYTES:
        raise HTTPException(413, f"foto troppo grande (max {MAX_PHOTO_BYTES // (1024*1024)} MB)")
    ext = _detect_image_ext(contents)
    if not ext:
        raise HTTPException(400, "formato non supportato (JPG, PNG o WebP)")
    h = hashlib.sha256(contents).hexdigest()[:32]
    fname = f"{h}{ext}"
    path = PHOTOS_DIR / fname
    if not path.exists():
        path.write_bytes(contents)
    return {"url": f"/photos/{fname}", "size": len(contents)}


# ---- Static / health ----

STATIC_DIR = BASE_DIR / "static"
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
# foto caricate dagli utenti — dir gia' creata in alto
app.mount("/photos", StaticFiles(directory=str(PHOTOS_DIR)), name="photos")


@app.get("/")
def index():
    return FileResponse(HTML_PATH)


@app.get("/manifest.webmanifest")
def manifest():
    """Serve manifest also at the root path so browsers find it without /static prefix."""
    return FileResponse(
        STATIC_DIR / "manifest.webmanifest",
        media_type="application/manifest+json",
    )


@app.get("/apple-touch-icon.png")
@app.get("/apple-touch-icon-precomposed.png")
@app.get("/favicon.ico")
def fallback_icon():
    """Return the SVG icon for any common icon path browsers probe automatically."""
    return FileResponse(STATIC_DIR / "icon.svg", media_type="image/svg+xml")


@app.get("/healthz")
def healthz():
    return {"ok": True}
