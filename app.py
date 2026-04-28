"""Pastinometro — backend minimale FastAPI + SQLite.

Espone:
- /api/auth/{register,login,logout,me}     auth username+password con cookie di sessione
- /api/kv, /api/kv/list, /api/kv/scan       KV store che replica window.storage
- /                                          serve il frontend (pastinometro.html)
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Optional

import bcrypt
from fastapi import FastAPI, HTTPException, Query, Request, Response
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

USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{2,30}$")
MAX_VALUE_BYTES = 6 * 1024 * 1024  # 6 MB per chiave (basta per recensioni con foto compresse)


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


# ---- Static / health ----

STATIC_DIR = BASE_DIR / "static"
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


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
