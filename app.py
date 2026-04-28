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
def register(payload: RegisterIn, response: Response):
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
def login(payload: LoginIn, response: Response):
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
            conn.execute(
                "INSERT INTO kv_shared(key, value, updated_at) VALUES (?,?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, payload.value, now),
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


@app.delete("/api/kv")
def kv_delete(request: Request, key: str = Query(...), shared: bool = Query(True)):
    _validate_key(key)
    user = _require_user(request)
    conn = get_db()
    try:
        if shared:
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

@app.get("/")
def index():
    return FileResponse(HTML_PATH)


@app.get("/healthz")
def healthz():
    return {"ok": True}
