from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import sqlite3
from pathlib import Path
import os
import time
from typing import Dict, List
import jwt
from passlib.context import CryptContext

# ----------------------------
# Config
# ----------------------------
DB_PATH = Path(os.environ.get("DB_PATH", "/tmp/inboxly.db"))

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALG = "HS256"
JWT_EXPIRES_DAYS = 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ----------------------------
# App
# ----------------------------
app = FastAPI(title="Inboxly API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://inboxly-ten.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------
# Models
# ----------------------------
class AuthBody(BaseModel):
    email: EmailStr
    password: str


# ----------------------------
# DB helpers
# ----------------------------
def get_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan TEXT NOT NULL DEFAULT 'free',
            created_at TEXT NOT NULL
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS inboxes (
            inbox_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            address TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            inbox_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            subject TEXT NOT NULL,
            received_at TEXT NOT NULL,
            preview TEXT NOT NULL,
            body TEXT NOT NULL,
            FOREIGN KEY (inbox_id) REFERENCES inboxes(inbox_id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()


init_db()

@app.on_event("startup")
def startup():
    init_db()


# ----------------------------
# Debug endpoint
# ----------------------------
@app.post("/debug/password-bytes")
def debug_password_bytes(body: AuthBody):
    return {
        "password_chars": len(body.password or ""),
        "password_bytes": len((body.password or "").encode("utf-8")),
    }


# ----------------------------
# Helpers
# ----------------------------
def _normalize_password(raw: str) -> str:
    pw = (raw or "").strip()

    if len(pw) < 8:
        raise HTTPException(status_code=400, detail="Password too short (min 8)")

    if len(pw.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password too long (max 72 bytes)")

    return pw


def _require_jwt_secret():
    if not JWT_SECRET:
        raise HTTPException(status_code=503, detail="JWT_SECRET not set on server")


def _create_token(user_id: str) -> str:
    _require_jwt_secret()
    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=JWT_EXPIRES_DAYS)
    payload = {"sub": user_id, "iat": int(now.timestamp()), "exp": int(exp.timestamp())}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def _get_user_id_from_auth(req: Request) -> str:
    _require_jwt_secret()
    auth = req.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token>")
    token = auth.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload.get("sub")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


# ----------------------------
# Public
# ----------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


# ----------------------------
# Auth
# ----------------------------
@app.post("/v1/auth/register")
def register(body: AuthBody, req: Request):
    pw = _normalize_password(body.password)

    try:
        pw_hash = pwd_context.hash(pw)
    except ValueError as e:
        pw_bytes = len(pw.encode("utf-8"))
        raise HTTPException(
            status_code=400,
            detail=f"bcrypt rejected password ({pw_bytes} bytes): {str(e)}"
        )

    user_id = str(uuid4())
    created_at = datetime.now(timezone.utc).isoformat()

    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users (user_id, email, password_hash, plan, created_at) VALUES (?, ?, ?, 'free', ?)",
            (user_id, body.email.lower().strip(), pw_hash, created_at),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=409, detail="Email already registered")

    conn.close()

    token = _create_token(user_id)
    return {"token": token, "user": {"user_id": user_id, "email": body.email, "plan": "free"}}


@app.post("/v1/auth/login")
def login(body: AuthBody):
    pw = _normalize_password(body.password)

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT user_id, password_hash FROM users WHERE email = ?", (body.email.lower().strip(),))
    row = cur.fetchone()
    conn.close()

    try:
        ok = bool(row) and pwd_context.verify(pw, row["password_hash"])
    except ValueError as e:
        pw_bytes = len(pw.encode("utf-8"))
        raise HTTPException(
            status_code=400,
            detail=f"bcrypt rejected password ({pw_bytes} bytes): {str(e)}"
        )

    if not ok:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = _create_token(row["user_id"])
    return {"token": token}
