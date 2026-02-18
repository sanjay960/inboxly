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
# Render-safe SQLite path:
# - Recommended on Render: set DB_PATH=/tmp/inboxly.db (writable)
# - Or attach a disk and set DB_PATH to that disk mount for persistence
DB_PATH = Path(os.environ.get("DB_PATH", "/tmp/inboxly.db"))

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALG = "HS256"
JWT_EXPIRES_DAYS = 7  # token lifetime

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
    # Ensure parent directory exists (useful if DB_PATH points to a mounted directory)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan TEXT NOT NULL DEFAULT 'free',
            created_at TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS inboxes (
            inbox_id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            address TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
        """
    )

    cur.execute(
        """
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
        """
    )

    # Indexes (scale-safe)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_inboxes_user ON inboxes(user_id)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_inboxes_expires ON inboxes(expires_at)")
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_inbox_received ON messages(inbox_id, received_at)"
    )

    conn.commit()
    conn.close()


# Init at import + on startup (safer for Render restarts)
init_db()


@app.on_event("startup")
def _startup():
    init_db()


# ----------------------------
# Rate limiting (MVP in-memory)
# ----------------------------
_rate_buckets: Dict[str, List[float]] = {}


def _rate_limit(key: str, limit: int, window_seconds: int) -> None:
    now = time.time()
    bucket = _rate_buckets.get(key, [])
    cutoff = now - window_seconds
    bucket = [t for t in bucket if t >= cutoff]
    if len(bucket) >= limit:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {limit} per {window_seconds}s",
        )
    bucket.append(now)
    _rate_buckets[key] = bucket


def _client_ip(req: Request) -> str:
    return req.client.host if req.client else "unknown"


# ----------------------------
# Password helpers (bcrypt 72-byte limit)
# ----------------------------
def _normalize_password(raw: str) -> str:
    pw = (raw or "").strip()

    if len(pw) < 8:
        raise HTTPException(status_code=400, detail="Password too short (min 8)")

    # bcrypt limit is 72 BYTES (not 72 characters)
    if len(pw.encode("utf-8")) > 72:
        raise HTTPException(status_code=400, detail="Password too long (max 72 bytes)")

    return pw


# ----------------------------
# JWT helpers
# ----------------------------
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
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def _get_user(user_id: str) -> sqlite3.Row:
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT user_id, email, plan, created_at FROM users WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return row


# ----------------------------
# Inbox expiry/ownership helpers
# ----------------------------
def _require_active_inbox_owned(inbox_id: str, user_id: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT user_id, expires_at FROM inboxes WHERE inbox_id = ?", (inbox_id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Inbox not found")

    if row["user_id"] != user_id:
        conn.close()
        raise HTTPException(status_code=403, detail="Forbidden")

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) >= expires_at:
        # delete inbox -> cascade messages
        cur.execute("DELETE FROM inboxes WHERE inbox_id = ?", (inbox_id,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=410, detail="Inbox expired")

    conn.close()


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
    ip = _client_ip(req)
    _rate_limit(f"{ip}:register", limit=10, window_seconds=60)

    pw = _normalize_password(body.password)

    user_id = str(uuid4())

    # Safety net: never let bcrypt error become 500
    try:
        pw_hash = pwd_context.hash(pw)
    except ValueError:
        raise HTTPException(status_code=400, detail="Password too long (max 72 bytes)")

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
def login(body: AuthBody, req: Request):
    ip = _client_ip(req)
    _rate_limit(f"{ip}:login", limit=20, window_seconds=60)

    pw = _normalize_password(body.password)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT user_id, password_hash, plan FROM users WHERE email = ?",
        (body.email.lower().strip(),),
    )
    row = cur.fetchone()
    conn.close()

    # Safety net: bcrypt verify should not throw 500
    try:
        ok = bool(row) and pwd_context.verify(pw, row["password_hash"])
    except ValueError:
        raise HTTPException(status_code=400, detail="Password too long (max 72 bytes)")

    if not ok:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = _create_token(row["user_id"])
    return {"token": token, "user": {"user_id": row["user_id"], "email": body.email, "plan": row["plan"]}}


@app.get("/v1/me")
def me(req: Request):
    user_id = _get_user_id_from_auth(req)
    u = _get_user(user_id)
    return {"user_id": u["user_id"], "email": u["email"], "plan": u["plan"], "created_at": u["created_at"]}


# ----------------------------
# Inboxes (authenticated)
# ----------------------------
@app.post("/v1/inbox")
def create_inbox(req: Request):
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:create_inbox", limit=20, window_seconds=60)

    user_id = _get_user_id_from_auth(req)
    user = _get_user(user_id)
    plan = user["plan"]

    max_active = 1 if plan == "free" else 10

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=15)
    created_at = now.isoformat()

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT COUNT(*) AS c FROM inboxes WHERE user_id = ? AND expires_at > ?",
        (user_id, now.isoformat()),
    )
    active = int(cur.fetchone()["c"])
    if active >= max_active:
        conn.close()
        raise HTTPException(status_code=402, detail=f"Plan limit reached: max {max_active} active inbox(es)")

    inbox_id = str(uuid4())
    address = f"{inbox_id[:8]}@inboxly.dev"

    cur.execute(
        "INSERT INTO inboxes (inbox_id, user_id, address, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
        (inbox_id, user_id, address, expires_at.isoformat(), created_at),
    )
    conn.commit()
    conn.close()

    return {"inbox_id": inbox_id, "address": address, "expires_at": expires_at.isoformat(), "plan": plan}


@app.get("/v1/inbox/{inbox_id}/messages")
def list_messages(inbox_id: str, req: Request):
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:list_messages", limit=60, window_seconds=60)

    user_id = _get_user_id_from_auth(req)
    _require_active_inbox_owned(inbox_id, user_id)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, sender, subject, received_at, preview
        FROM messages
        WHERE inbox_id = ?
        ORDER BY received_at DESC
        """,
        (inbox_id,),
    )
    rows = cur.fetchall()
    conn.close()

    messages = [
        {
            "id": r["id"],
            "from": r["sender"],
            "subject": r["subject"],
            "received_at": r["received_at"],
            "preview": r["preview"],
        }
        for r in rows
    ]

    return {"inbox_id": inbox_id, "messages": messages}


@app.get("/v1/message/{message_id}")
def get_message(message_id: str, req: Request):
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:get_message", limit=120, window_seconds=60)

    user_id = _get_user_id_from_auth(req)

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        SELECT m.id, m.inbox_id, m.sender, m.subject, m.received_at, m.body,
               i.user_id, i.expires_at
        FROM messages m
        JOIN inboxes i ON i.inbox_id = m.inbox_id
        WHERE m.id = ?
        """,
        (message_id,),
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Message not found")

    if row["user_id"] != user_id:
        conn.close()
        raise HTTPException(status_code=403, detail="Forbidden")

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) >= expires_at:
        cur.execute("DELETE FROM inboxes WHERE inbox_id = ?", (row["inbox_id"],))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=410, detail="Inbox expired")

    conn.close()

    return {
        "id": row["id"],
        "inbox_id": row["inbox_id"],
        "from": row["sender"],
        "subject": row["subject"],
        "received_at": row["received_at"],
        "body": row["body"],
    }


@app.post("/v1/inbox/{inbox_id}/test-email")
def send_test_email(inbox_id: str, req: Request):
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:test_email", limit=60, window_seconds=60)

    user_id = _get_user_id_from_auth(req)
    _require_active_inbox_owned(inbox_id, user_id)

    now = datetime.now(timezone.utc).isoformat()
    msg_id = str(uuid4())

    msg = {
        "id": msg_id,
        "from": "test@inboxly.dev",
        "subject": "Welcome to Inboxly (Test)",
        "received_at": now,
        "preview": "Message stored in your user-owned inbox.",
        "body": "Hi! This is a fake message for local testing.",
    }

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO messages (id, inbox_id, sender, subject, received_at, preview, body)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (msg_id, inbox_id, msg["from"], msg["subject"], msg["received_at"], msg["preview"], msg["body"]),
    )
    conn.commit()
    conn.close()

    return msg

@app.post("/debug/password-bytes")
def debug_password_bytes(body: AuthBody):
    # DO NOT return password; only return lengths
    return {
        "password_chars": len(body.password or ""),
        "password_bytes": len((body.password or "").encode("utf-8")),
    }

# ----------------------------
# Admin cleanup (Bearer admin key)
# ----------------------------
@app.post("/admin/cleanup-expired")
def cleanup_expired(req: Request):
    admin_key = os.environ.get("INBOXLY_ADMIN_KEY")
    if not admin_key:
        raise HTTPException(status_code=503, detail="INBOXLY_ADMIN_KEY not set on server")

    auth = req.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token>")

    token = auth.split(" ", 1)[1].strip()
    if token != admin_key:
        raise HTTPException(status_code=401, detail="Unauthorized")

    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:cleanup", limit=10, window_seconds=60)

    now = datetime.now(timezone.utc).isoformat()

    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) AS c FROM inboxes WHERE expires_at <= ?", (now,))
    inbox_count = int(cur.fetchone()["c"])

    cur.execute("DELETE FROM inboxes WHERE expires_at <= ?", (now,))
    conn.commit()
    conn.close()

    return {"deleted_inboxes": inbox_count, "timestamp": now}
