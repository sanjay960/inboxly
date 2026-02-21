from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import os
import time
from typing import Dict, List, Optional

import jwt
from passlib.context import CryptContext

import psycopg
from psycopg.rows import dict_row

# ----------------------------
# Config
# ----------------------------
DATABASE_URL = os.environ.get("DATABASE_URL", "")
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
# DB helpers (Postgres / Neon)
# ----------------------------
def _require_db():
    if not DATABASE_URL:
        raise HTTPException(status_code=503, detail="DATABASE_URL not set on server")

def get_db():
    _require_db()
    # Neon requires SSL; the provided URL usually includes sslmode=require.
    # We use dict_row so rows behave like dicts (like sqlite Row).
    conn = psycopg.connect(DATABASE_URL, row_factory=dict_row)
    return conn

def init_db():
    _require_db()
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    plan TEXT NOT NULL DEFAULT 'free',
                    created_at TIMESTAMPTZ NOT NULL
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS inboxes (
                    inbox_id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
                    address TEXT NOT NULL,
                    expires_at TIMESTAMPTZ NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL
                );
                """
            )

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    inbox_id TEXT NOT NULL REFERENCES inboxes(inbox_id) ON DELETE CASCADE,
                    sender TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    received_at TIMESTAMPTZ NOT NULL,
                    preview TEXT NOT NULL,
                    body TEXT NOT NULL
                );
                """
            )

            # Indexes
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_inboxes_user ON inboxes(user_id);")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_inboxes_expires ON inboxes(expires_at);")
            cur.execute(
                "CREATE INDEX IF NOT EXISTS idx_messages_inbox_received ON messages(inbox_id, received_at);"
            )

        conn.commit()

@app.on_event("startup")
def startup():
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
# Password helpers (bcrypt safety)
# ----------------------------
def _normalize_password(raw: str) -> str:
    pw = (raw or "").strip()

    if len(pw) < 8:
        raise HTTPException(status_code=400, detail="Password too short (min 8)")

    # bcrypt limit: 72 BYTES
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

def _get_user(user_id: str) -> dict:
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, email, plan, created_at FROM users WHERE user_id = %s",
                (user_id,),
            )
            row = cur.fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return row

# ----------------------------
# Inbox helpers
# ----------------------------
def _require_active_inbox_owned(inbox_id: str, user_id: str):
    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, expires_at FROM inboxes WHERE inbox_id = %s",
                (inbox_id,),
            )
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Inbox not found")

            if row["user_id"] != user_id:
                raise HTTPException(status_code=403, detail="Forbidden")

            expires_at: datetime = row["expires_at"]
            if datetime.now(timezone.utc) >= expires_at:
                # delete inbox -> cascade messages
                cur.execute("DELETE FROM inboxes WHERE inbox_id = %s", (inbox_id,))
                conn.commit()
                raise HTTPException(status_code=410, detail="Inbox expired")

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

    try:
        pw_hash = pwd_context.hash(pw)
    except ValueError as e:
        pw_bytes = len(pw.encode("utf-8"))
        raise HTTPException(status_code=400, detail=f"bcrypt rejected password ({pw_bytes} bytes): {str(e)}")

    user_id = str(uuid4())
    created_at = datetime.now(timezone.utc)

    try:
        with get_db() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO users (user_id, email, password_hash, plan, created_at)
                    VALUES (%s, %s, %s, 'free', %s)
                    """,
                    (user_id, body.email.lower().strip(), pw_hash, created_at),
                )
            conn.commit()
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="Email already registered")

    token = _create_token(user_id)
    return {"token": token, "user": {"user_id": user_id, "email": body.email, "plan": "free"}}

@app.post("/v1/auth/login")
def login(body: AuthBody, req: Request):
    ip = _client_ip(req)
    _rate_limit(f"{ip}:login", limit=20, window_seconds=60)

    pw = _normalize_password(body.password)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, password_hash, plan FROM users WHERE email = %s",
                (body.email.lower().strip(),),
            )
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    try:
        ok = pwd_context.verify(pw, row["password_hash"])
    except ValueError as e:
        pw_bytes = len(pw.encode("utf-8"))
        raise HTTPException(status_code=400, detail=f"bcrypt rejected password ({pw_bytes} bytes): {str(e)}")

    if not ok:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = _create_token(row["user_id"])
    return {"token": token, "user": {"user_id": row["user_id"], "email": body.email, "plan": row["plan"]}}

@app.get("/v1/me")
def me(req: Request):
    user_id = _get_user_id_from_auth(req)
    u = _get_user(user_id)
    return {"user_id": u["user_id"], "email": u["email"], "plan": u["plan"], "created_at": u["created_at"].isoformat()}

# ----------------------------
# Inboxes
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

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS c FROM inboxes WHERE user_id = %s AND expires_at > %s",
                (user_id, now),
            )
            active = int(cur.fetchone()["c"])

            if active >= max_active:
                raise HTTPException(status_code=402, detail=f"Plan limit reached: max {max_active} active inbox(es)")

            inbox_id = str(uuid4())
            address = f"{inbox_id[:8]}@inboxly.dev"

            cur.execute(
                """
                INSERT INTO inboxes (inbox_id, user_id, address, expires_at, created_at)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (inbox_id, user_id, address, expires_at, now),
            )
        conn.commit()

    return {"inbox_id": inbox_id, "address": address, "expires_at": expires_at.isoformat(), "plan": plan}


@app.get("/v1/inboxes/active")
def list_active_inboxes(req: Request):
    user_id = _get_user_id_from_auth(req)
    now = datetime.now(timezone.utc)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT inbox_id, address, expires_at
                FROM inboxes
                WHERE user_id = %s AND expires_at > %s
                ORDER BY created_at DESC
                LIMIT 10
                """,
                (user_id, now),
            )
            rows = cur.fetchall()

    inboxes = [
        {
            "inbox_id": r["inbox_id"],
            "address": r["address"],
            "expires_at": r["expires_at"].isoformat(),
        }
        for r in rows
    ]

    return {"inboxes": inboxes}


@app.get("/v1/inbox/{inbox_id}/messages")
def list_messages(inbox_id: str, req: Request):
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:list_messages", limit=60, window_seconds=60)

    user_id = _get_user_id_from_auth(req)
    _require_active_inbox_owned(inbox_id, user_id)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, sender, subject, received_at, preview
                FROM messages
                WHERE inbox_id = %s
                ORDER BY received_at DESC
                """,
                (inbox_id,),
            )
            rows = cur.fetchall()

    messages = [
        {
            "id": r["id"],
            "from": r["sender"],
            "subject": r["subject"],
            "received_at": r["received_at"].isoformat(),
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

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    m.id,
                    m.inbox_id,
                    m.sender,
                    m.subject,
                    m.received_at,
                    m.body,
                    i.user_id AS owner_user_id,
                    i.expires_at AS inbox_expires_at
                FROM messages m
                JOIN inboxes i ON i.inbox_id = m.inbox_id
                WHERE m.id = %s
                """,
                (message_id,),
            )
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Message not found")

            if row["owner_user_id"] != user_id:
                raise HTTPException(status_code=403, detail="Forbidden")

            expires_at: datetime = row["inbox_expires_at"]
            if datetime.now(timezone.utc) >= expires_at:
                cur.execute("DELETE FROM inboxes WHERE inbox_id = %s", (row["inbox_id"],))
                conn.commit()
                raise HTTPException(status_code=410, detail="Inbox expired")

    return {
        "id": row["id"],
        "inbox_id": row["inbox_id"],
        "from": row["sender"],
        "subject": row["subject"],
        "received_at": row["received_at"].isoformat(),
        "body": row["body"],
    }

@app.post("/v1/inbox/{inbox_id}/test-email")
def send_test_email(inbox_id: str, req: Request):
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:test_email", limit=60, window_seconds=60)

    user_id = _get_user_id_from_auth(req)
    _require_active_inbox_owned(inbox_id, user_id)

    now = datetime.now(timezone.utc)
    msg_id = str(uuid4())

    msg = {
        "id": msg_id,
        "from": "test@inboxly.dev",
        "subject": "Welcome to Inboxly (Test)",
        "received_at": now,
        "preview": "Message stored in your user-owned inbox.",
        "body": "Hi! This is a fake message for testing.",
    }

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO messages (id, inbox_id, sender, subject, received_at, preview, body)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (msg_id, inbox_id, msg["from"], msg["subject"], now, msg["preview"], msg["body"]),
            )
        conn.commit()

    return msg

@app.delete("/v1/inbox/{inbox_id}")
def delete_inbox(inbox_id: str, req: Request):
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:delete_inbox", limit=30, window_seconds=60)

    user_id = _get_user_id_from_auth(req)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM inboxes WHERE inbox_id = %s", (inbox_id,))
            row = cur.fetchone()

            if not row:
                raise HTTPException(status_code=404, detail="Inbox not found")

            if row["user_id"] != user_id:
                raise HTTPException(status_code=403, detail="Forbidden")

            cur.execute("DELETE FROM inboxes WHERE inbox_id = %s", (inbox_id,))
        conn.commit()

    return {"deleted": True, "inbox_id": inbox_id}

# ----------------------------
# Admin cleanup
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

    now = datetime.now(timezone.utc)

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) AS c FROM inboxes WHERE expires_at <= %s", (now,))
            inbox_count = int(cur.fetchone()["c"])
            cur.execute("DELETE FROM inboxes WHERE expires_at <= %s", (now,))
        conn.commit()

    return {"deleted_inboxes": inbox_count, "timestamp": now.isoformat()}


@app.post("/admin/set-plan")
def admin_set_plan(req: Request, email: str, plan: str):
    admin_key = os.environ.get("INBOXLY_ADMIN_KEY")
    if not admin_key:
        raise HTTPException(status_code=503, detail="INBOXLY_ADMIN_KEY not set on server")

    auth = req.headers.get("authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token>")

    token = auth.split(" ", 1)[1].strip()
    if token != admin_key:
        raise HTTPException(status_code=401, detail="Unauthorized")

    plan = plan.strip().lower()
    if plan not in ("free", "pro"):
        raise HTTPException(status_code=400, detail="Invalid plan. Use 'free' or 'pro'.")

    email_norm = email.strip().lower()
    if not email_norm:
        raise HTTPException(status_code=400, detail="Email required")

    with get_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET plan = %s WHERE email = %s RETURNING user_id, email, plan",
                (plan, email_norm),
            )
            row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    return {"updated": True, "user": row}

