from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import sqlite3
from pathlib import Path
import os
import time
from typing import Dict, List, Tuple

app = FastAPI(title="Inboxly API")

app.add_middleware(
    CORSMiddleware,
    # Keep this tight in production (your Vercel + localhost)
    allow_origins=[
        "http://localhost:3000",
        "https://inboxly-ten.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQLite DB (Render free tier = ephemeral disk, OK for MVP)
DB_PATH = Path(__file__).with_name("inboxly.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Enforce FK behavior in SQLite
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS inboxes (
            inbox_id TEXT PRIMARY KEY,
            address TEXT NOT NULL,
            expires_at TEXT NOT NULL
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

    # Indexes (Day 10 hardening)
    cur.execute(
        "CREATE INDEX IF NOT EXISTS idx_messages_inbox_received ON messages(inbox_id, received_at)"
    )
    cur.execute("CREATE INDEX IF NOT EXISTS idx_inboxes_expires ON inboxes(expires_at)")

    conn.commit()
    conn.close()


init_db()


# ---------------------------
# Rate limiting (Day 10)
# ---------------------------
# Very small in-memory limiter (good for MVP)
# NOTE: if you scale to multiple instances, move to Redis.
_rate_buckets: Dict[str, List[float]] = {}  # key -> list of request timestamps


def _rate_limit(key: str, limit: int, window_seconds: int) -> None:
    now = time.time()
    bucket = _rate_buckets.get(key, [])

    # Keep only timestamps within window
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
    # If behind a proxy, you’d read X-Forwarded-For. Keep simple for now.
    return req.client.host if req.client else "unknown"


# ---------------------------
# Expiry enforcement
# ---------------------------
def _require_active_inbox(inbox_id: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT expires_at FROM inboxes WHERE inbox_id = ?", (inbox_id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Inbox not found")

    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.now(timezone.utc) >= expires_at:
        # Cleanup expired inbox + its messages
        cur.execute("DELETE FROM inboxes WHERE inbox_id = ?", (inbox_id,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=410, detail="Inbox expired")

    conn.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/inbox")
def create_inbox(req: Request):
    # Rate limit: Create inbox = stricter
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:create_inbox", limit=20, window_seconds=60)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=15)

    inbox_id = str(uuid4())
    address = f"{inbox_id[:8]}@inboxly.dev"

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO inboxes (inbox_id, address, expires_at) VALUES (?, ?, ?)",
        (inbox_id, address, expires_at.isoformat()),
    )
    conn.commit()
    conn.close()

    return {
        "inbox_id": inbox_id,
        "address": address,
        "expires_at": expires_at.isoformat(),
        "plan": "free",
    }


@app.get("/v1/inbox/{inbox_id}/messages")
def list_messages(inbox_id: str, req: Request):
    # Rate limit: Read messages
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:list_messages", limit=60, window_seconds=60)

    _require_active_inbox(inbox_id)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, sender, subject, received_at, preview, body
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
            "body": r["body"],
        }
        for r in rows
    ]

    return {"inbox_id": inbox_id, "messages": messages}


@app.post("/v1/inbox/{inbox_id}/test-email")
def send_test_email(inbox_id: str, req: Request):
    # Rate limit: Write message
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:test_email", limit=60, window_seconds=60)

    _require_active_inbox(inbox_id)

    now = datetime.now(timezone.utc).isoformat()
    msg_id = str(uuid4())

    msg = {
        "id": msg_id,
        "from": "test@inboxly.dev",
        "subject": "Welcome to Inboxly (Test)",
        "received_at": now,
        "preview": "This is a simulated email stored in SQLite (Day 10).",
        "body": "Hi! This is a fake message stored in SQLite now. Rate limiting + cleanup endpoint added.",
    }

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO messages (id, inbox_id, sender, subject, received_at, preview, body)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            msg_id,
            inbox_id,
            msg["from"],
            msg["subject"],
            msg["received_at"],
            msg["preview"],
            msg["body"],
        ),
    )
    conn.commit()
    conn.close()

    return msg


# ---------------------------
# Admin cleanup endpoint (Day 10)
# ---------------------------
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

    # Optional: rate limit cleanup too
    ip = _client_ip(req)
    _rate_limit(key=f"{ip}:cleanup", limit=10, window_seconds=60)

    now = datetime.now(timezone.utc).isoformat()

    conn = get_db()
    cur = conn.cursor()

    # Count first (for reporting)
    cur.execute("SELECT COUNT(*) AS c FROM inboxes WHERE expires_at <= ?", (now,))
    inbox_count = int(cur.fetchone()["c"])

    # Deleting inboxes will cascade messages (FK ON DELETE CASCADE)
    cur.execute("DELETE FROM inboxes WHERE expires_at <= ?", (now,))
    conn.commit()
    conn.close()

    return {"deleted_inboxes": inbox_count, "timestamp": now}
