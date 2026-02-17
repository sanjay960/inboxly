from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import sqlite3
from pathlib import Path

app = FastAPI(title="Inboxly API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# SQLite DB (Day 8)
DB_PATH = Path(__file__).with_name("inboxly.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
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
            FOREIGN KEY (inbox_id) REFERENCES inboxes(inbox_id)
        )
        """
    )

    conn.commit()
    conn.close()


init_db()


def _require_active_inbox(inbox_id: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT expires_at FROM inboxes WHERE inbox_id = ?", (inbox_id,))
    row = cur.fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Inbox not found")

    # stored as ISO string with timezone (+00:00)
    expires_at = datetime.fromisoformat(row["expires_at"])

    if datetime.now(timezone.utc) >= expires_at:
        # cleanup expired inbox + its messages
        cur.execute("DELETE FROM messages WHERE inbox_id = ?", (inbox_id,))
        cur.execute("DELETE FROM inboxes WHERE inbox_id = ?", (inbox_id,))
        conn.commit()
        conn.close()
        raise HTTPException(status_code=410, detail="Inbox expired")

    conn.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/v1/inbox")
def create_inbox():
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
def list_messages(inbox_id: str):
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
def send_test_email(inbox_id: str):
    _require_active_inbox(inbox_id)

    now = datetime.now(timezone.utc).isoformat()
    msg_id = str(uuid4())

    msg = {
        "id": msg_id,
        "from": "test@inboxly.dev",
        "subject": "Welcome to Inboxly (Test)",
        "received_at": now,
        "preview": "This is a simulated email stored in SQLite (Day 8).",
        "body": "Hi! This is a fake message stored in SQLite now. If you restart the API, it should still be here.",
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
