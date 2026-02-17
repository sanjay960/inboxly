"use client";

import { useEffect, useMemo, useState } from "react";

const STORAGE_KEY = "inboxly_current_inbox_v1";

type InboxResponse = {
  inbox_id: string;
  address: string;
  expires_at: string;
  plan: "free" | "pro";
};

type Message = {
  id: string;
  from: string;
  subject: string;
  received_at: string;
  preview: string;
  body: string;
};

export default function Home() {
  const [inbox, setInbox] = useState<InboxResponse | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [selected, setSelected] = useState<Message | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Day 7: track whether the last inbox expired (for UI)
  const [expiredNotice, setExpiredNotice] = useState<string | null>(null);

  // Restore saved inbox on first load
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const parsed: InboxResponse = JSON.parse(raw);
      setInbox(parsed);
    } catch {
      localStorage.removeItem(STORAGE_KEY);
    }
  }, []);

  // Save inbox whenever it changes
  useEffect(() => {
    if (!inbox) {
      localStorage.removeItem(STORAGE_KEY);
      setMessages([]);
      setSelected(null);
      return;
    }
    localStorage.setItem(STORAGE_KEY, JSON.stringify(inbox));
  }, [inbox]);

  // Tick every second to update countdown
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const remainingSeconds = useMemo(() => {
    if (!inbox) return 0;
    const expiresMs = new Date(inbox.expires_at).getTime();
    const nowMs = Date.now();
    return Math.max(0, Math.floor((expiresMs - nowMs) / 1000));
  }, [inbox, tick]);

  const mmss = useMemo(() => {
    const m = Math.floor(remainingSeconds / 60);
    const s = remainingSeconds % 60;
    return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }, [remainingSeconds]);

  const expired = inbox !== null && remainingSeconds === 0;

  // If local timer reaches 0, clear inbox (Day 7)
  useEffect(() => {
    if (!inbox) return;
    if (expired) {
      setExpiredNotice("Inbox expired. Generate a new inbox.");
      setInbox(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expired]);

  async function generateInbox() {
    setLoading(true);
    setError(null);
    setExpiredNotice(null);

    try {
      const res = await fetch("http://127.0.0.1:8000/v1/inbox", {
        method: "POST",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data: InboxResponse = await res.json();

      setInbox(data);
      setSelected(null);
      setMessages([]);
    } catch (e: any) {
      setError(e?.message ?? "Unknown error");
    } finally {
      setLoading(false);
    }
  }

  async function copyEmail() {
    if (!inbox) return;
    await navigator.clipboard.writeText(inbox.address);
  }

  function clearInbox() {
    setInbox(null);
    setExpiredNotice(null);
    setError(null);
  }

  async function fetchMessages(id: string) {
    try {
      const res = await fetch(`http://127.0.0.1:8000/v1/inbox/${id}/messages`);

      // Day 7: handle expiry from backend
      if (res.status === 410) {
        setExpiredNotice("Inbox expired (server). Generate a new inbox.");
        setInbox(null);
        return;
      }

      if (!res.ok) return;

      const data = await res.json();
      setMessages(Array.isArray(data.messages) ? data.messages : []);
    } catch {
      // ignore network errors for now
    }
  }

  // Auto-fetch messages when inbox exists, refresh every 5s
  useEffect(() => {
    if (!inbox) return;

    fetchMessages(inbox.inbox_id);
    const interval = setInterval(() => fetchMessages(inbox.inbox_id), 5000);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inbox]);

  async function sendTestEmail() {
    if (!inbox) return;

    setError(null);

    try {
      const res = await fetch(
        `http://127.0.0.1:8000/v1/inbox/${inbox.inbox_id}/test-email`,
        { method: "POST" }
      );

      // Day 7: handle expiry from backend
      if (res.status === 410) {
        setExpiredNotice("Inbox expired (server). Generate a new inbox.");
        setInbox(null);
        return;
      }

      if (!res.ok) throw new Error(`HTTP ${res.status}`);

      fetchMessages(inbox.inbox_id);
    } catch (e: any) {
      setError(e?.message ?? "Failed to send test email");
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center bg-gray-100 p-6">
      <div className="bg-white p-8 rounded-2xl shadow-md w-full max-w-md space-y-5">
        <h1 className="text-2xl font-semibold text-center">Inboxly</h1>

        {/* Notices */}
        {expiredNotice && (
          <div className="bg-amber-50 text-amber-800 p-3 rounded-xl text-sm">
            {expiredNotice}
          </div>
        )}

        {!inbox ? (
          <button
            onClick={generateInbox}
            disabled={loading}
            className="w-full px-4 py-2 rounded-xl border hover:bg-gray-50 disabled:opacity-50"
          >
            {loading ? "Generating..." : "Generate Inbox"}
          </button>
        ) : (
          <div className="space-y-3">
            <div className="rounded-xl border p-3">
              <div className="text-xs text-gray-500">Your temporary email</div>
              <div className="font-mono text-sm break-words">{inbox.address}</div>

              <div className="mt-2 flex flex-wrap gap-2">
                <button
                  onClick={copyEmail}
                  className="px-3 py-1 rounded-lg border text-sm hover:bg-gray-50"
                >
                  Copy
                </button>

                <button
                  onClick={generateInbox}
                  disabled={loading}
                  className="px-3 py-1 rounded-lg border text-sm hover:bg-gray-50 disabled:opacity-50"
                >
                  {loading ? "..." : "New Inbox"}
                </button>

                <button
                  onClick={clearInbox}
                  className="px-3 py-1 rounded-lg border text-sm hover:bg-gray-50"
                >
                  Clear
                </button>
              </div>
            </div>

            <div className="rounded-xl p-3 text-sm bg-gray-50">
              <div className="font-medium">Expires in</div>
              <div className="font-mono text-lg">{mmss}</div>
            </div>

            {/* Messages */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-medium">Messages</h2>
                <button
                  onClick={sendTestEmail}
                  className="px-2 py-1 border rounded text-xs hover:bg-gray-50"
                >
                  Send Test Email
                </button>
              </div>

              {/* Selected message details */}
              {selected && (
                <div className="border rounded-xl p-3 text-sm bg-white">
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-semibold break-words">
                      {selected.subject}
                    </div>
                    <button
                      onClick={() => setSelected(null)}
                      className="px-2 py-1 border rounded text-xs hover:bg-gray-50"
                    >
                      Close
                    </button>
                  </div>

                  <div className="mt-2 text-xs text-gray-600">
                    From: {selected.from}
                  </div>
                  <div className="text-xs text-gray-600">
                    Received: {new Date(selected.received_at).toLocaleString()}
                  </div>

                  <div className="mt-3 whitespace-pre-wrap text-sm">
                    {selected.body}
                  </div>
                </div>
              )}

              {messages.length === 0 ? (
                <div className="text-xs text-gray-500">No messages yet…</div>
              ) : (
                <div className="space-y-2 max-h-56 overflow-y-auto">
                  {messages.map((msg) => (
                    <button
                      key={msg.id}
                      onClick={() => setSelected(msg)}
                      className="w-full text-left border rounded p-2 text-xs bg-gray-50 hover:bg-gray-100"
                      title="Click to open"
                    >
                      <div className="font-medium">{msg.subject}</div>
                      <div className="text-gray-500">From: {msg.from}</div>
                      <div className="text-gray-500">
                        Received: {new Date(msg.received_at).toLocaleString()}
                      </div>
                      <div className="mt-1">{msg.preview}</div>
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

        {error && (
          <div className="bg-red-50 text-red-700 p-3 rounded-xl text-sm">
            Error: {error}
          </div>
        )}

        <p className="text-xs text-gray-500 text-center">
          Day 7: expiry enforced (410 Gone) + auto-clear.
        </p>
      </div>
    </main>
  );
}
