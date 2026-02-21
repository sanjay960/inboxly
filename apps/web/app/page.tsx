"use client";

import { useEffect, useMemo, useState } from "react";

const STORAGE_KEY = "inboxly_current_inbox_v1";
const TOKEN_KEY = "inboxly_jwt_v1";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ||
  process.env.NEXT_PUBLIC_API_BASE_URL ||
  "http://127.0.0.1:8000";

type Plan = "free" | "pro";

type InboxResponse = {
  inbox_id: string;
  address: string;
  expires_at: string;
  plan: Plan;
};

type MessageListItem = {
  id: string;
  from: string;
  subject: string;
  received_at: string;
  preview: string;
};

type MessageDetail = {
  id: string;
  inbox_id: string;
  from: string;
  subject: string;
  received_at: string;
  body: string;
};

type AuthResponse = {
  token: string;
  user: { user_id: string; email: string; plan: Plan };
};

function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function setToken(token: string | null) {
  try {
    if (!token) localStorage.removeItem(TOKEN_KEY);
    else localStorage.setItem(TOKEN_KEY, token);
  } catch {
    // ignore
  }
}

function clearStoredInbox() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}

async function apiFetch(path: string, init: RequestInit = {}) {
  const token = getToken();
  const headers = new Headers(init.headers || {});
  if (token) headers.set("Authorization", `Bearer ${token}`);
  return fetch(`${API_BASE}${path}`, { ...init, headers });
}

export default function Home() {
  // Auth
  const [authEmail, setAuthEmail] = useState("test@example.com");
  const [authPassword, setAuthPassword] = useState("password123");
  const [me, setMe] = useState<{ email: string; plan: Plan } | null>(null);

  // Inbox + messages
  const [inbox, setInbox] = useState<InboxResponse | null>(null);
  const [messages, setMessages] = useState<MessageListItem[]>([]);
  const [selected, setSelected] = useState<MessageDetail | null>(null);

  const [loadingAuth, setLoadingAuth] = useState(false);
  const [loadingInbox, setLoadingInbox] = useState(false);
  const [loadingMsg, setLoadingMsg] = useState(false);

  const [error, setError] = useState<string | null>(null);
  const [expiredNotice, setExpiredNotice] = useState<string | null>(null);

  // Restore saved inbox (local metadata)
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return;
      const parsed: InboxResponse = JSON.parse(raw);
      setInbox(parsed);
    } catch {
      clearStoredInbox();
    }
  }, []);

  // Persist inbox metadata
  useEffect(() => {
    if (!inbox) {
      clearStoredInbox();
      setMessages([]);
      setSelected(null);
      return;
    }
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(inbox));
    } catch {
      // ignore
    }
  }, [inbox]);

  // Load /v1/me if token exists
  useEffect(() => {
    if (!getToken()) return;
    refreshMeAndRestore();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function refreshMe() {
    try {
      const res = await apiFetch("/v1/me");
      if (res.status === 401) {
        logout();
        return null;
      }
      if (!res.ok) return null;
      const data = await res.json();
      const out = { email: data.email as string, plan: data.plan as Plan };
      setMe(out);
      return out;
    } catch {
      return null;
    }
  }

  async function restoreActiveInboxFromServer(planHint?: Plan) {
    try {
      const res = await apiFetch("/v1/inboxes/active");
      if (res.status === 401) {
        logout();
        return;
      }
      if (!res.ok) return;
      const data = await res.json();
      const first = Array.isArray(data.inboxes) ? data.inboxes[0] : null;
      if (!first) return;

      setInbox({
        inbox_id: first.inbox_id,
        address: first.address,
        expires_at: first.expires_at,
        plan: planHint ?? me?.plan ?? "free",
      });
    } catch {
      // ignore
    }
  }

  async function refreshMeAndRestore() {
    const m = await refreshMe();
    if (m) await restoreActiveInboxFromServer(m.plan);
  }

  async function register() {
    setLoadingAuth(true);
    setError(null);
    setExpiredNotice(null);

    try {
      const res = await fetch(`${API_BASE}/v1/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: authEmail, password: authPassword }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.detail ?? `HTTP ${res.status}`);

      const out = data as AuthResponse;
      setToken(out.token);
      setMe({ email: out.user.email, plan: out.user.plan });

      // try restore inbox if any active
      await restoreActiveInboxFromServer(out.user.plan);
    } catch (e: any) {
      setError(e?.message ?? "Register failed");
    } finally {
      setLoadingAuth(false);
    }
  }

  async function login() {
    setLoadingAuth(true);
    setError(null);
    setExpiredNotice(null);

    try {
      const res = await fetch(`${API_BASE}/v1/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: authEmail, password: authPassword }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.detail ?? `HTTP ${res.status}`);

      const out = data as AuthResponse;
      setToken(out.token);
      setMe({ email: out.user.email, plan: out.user.plan });

      // restore active inbox after login
      await restoreActiveInboxFromServer(out.user.plan);
    } catch (e: any) {
      setError(e?.message ?? "Login failed");
    } finally {
      setLoadingAuth(false);
    }
  }

  function logout() {
    setToken(null);
    setMe(null);
    setInbox(null);
    setMessages([]);
    setSelected(null);
    setExpiredNotice(null);
    setError(null);
    clearStoredInbox();
  }

  // Countdown tick
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setTick((x) => x + 1), 1000);
    return () => clearInterval(t);
  }, []);

  const remainingSeconds = useMemo(() => {
    if (!inbox) return 0;
    const expiresMs = new Date(inbox.expires_at).getTime();
    return Math.max(0, Math.floor((expiresMs - Date.now()) / 1000));
  }, [inbox, tick]);

  const mmss = useMemo(() => {
    const m = Math.floor(remainingSeconds / 60);
    const s = remainingSeconds % 60;
    return `${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`;
  }, [remainingSeconds]);

  const expired = inbox !== null && remainingSeconds === 0;

  useEffect(() => {
    if (!inbox) return;
    if (expired) {
      setExpiredNotice("Inbox expired. Generate a new inbox.");
      setInbox(null);
      setMessages([]);
      setSelected(null);
      clearStoredInbox();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [expired]);

  async function generateInbox() {
    setLoadingInbox(true);
    setError(null);
    setExpiredNotice(null);

    try {
      const res = await apiFetch("/v1/inbox", { method: "POST" });

      if (res.status === 401) {
        logout();
        throw new Error("Unauthorized. Please login again.");
      }

      const data = await res.json().catch(() => ({}));

      if (res.status === 402) {
        throw new Error(data?.detail ?? "Plan limit reached");
      }

      if (!res.ok) throw new Error(data?.detail ?? `HTTP ${res.status}`);

      setInbox(data as InboxResponse);
      setMessages([]);
      setSelected(null);
    } catch (e: any) {
      setError(e?.message ?? "Failed to generate inbox");
    } finally {
      setLoadingInbox(false);
    }
  }

  async function deleteInbox() {
    if (!inbox) return;
    setError(null);

    try {
      const res = await apiFetch(`/v1/inbox/${inbox.inbox_id}`, { method: "DELETE" });

      if (res.status === 401) {
        logout();
        return;
      }

      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.detail ?? `HTTP ${res.status}`);

      // clear local state
      setInbox(null);
      setMessages([]);
      setSelected(null);
      clearStoredInbox();
    } catch (e: any) {
      setError(e?.message ?? "Failed to delete inbox");
    }
  }

  async function copyEmail() {
    if (!inbox) return;
    await navigator.clipboard.writeText(inbox.address);
  }

  function clearInboxLocal() {
    setInbox(null);
    setExpiredNotice(null);
    setError(null);
    setSelected(null);
    setMessages([]);
    clearStoredInbox();
  }

  async function fetchMessages(inboxId: string) {
    try {
      const res = await apiFetch(`/v1/inbox/${inboxId}/messages`);

      if (res.status === 410) {
        setExpiredNotice("Inbox expired (server). Generate a new inbox.");
        clearInboxLocal();
        return;
      }

      if (res.status === 401) {
        logout();
        return;
      }

      if (!res.ok) return;

      const data = await res.json();
      const list = Array.isArray(data.messages) ? (data.messages as MessageListItem[]) : [];
      setMessages(list);
    } catch {
      // ignore
    }
  }

  useEffect(() => {
    if (!inbox) return;

    fetchMessages(inbox.inbox_id);
    const interval = setInterval(() => fetchMessages(inbox.inbox_id), 10_000);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inbox?.inbox_id]);

  async function openMessage(messageId: string) {
    setLoadingMsg(true);
    setError(null);

    try {
      const res = await apiFetch(`/v1/message/${messageId}`);

      if (res.status === 410) {
        setExpiredNotice("Inbox expired (server). Generate a new inbox.");
        clearInboxLocal();
        return;
      }

      if (res.status === 401) {
        logout();
        return;
      }

      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.detail ?? `HTTP ${res.status}`);

      setSelected(data as MessageDetail);
    } catch (e: any) {
      setError(e?.message ?? "Failed to open message");
    } finally {
      setLoadingMsg(false);
    }
  }

  async function sendTestEmail() {
    if (!inbox) return;

    setError(null);

    try {
      const res = await apiFetch(`/v1/inbox/${inbox.inbox_id}/test-email`, { method: "POST" });

      if (res.status === 410) {
        setExpiredNotice("Inbox expired (server). Generate a new inbox.");
        clearInboxLocal();
        return;
      }

      if (res.status === 401) {
        logout();
        return;
      }

      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data?.detail ?? `HTTP ${res.status}`);

      fetchMessages(inbox.inbox_id);
    } catch (e: any) {
      setError(e?.message ?? "Failed to send test email");
    }
  }

  return (
    <main className="min-h-screen flex items-center justify-center bg-gray-100 p-6">
      <div className="bg-white p-8 rounded-2xl shadow-md w-full max-w-md space-y-5">
        <h1 className="text-2xl font-semibold text-center">Inboxly</h1>

        {expiredNotice && (
          <div className="bg-amber-50 text-amber-800 p-3 rounded-xl text-sm">
            {expiredNotice}
          </div>
        )}

        {!me ? (
          <div className="space-y-3">
            <div className="rounded-xl border p-3 space-y-2">
              <div className="text-sm font-medium">Login / Register</div>

              <input
                value={authEmail}
                onChange={(e) => setAuthEmail(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border text-sm"
                placeholder="Email"
                autoComplete="email"
              />
              <input
                value={authPassword}
                onChange={(e) => setAuthPassword(e.target.value)}
                className="w-full px-3 py-2 rounded-lg border text-sm"
                placeholder="Password (min 8)"
                type="password"
                autoComplete="current-password"
              />

              <div className="flex gap-2">
                <button
                  onClick={login}
                  disabled={loadingAuth}
                  className="flex-1 px-4 py-2 rounded-xl border hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingAuth ? "..." : "Login"}
                </button>
                <button
                  onClick={register}
                  disabled={loadingAuth}
                  className="flex-1 px-4 py-2 rounded-xl border hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingAuth ? "..." : "Register"}
                </button>
              </div>
            </div>

            <p className="text-xs text-gray-500 text-center">
              SaaS mode: JWT auth required to create inbox and read messages.
            </p>
          </div>
        ) : (
          <div className="rounded-xl border p-3 flex items-center justify-between">
            <div>
              <div className="text-sm font-medium break-words">{me.email}</div>
              <div className="text-xs text-gray-500">Plan: {me.plan}</div>
            </div>
            <button
              onClick={logout}
              className="px-3 py-1 rounded-lg border text-sm hover:bg-gray-50"
            >
              Logout
            </button>
          </div>
        )}

        {!inbox ? (
          <button
            onClick={generateInbox}
            disabled={loadingInbox || !me}
            className="w-full px-4 py-2 rounded-xl border hover:bg-gray-50 disabled:opacity-50"
            title={!me ? "Login first" : ""}
          >
            {loadingInbox ? "Generating..." : "Generate Inbox"}
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
                  disabled={loadingInbox}
                  className="px-3 py-1 rounded-lg border text-sm hover:bg-gray-50 disabled:opacity-50"
                >
                  {loadingInbox ? "..." : "New Inbox"}
                </button>

                <button
                  onClick={deleteInbox}
                  className="px-3 py-1 rounded-lg border text-sm hover:bg-gray-50"
                >
                  Delete
                </button>

                <button
                  onClick={clearInboxLocal}
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

              {selected && (
                <div className="border rounded-xl p-3 text-sm bg-white">
                  <div className="flex items-center justify-between gap-3">
                    <div className="font-semibold break-words">{selected.subject}</div>
                    <button
                      onClick={() => setSelected(null)}
                      className="px-2 py-1 border rounded text-xs hover:bg-gray-50"
                    >
                      Close
                    </button>
                  </div>

                  <div className="mt-2 text-xs text-gray-600">From: {selected.from}</div>
                  <div className="text-xs text-gray-600">
                    Received: {new Date(selected.received_at).toLocaleString()}
                  </div>

                  <div className="mt-3 whitespace-pre-wrap text-sm">
                    {loadingMsg ? "Loading..." : selected.body}
                  </div>
                </div>
              )}

              {messages.length === 0 ? (
                <div className="text-xs text-gray-500">
                  No messages yet… (auto-refresh every 10s)
                </div>
              ) : (
                <div className="space-y-2 max-h-56 overflow-y-auto">
                  {messages.map((msg) => (
                    <button
                      key={msg.id}
                      onClick={() => openMessage(msg.id)}
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
          SaaS mode: JWT + active inbox restore + preview list + open message + delete inbox + admin tools.
        </p>
      </div>
    </main>
  );
}