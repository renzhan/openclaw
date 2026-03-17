import { randomBytes } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import type { AuthenticationData } from "./oauth-service.js";

const SESSION_COOKIE = "oclaw_oauth_session";
const SESSION_TTL_MS = 8 * 60 * 60 * 1000; // 8 hours

type OAuthSession = {
  user: AuthenticationData;
  expiresAt: number;
};

const sessions = new Map<string, OAuthSession>();

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (s.expiresAt <= now) sessions.delete(id);
  }
}, 15 * 60 * 1000).unref();

export function createOAuthSession(user: AuthenticationData): string {
  const id = randomBytes(32).toString("hex");
  sessions.set(id, { user, expiresAt: Date.now() + SESSION_TTL_MS });
  return id;
}

export function resolveOAuthSession(req: IncomingMessage): AuthenticationData | null {
  const id = parseCookie(req, SESSION_COOKIE);
  if (!id) return null;
  const session = sessions.get(id);
  if (!session || session.expiresAt <= Date.now()) {
    if (session) sessions.delete(id);
    return null;
  }
  return session.user;
}

export function setSessionCookie(res: ServerResponse, sessionId: string, secure: boolean): void {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  const parts = [
    `${SESSION_COOKIE}=${sessionId}`,
    `Max-Age=${maxAge}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
  ];
  if (secure) parts.push("Secure");
  res.setHeader("Set-Cookie", parts.join("; "));
}

export function clearSessionCookie(res: ServerResponse): void {
  res.setHeader("Set-Cookie", `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax`);
}

function parseCookie(req: IncomingMessage, name: string): string | null {
  const header = req.headers.cookie ?? "";
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k?.trim() === name) return decodeURIComponent(rest.join("=").trim());
  }
  return null;
}
