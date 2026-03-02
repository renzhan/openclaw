import type { IncomingMessage, ServerResponse } from "node:http";
import { buildAuthorizeUrl, resolveOAuthConfig, resolveRedirectUri } from "./oauth-config.js";
import { getAuthorizationToken } from "./oauth-service.js";
import { createOAuthSession, resolveOAuthSession, setSessionCookie } from "./oauth-session.js";
import { sendJson, sendMethodNotAllowed } from "./http-common.js";

const CALLBACK_PATH = "/api/v1/auth/callback";

// Paths exempt from the OAuth session gate — callback MUST be here
const EXEMPT_PREFIXES = [CALLBACK_PATH, "/assets/", "/favicon", "/_"];

/**
 * Gate: redirect unauthenticated browser requests to IAM login.
 * Returns true if the request was handled (redirect or 401 sent).
 */
export function enforceOAuthSession(req: IncomingMessage, res: ServerResponse): boolean {
  const cfg = resolveOAuthConfig();
  if (!cfg) return false;

  const url = new URL(req.url ?? "/", "http://localhost");
  const pathname = url.pathname;

  // Callback and static assets are always exempt — never redirect these
  if (EXEMPT_PREFIXES.some((p) => pathname === p || pathname.startsWith(p))) {
    return false;
  }

  const user = resolveOAuthSession(req);
  if (user) return false;

  const isBrowser = req.method === "GET" || req.method === "HEAD";
  if (!isBrowser) {
    sendJson(res, 401, { ok: false, error: "Unauthorized" });
    return true;
  }

  const host = req.headers.host ?? "localhost";
  const secure = isSecureRequest(req);
  const redirectUri = resolveRedirectUri(cfg, host, secure);

  // Only store pathname as state — never include query string to avoid
  // encoding ?code=...&state=... from a previous failed callback
  const state = encodeURIComponent(url.pathname);
  const iamUrl = buildAuthorizeUrl(cfg, redirectUri, state);

  res.statusCode = 302;
  res.setHeader("Location", iamUrl);
  res.setHeader("Cache-Control", "no-store");
  res.end();
  return true;
}

/**
 * Handle GET /api/v1/auth/callback?code=...&state=...
 *
 * Calls get_authorization_token (mirrors Python OAuthService.get_authorization_token),
 * creates a session cookie, then redirects back to the original page.
 *
 * Also handles POST for programmatic use: { code, redirect_uri? } → { ok, user }
 */
export async function handleOAuthCallbackRequest(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname !== CALLBACK_PATH) return false;

  if (req.method !== "GET" && req.method !== "POST") {
    sendMethodNotAllowed(res, "GET, POST");
    return true;
  }

  const cfg = resolveOAuthConfig();
  if (!cfg) {
    sendJson(res, 503, { ok: false, error: "OAuth not configured" });
    return true;
  }

  const host = req.headers.host ?? "localhost";
  const secure = isSecureRequest(req);
  const redirectUri = resolveRedirectUri(cfg, host, secure);

  if (req.method === "GET") {
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");

    if (!code) {
      res.statusCode = 400;
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end("Missing authorization code");
      return true;
    }

    // Mirrors Python: get_authorization_token(code, redirect_uri)
    const authResponse = await getAuthorizationToken(cfg, code, redirectUri);

    if (!authResponse.success || !authResponse.data) {
      // Show error page — do NOT redirect back to IAM (would cause infinite loop)
      res.statusCode = 200;
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.setHeader("Cache-Control", "no-store");
      res.end(buildErrorPage(authResponse.message));
      return true;
    }

    const sessionId = createOAuthSession(authResponse.data);
    setSessionCookie(res, sessionId, secure);

    // Write user data to localStorage via an intermediate HTML page, then redirect
    const returnTo = safeReturnTo(decodeState(state ?? ""));
    res.statusCode = 200;
    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Cache-Control", "no-store");
    res.end(buildLoginSuccessPage(authResponse.data, returnTo));
    return true;
  }

  // POST — programmatic
  const body = await readJsonBody(req);
  if (!body.ok) {
    sendJson(res, 400, { ok: false, error: body.error });
    return true;
  }

  const data = body.value as Record<string, unknown>;
  const code = typeof data["code"] === "string" ? data["code"] : null;
  const overrideRedirectUri =
    typeof data["redirect_uri"] === "string" ? data["redirect_uri"] : redirectUri;

  if (!code) {
    sendJson(res, 400, { ok: false, error: "Missing required parameter: code" });
    return true;
  }

  const authResponse = await getAuthorizationToken(cfg, code, overrideRedirectUri);
  if (!authResponse.success || !authResponse.data) {
    sendJson(res, 401, { ok: false, error: authResponse.message });
    return true;
  }

  const sessionId = createOAuthSession(authResponse.data);
  setSessionCookie(res, sessionId, secure);
  sendJson(res, 200, { ok: true, user: authResponse.data });
  return true;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function isSecureRequest(req: IncomingMessage): boolean {
  const proto = req.headers["x-forwarded-proto"];
  if (typeof proto === "string") return proto.toLowerCase() === "https";
  return (req.socket as { encrypted?: boolean }).encrypted === true;
}

function safeReturnTo(raw: string): string {
  if (!raw || raw.startsWith("//") || /^https?:\/\//i.test(raw)) return "/";
  return raw.startsWith("/") ? raw : "/";
}

function decodeState(state: string): string {
  try {
    const once = decodeURIComponent(state);
    if (/%[0-9a-fA-F]{2}/.test(once)) {
      try { return decodeURIComponent(once); } catch { return once; }
    }
    return once;
  } catch {
    return "/";
  }
}

async function readJsonBody(
  req: IncomingMessage,
): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > 65536) { resolve({ ok: false, error: "Body too large" }); req.destroy(); }
      else chunks.push(chunk);
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve({ ok: true, value: raw ? (JSON.parse(raw) as unknown) : {} });
      } catch { resolve({ ok: false, error: "Invalid JSON" }); }
    });
    req.on("error", () => resolve({ ok: false, error: "Read error" }));
  });
}

function buildErrorPage(message: string): string {
  const escaped = message.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Login Failed</title>
<style>body{font-family:sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;background:#f5f5f5}
.box{background:#fff;padding:2rem 3rem;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);text-align:center;max-width:400px}
h2{color:#d32f2f;margin-top:0}p{color:#555}a{color:#1976d2;text-decoration:none;font-weight:bold}</style>
</head><body><div class="box">
<h2>Login Failed</h2>
<p>${escaped}</p>
<p><a href="/">Try again</a></p>
</div></body></html>`;
}

function buildLoginSuccessPage(
  user: import("./oauth-service.js").AuthenticationData,
  returnTo: string,
): string {
  const payload = JSON.stringify({
    user_id: user.user_id,
    username: user.username,
    name: user.name ?? null,
    email: user.email ?? null,
    phone: user.phone ?? null,
    tenant_id: user.tenant_id,
    tenant_name: user.tenant_name ?? null,
    roles: user.roles,
    exp: user.exp,
    access_token: user.access_token,
  });
  // Escape for safe embedding inside a JS template literal
  const safePayload = payload
    .replace(/\\/g, "\\\\")
    .replace(/`/g, "\\`")
    .replace(/<\/script>/gi, "<\\/script>");
  const safeReturn = returnTo.replace(/'/g, "\\'");
  return [
    "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Logging in...</title></head>",
    "<body><script>",
    "try{localStorage.setItem('oclaw_oauth_user',`" + safePayload + "`);}catch(e){console.warn('localStorage write failed:',e);}",
    "window.location.replace('" + safeReturn + "');",
    "</script></body></html>",
  ].join("\n");
}
