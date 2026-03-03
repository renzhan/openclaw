import type { IncomingMessage, ServerResponse } from "node:http";
import { resolveOAuthConfig } from "./oauth-config.js";
import { loginWithCredentials } from "./oauth-service.js";
import { createOAuthSession, resolveOAuthSession, setSessionCookie } from "./oauth-session.js";
import { sendJson, sendMethodNotAllowed } from "./http-common.js";

const LOGIN_PATH = "/api/v1/auth/login";
const LOGIN_PAGE_PATH = "/login";

// Paths that never require an OAuth session
const EXEMPT_PREFIXES = [LOGIN_PATH, LOGIN_PAGE_PATH, "/assets/", "/favicon", "/_"];

// ── Session gate ──────────────────────────────────────────────────────────────

/**
 * Gate: redirect unauthenticated browser requests to the custom login page.
 * Returns true if the request was handled.
 */
export function enforceOAuthSession(req: IncomingMessage, res: ServerResponse): boolean {
  const cfg = resolveOAuthConfig();
  if (!cfg) return false;

  const url = new URL(req.url ?? "/", "http://localhost");
  const pathname = url.pathname;

  if (EXEMPT_PREFIXES.some((p) => pathname === p || pathname.startsWith(p))) return false;

  const user = resolveOAuthSession(req);
  if (user) return false;

  const isBrowser = req.method === "GET" || req.method === "HEAD";
  if (!isBrowser) {
    sendJson(res, 401, { ok: false, error: "Unauthorized" });
    return true;
  }

  // Redirect to login page, pass original path as `next`
  const next = encodeURIComponent(url.pathname);
  res.statusCode = 302;
  res.setHeader("Location", `${LOGIN_PAGE_PATH}?next=${next}`);
  res.setHeader("Cache-Control", "no-store");
  res.end();
  return true;
}

// ── Login page (GET /login) ───────────────────────────────────────────────────

export function handleLoginPageRequest(req: IncomingMessage, res: ServerResponse): boolean {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname !== LOGIN_PAGE_PATH) return false;

  if (req.method !== "GET" && req.method !== "HEAD") {
    sendMethodNotAllowed(res, "GET");
    return true;
  }

  const cfg = resolveOAuthConfig();
  if (!cfg) {
    sendJson(res, 503, { ok: false, error: "OAuth not configured" });
    return true;
  }

  const next = url.searchParams.get("next") ?? "/";
  res.statusCode = 200;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(buildLoginPage(next));
  return true;
}

// ── Login API (POST /api/v1/auth/login) ───────────────────────────────────────

export async function handleLoginRequest(
  req: IncomingMessage,
  res: ServerResponse,
): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (url.pathname !== LOGIN_PATH) return false;

  if (req.method !== "POST") {
    sendMethodNotAllowed(res, "POST");
    return true;
  }

  const cfg = resolveOAuthConfig();
  if (!cfg) {
    sendJson(res, 503, { ok: false, error: "OAuth not configured" });
    return true;
  }

  const body = await readJsonBody(req);
  if (!body.ok) {
    sendJson(res, 400, { ok: false, error: body.error });
    return true;
  }

  const data = body.value as Record<string, unknown>;
  const username = typeof data["username"] === "string" ? data["username"].trim() : "";
  const password = typeof data["password"] === "string" ? data["password"] : "";

  if (!username || !password) {
    sendJson(res, 400, { ok: false, error: "username and password are required" });
    return true;
  }

  const authResponse = await loginWithCredentials(cfg, username, password);

  if (!authResponse.success || !authResponse.data) {
    sendJson(res, 401, { ok: false, error: authResponse.message || "Login failed" });
    return true;
  }

  const secure = isSecureRequest(req);
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

async function readJsonBody(
  req: IncomingMessage,
): Promise<{ ok: true; value: unknown } | { ok: false; error: string }> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > 65536) {
        resolve({ ok: false, error: "Body too large" });
        req.destroy();
      } else {
        chunks.push(chunk);
      }
    });
    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve({ ok: true, value: raw ? (JSON.parse(raw) as unknown) : {} });
      } catch {
        resolve({ ok: false, error: "Invalid JSON" });
      }
    });
    req.on("error", () => resolve({ ok: false, error: "Read error" }));
  });
}

// ── Login page HTML ───────────────────────────────────────────────────────────

function buildLoginPage(next: string): string {
  const safeNext = next.replace(/'/g, "\\'").replace(/</g, "&lt;");
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign In</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f0f2f5;display:flex;align-items:center;justify-content:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:2.5rem 2rem;width:100%;max-width:380px}
h1{font-size:1.4rem;font-weight:600;color:#111;margin-bottom:1.5rem;text-align:center}
.field{display:flex;flex-direction:column;gap:6px;margin-bottom:1rem}
label{font-size:.85rem;font-weight:500;color:#444}
input{border:1px solid #d1d5db;border-radius:8px;padding:.6rem .8rem;font-size:.95rem;outline:none;transition:border-color .15s}
input:focus{border-color:#4f46e5}
.btn{width:100%;padding:.7rem;background:#4f46e5;color:#fff;border:none;border-radius:8px;font-size:1rem;font-weight:500;cursor:pointer;margin-top:.5rem;transition:background .15s}
.btn:hover{background:#4338ca}
.btn:disabled{background:#a5b4fc;cursor:not-allowed}
.error{color:#dc2626;font-size:.85rem;margin-top:.75rem;text-align:center;min-height:1.2em}
</style>
</head>
<body>
<div class="card">
  <h1>Sign In</h1>
  <form id="form">
    <div class="field">
      <label for="username">Username</label>
      <input id="username" name="username" type="text" autocomplete="username" required autofocus />
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password" required />
    </div>
    <button class="btn" type="submit" id="btn">Sign In</button>
    <div class="error" id="err"></div>
  </form>
</div>
<script>
(function(){
  var next = '${safeNext}';
  var form = document.getElementById('form');
  var btn = document.getElementById('btn');
  var err = document.getElementById('err');
  form.addEventListener('submit', function(e){
    e.preventDefault();
    err.textContent = '';
    btn.disabled = true;
    btn.textContent = 'Signing in...';
    var username = document.getElementById('username').value.trim();
    var password = document.getElementById('password').value;
    fetch('${LOGIN_PATH}', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({username: username, password: password})
    })
    .then(function(r){ return r.json(); })
    .then(function(data){
      if(data.ok && data.user){
        try{ localStorage.setItem('oclaw_oauth_user', JSON.stringify(data.user)); }catch(e){}
        var dest = decodeURIComponent(next) || '/';
        if(!dest.startsWith('/')) dest = '/';
        window.location.replace(dest);
      } else {
        err.textContent = data.error || 'Login failed';
        btn.disabled = false;
        btn.textContent = 'Sign In';
      }
    })
    .catch(function(){
      err.textContent = 'Network error, please try again';
      btn.disabled = false;
      btn.textContent = 'Sign In';
    });
  });
})();
</script>
</body>
</html>`;
}
