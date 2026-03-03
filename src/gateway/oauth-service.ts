import { createPublicKey, createVerify } from "node:crypto";
import type { OAuthConfig } from "./oauth-config.js";

// ── Types ─────────────────────────────────────────────────────────────────────

export type AuthenticationData = {
  user_id: string;
  username: string;
  name?: string;
  email?: string;
  phone?: string;
  tenant_id: string;
  tenant_name?: string;
  roles: string[];
  exp: number;
  access_token: string;
};

export type AuthResponse = {
  success: boolean;
  code: number;
  message: string;
  data: AuthenticationData | null;
};

function emptyAuthResponse(): AuthResponse {
  return { success: false, code: 0, message: "", data: null };
}

// ── JWKS cache ────────────────────────────────────────────────────────────────

let _jwksCache: Record<string, unknown> | null = null;

// ── Password login ────────────────────────────────────────────────────────────

/**
 * Login with username + password via POST /platform/v1/users/login.
 * Returns the access_token on success, or throws with a user-facing message.
 */
async function loginWithPassword(
  cfg: OAuthConfig,
  username: string,
  password: string,
): Promise<string> {
  const url = `${cfg.IAM_HOST}/platform/v1/users/login`;
  console.log("[oauth] loginWithPassword →", url);

  const response = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: cfg.AUTHORIZATION,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
    signal: AbortSignal.timeout(cfg.REQUEST_TIMEOUT),
  });

  const data = (await response.json()) as Record<string, unknown>;
  const code = data["code"];

  if (code !== 0) {
    const msg = typeof data["msg"] === "string" ? data["msg"] : "Invalid username or password";
    console.error("[oauth] Login failed, code:", code, msg);
    throw new Error(msg);
  }

  const tokenData = data["data"] as Record<string, unknown>;
  const accessToken = String(tokenData["access_token"] ?? "");
  if (!accessToken) throw new Error("No access_token in login response");

  console.log("[oauth] Login successful for:", username);
  return accessToken;
}

// ── User info ─────────────────────────────────────────────────────────────────

type UserInfoData = {
  id: string;
  userName?: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  contactNumber?: string;
  companyCode?: string;
  userRoles?: Array<{ id?: string; name?: string }>;
};

/**
 * Fetch user profile via GET /user-info with Bearer token.
 */
async function fetchUserInfo(cfg: OAuthConfig, accessToken: string): Promise<UserInfoData> {
  const url = `${cfg.IAM_HOST}/user-info`;
  console.log("[oauth] fetchUserInfo →", url);

  const response = await fetch(url, {
    method: "GET",
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(cfg.REQUEST_TIMEOUT),
  });

  const data = (await response.json()) as Record<string, unknown>;
  const code = data["code"];

  if (code !== 0) {
    const msg = typeof data["msg"] === "string" ? data["msg"] : "Failed to fetch user info";
    console.error("[oauth] fetchUserInfo failed, code:", code, msg);
    throw new Error(msg);
  }

  return data["data"] as UserInfoData;
}

// ── JWT helpers (kept for token expiry extraction) ────────────────────────────

function b64urlDecode(s: string): string {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
}

function extractJwtExp(token: string): number {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return 0;
    const payload = JSON.parse(b64urlDecode(parts[1])) as Record<string, unknown>;
    return typeof payload["exp"] === "number" ? payload["exp"] : 0;
  } catch {
    return 0;
  }
}

// ── JWKS / JWT verify (kept for optional token verification) ──────────────────

async function getJwks(cfg: OAuthConfig): Promise<Record<string, unknown> | null> {
  if (_jwksCache) return _jwksCache;
  try {
    const url = `${cfg.IAM_HOST}${cfg.JWKS_URL}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(cfg.REQUEST_TIMEOUT) });
    if (response.status === 200) {
      _jwksCache = (await response.json()) as Record<string, unknown>;
      return _jwksCache;
    }
    console.error("[oauth] Failed to fetch JWKS:", response.status);
  } catch (e) {
    console.error("[oauth] Get JWKS error:", e);
  }
  return null;
}

function jwkToPem(jwk: Record<string, string>): string {
  const pubKey = createPublicKey({ key: { kty: "RSA", e: jwk["e"], n: jwk["n"] }, format: "jwk" });
  return pubKey.export({ type: "spki", format: "pem" }) as string;
}

function verifyJwtSignature(token: string, pem: string): void {
  const parts = token.split(".");
  const signingInput = `${parts[0]}.${parts[1]}`;
  const sigB64 = parts[2].replace(/-/g, "+").replace(/_/g, "/");
  const sig = Buffer.from(sigB64 + "=".repeat((4 - (sigB64.length % 4)) % 4), "base64");
  const verify = createVerify("RSA-SHA256");
  verify.update(signingInput);
  if (!verify.verify(pem, sig)) throw new Error("JWT signature verification failed");
}

// ── Main entry point ──────────────────────────────────────────────────────────

/**
 * Authenticate with username + password:
 * 1. POST /platform/v1/users/login → access_token
 * 2. GET /user-info → user profile
 * 3. Optionally verify JWT signature if JWKS available
 * Returns AuthResponse with AuthenticationData shaped for oclaw_oauth_user.
 */
export async function loginWithCredentials(
  cfg: OAuthConfig,
  username: string,
  password: string,
): Promise<AuthResponse> {
  const authResponse = emptyAuthResponse();

  try {
    // Step 1: password login → access_token
    const accessToken = await loginWithPassword(cfg, username, password);

    // Step 2: fetch user profile
    const userInfo = await fetchUserInfo(cfg, accessToken);

    // Step 3: optional JWT signature verify
    if (cfg.JWT_VERIFY_SIGNATURE) {
      try {
        const jwks = await getJwks(cfg);
        if (jwks && Array.isArray(jwks["keys"]) && (jwks["keys"] as unknown[]).length > 0) {
          const key = (jwks["keys"] as Record<string, string>[])[0];
          verifyJwtSignature(accessToken, jwkToPem(key));
        }
      } catch (e) {
        console.warn("[oauth] JWT signature verify failed (non-fatal):", e);
      }
    }

    // Step 4: check token expiry
    if (cfg.JWT_VERIFY_EXP) {
      const exp = extractJwtExp(accessToken);
      if (exp > 0 && exp < Math.floor(Date.now() / 1000)) {
        authResponse.message = "Token expired";
        return authResponse;
      }
    }

    // Build AuthenticationData from user-info response
    const roles = Array.isArray(userInfo.userRoles)
      ? userInfo.userRoles.map((r) => String(r.id ?? "")).filter(Boolean)
      : [];

    const name = [userInfo.firstName, userInfo.lastName].filter(Boolean).join(" ") || undefined;

    const authData: AuthenticationData = {
      user_id: String(userInfo.id ?? ""),
      username: String(userInfo.userName ?? username),
      name,
      email: userInfo.email ?? undefined,
      phone: userInfo.contactNumber ?? undefined,
      tenant_id: String(userInfo.companyCode ?? ""),
      roles,
      exp: extractJwtExp(accessToken),
      access_token: accessToken,
    };

    authResponse.success = true;
    authResponse.code = 200;
    authResponse.data = authData;
    console.log("[oauth] Authenticated user:", authData.username, "id:", authData.user_id);
  } catch (e) {
    const msg =  "Authentication failed";
    console.error("[oauth] loginWithCredentials error:", e);
    authResponse.message = msg;
  }

  return authResponse;
}

export function clearJwksCache(): void {
  _jwksCache = null;
}
