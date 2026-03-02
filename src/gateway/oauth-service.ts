import { createPublicKey, createVerify } from "node:crypto";
import type { OAuthConfig } from "./oauth-config.js";

// ── Types (mirrors Python schemas) ───────────────────────────────────────────

export type TokenResponse = {
  success: boolean;
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
};

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

// ── JWKS cache (mirrors Python self._jwks_cache) ──────────────────────────────

let _jwksCache: Record<string, unknown> | null = null;

// ── OAuthService methods (mirrors Python class) ───────────────────────────────

/**
 * _exchange_token_by_code: exchange authorization code for token.
 * Mirrors Python OAuthService._exchange_token_by_code exactly.
 */
async function exchangeTokenByCode(
  cfg: OAuthConfig,
  code: string,
  redirectUri?: string,
): Promise<TokenResponse> {
  const tokenResponse: TokenResponse = {
    success: false,
    access_token: "",
    token_type: "",
    expires_in: 0,
    refresh_token: "",
    scope: "",
  };

  try {
    const url = `${cfg.IAM_HOST}${cfg.TOKEN_URL}`;
    const formData = new URLSearchParams({
      grant_type: cfg.AUTHORIZATION_GRANT_TYPE,
      code,
    });
    if (redirectUri) {
      formData.set("redirect_uri", redirectUri);
    }

    console.log("[oauth] _exchange_token_by_code →", url, "redirect_uri:", redirectUri ?? "(none)");

    const response = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: cfg.AUTHORIZATION,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: formData.toString(),
      signal: AbortSignal.timeout(cfg.REQUEST_TIMEOUT),
    });

    if (response.status === 200) {
      const data = (await response.json()) as Record<string, unknown>;
      tokenResponse.success = true;
      tokenResponse.access_token = String(data["access_token"] ?? "");
      tokenResponse.token_type = String(data["token_type"] ?? "");
      tokenResponse.expires_in = Number(data["expires_in"] ?? 0);
      tokenResponse.refresh_token = String(data["refresh_token"] ?? "");
      tokenResponse.scope = String(data["scope"] ?? "");
      console.log("[oauth] Token exchanged successfully");
    } else {
      const body = await response.text().catch(() => "");
      console.error("[oauth] Token exchange failed:", response.status, body);
    }
  } catch (e) {
    console.error("[oauth] Exchange token error:", e);
  }

  return tokenResponse;
}

/**
 * _get_jwks: fetch JWKS with cache.
 * Mirrors Python OAuthService._get_jwks exactly.
 */
async function getJwks(cfg: OAuthConfig): Promise<Record<string, unknown> | null> {
  if (_jwksCache) return _jwksCache;

  try {
    const url = `${cfg.IAM_HOST}${cfg.JWKS_URL}`;
    const response = await fetch(url, {
      signal: AbortSignal.timeout(cfg.REQUEST_TIMEOUT),
    });

    if (response.status === 200) {
      _jwksCache = (await response.json()) as Record<string, unknown>;
      console.log("[oauth] JWKS fetched successfully");
      return _jwksCache;
    } else {
      console.error("[oauth] Failed to fetch JWKS:", response.status);
    }
  } catch (e) {
    console.error("[oauth] Get JWKS error:", e);
  }

  return null;
}

/**
 * _jwk_to_pem: convert JWK to PEM public key.
 * Mirrors Python OAuthService._jwk_to_pem using Node built-in crypto.
 */
function jwkToPem(jwk: Record<string, string>): string {
  // Node's createPublicKey accepts JWK directly — equivalent to Python's
  // RSAPublicNumbers(e, n).public_key().public_bytes(PEM, SubjectPublicKeyInfo)
  const pubKey = createPublicKey({
    key: { kty: "RSA", e: jwk["e"], n: jwk["n"] },
    format: "jwk",
  });
  return pubKey.export({ type: "spki", format: "pem" }) as string;
}

/**
 * Minimal RS256 JWT verify — mirrors Python jwt.decode() with options dict.
 * Supports verify_signature, verify_exp (verify_aud/verify_iss always false here).
 */
function decodeAndVerifyJwt(
  token: string,
  pem: string,
  cfg: OAuthConfig,
): Record<string, unknown> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("Invalid JWT structure");

  function b64urlDecode(s: string): string {
    const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
    return Buffer.from(padded.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  }

  const payload = JSON.parse(b64urlDecode(parts[1])) as Record<string, unknown>;

  if (cfg.JWT_VERIFY_SIGNATURE) {
    const signingInput = `${parts[0]}.${parts[1]}`;
    const sigB64 = parts[2].replace(/-/g, "+").replace(/_/g, "/");
    const sig = Buffer.from(sigB64 + "=".repeat((4 - (sigB64.length % 4)) % 4), "base64");
    const verify = createVerify("RSA-SHA256");
    verify.update(signingInput);
    if (!verify.verify(pem, sig)) {
      throw new Error("InvalidTokenError: signature verification failed");
    }
  }

  if (cfg.JWT_VERIFY_EXP) {
    const exp = payload["exp"];
    if (typeof exp !== "number" || exp < Math.floor(Date.now() / 1000)) {
      throw new Error("ExpiredSignatureError");
    }
  }

  return payload;
}

/**
 * _verify_token: verify JWT and extract user info.
 * Mirrors Python OAuthService._verify_token exactly.
 */
async function verifyToken(cfg: OAuthConfig, token: string): Promise<AuthResponse> {
  const authResponse = emptyAuthResponse();

  try {
    // 获取 JWKS
    const jwks = await getJwks(cfg);
    if (!jwks || !Array.isArray(jwks["keys"]) || !(jwks["keys"] as unknown[]).length) {
      authResponse.message = "Configuration mismatch";
      return authResponse;
    }

    // 获取公钥 (use first key, mirrors Python: key = jwks["keys"][0])
    const keys = jwks["keys"] as Record<string, string>[];
    const key = keys[0];
    const publicKey = jwkToPem(key);

    // 解码 JWT
    let decoded: Record<string, unknown>;
    try {
      decoded = decodeAndVerifyJwt(token, publicKey, cfg);
    } catch (e) {
      const msg = String(e);
      if (msg.includes("ExpiredSignatureError")) {
        console.warn("[oauth] Token expired");
        authResponse.message = "Token expired";
      } else {
        console.warn("[oauth] Invalid token:", msg);
        authResponse.message = "Invalid token";
      }
      return authResponse;
    }

    // 提取用户数据 (mirrors Python: jwt_data = decoded.get("data", {}))
    const jwtData = (decoded["data"] ?? {}) as Record<string, unknown>;

    if (jwtData && Object.keys(jwtData).length > 0) {
      const authData: AuthenticationData = {
        user_id: String(jwtData["user_id"] ?? ""),
        username: String(jwtData["user_name"] ?? ""),
        name: jwtData["name"] != null ? String(jwtData["name"]) : undefined,
        email: jwtData["email"] != null ? String(jwtData["email"]) : undefined,
        phone: jwtData["phone"] != null ? String(jwtData["phone"]) : undefined,
        tenant_id: String(jwtData["tenant_id"] ?? ""),
        tenant_name: jwtData["tenant_name"] != null ? String(jwtData["tenant_name"]) : undefined,
        roles: Array.isArray(jwtData["role_ids"]) ? (jwtData["role_ids"] as string[]) : [],
        exp: typeof decoded["exp"] === "number" ? decoded["exp"] : 0,
        access_token: token,
      };

      authResponse.success = true;
      authResponse.code = 200;
      authResponse.data = authData;
      console.log("[oauth] Token verified for user:", authData.username);
    } else {
      authResponse.message = "Invalid token data";
    }
  } catch (e) {
    console.error("[oauth] Token verification error:", e);
    authResponse.message = "Verification failed";
  }

  return authResponse;
}

/**
 * get_authorization_token: main entry point.
 * Mirrors Python OAuthService.get_authorization_token exactly.
 */
export async function getAuthorizationToken(
  cfg: OAuthConfig,
  code: string,
  redirectUri?: string,
): Promise<AuthResponse> {
  const authResponse = emptyAuthResponse();

  try {
    // 1. 通过授权码换取 token
    const tokenResponse = await exchangeTokenByCode(cfg, code, redirectUri);

    if (tokenResponse.success) {
      // 2. 验证 token 并获取用户信息
      return await verifyToken(cfg, tokenResponse.access_token);
    } else {
      authResponse.message = "Failed to exchange token";
      console.warn("[oauth] Token exchange failed for code:", code);
    }
  } catch (e) {
    console.error("[oauth] Get authorization token error:", e);
    authResponse.message = "Authentication failed";
  }

  return authResponse;
}

export function clearJwksCache(): void {
  _jwksCache = null;
}
