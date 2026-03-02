export type OAuthConfig = {
  IAM_HOST: string;
  TOKEN_URL: string;
  JWKS_URL: string;
  AUTHORIZE_URL: string;
  /** Value passed as Authorization header to token endpoint */
  AUTHORIZATION: string;
  CLIENT_ID: string;
  AUTHORIZATION_GRANT_TYPE: string;
  JWT_ALGORITHM: string;
  JWT_VERIFY_SIGNATURE: boolean;
  JWT_VERIFY_EXP: boolean;
  JWT_VERIFY_AUD: boolean;
  JWT_VERIFY_ISS: boolean;
  REQUEST_TIMEOUT: number;
  /** Origin-only redirect_uri registered with IAM, e.g. "http://localhost:18789" */
  REDIRECT_URI: string;
};

export function resolveOAuthConfig(): OAuthConfig | null {
  const IAM_HOST = process.env.OAUTH_IAM_HOST ?? "https://id-staging.item.com";
  const CLIENT_ID = process.env.OAUTH_CLIENT_ID ?? "stag-SAIL000000-ojja7lspTp";
  if (!IAM_HOST || !CLIENT_ID) return null;

  const CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET ?? "7c1f62cc-2d5a-487b-a1f7-a3dc0fb8bd28";
  // Build Basic auth header from clientId:clientSecret (matches Python AUTHORIZATION setting)
  const AUTHORIZATION =
    process.env.OAUTH_AUTHORIZATION ??
    `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;

  return {
    IAM_HOST,
    CLIENT_ID,
    AUTHORIZATION,
    TOKEN_URL: process.env.OAUTH_TOKEN_URL ?? "/oauth2/token",
    JWKS_URL: process.env.OAUTH_JWKS_URL ?? "/oauth2/jwks",
    AUTHORIZE_URL: process.env.OAUTH_AUTHORIZE_URL ?? "/oauth2/authorize",
    AUTHORIZATION_GRANT_TYPE: process.env.OAUTH_GRANT_TYPE ?? "authorization_code",
    JWT_ALGORITHM: process.env.OAUTH_JWT_ALGORITHM ?? "RS256",
    JWT_VERIFY_SIGNATURE: process.env.OAUTH_VERIFY_SIGNATURE !== "false",
    JWT_VERIFY_EXP: process.env.OAUTH_VERIFY_EXP !== "false",
    JWT_VERIFY_AUD: process.env.OAUTH_VERIFY_AUD === "true",
    JWT_VERIFY_ISS: process.env.OAUTH_VERIFY_ISS === "true",
    REQUEST_TIMEOUT: Number(process.env.OAUTH_REQUEST_TIMEOUT_MS ?? "10000"),
    REDIRECT_URI: process.env.OAUTH_REDIRECT_URI ?? "",
  };
}

export function buildAuthorizeUrl(cfg: OAuthConfig, redirectUri: string, state: string): string {
  const url = new URL(`${cfg.IAM_HOST}${cfg.AUTHORIZE_URL}`);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", cfg.CLIENT_ID);
  url.searchParams.set("redirect_uri", redirectUri);
  url.searchParams.set("state", state);
  return url.toString();
}

/** Returns full callback URL: e.g. http://localhost:18789/api/v1/auth/callback */
export function resolveRedirectUri(cfg: OAuthConfig, host: string, secure: boolean): string {
  if (cfg.REDIRECT_URI) return cfg.REDIRECT_URI;
  return `${secure ? "https" : "http"}://${host}/api/v1/auth/callback`;
}
