export type OAuthConfig = {
  IAM_HOST: string;
  TOKEN_URL: string;
  JWKS_URL: string;
  /** Value passed as Authorization header to login and token endpoints */
  AUTHORIZATION: string;
  CLIENT_ID: string;
  JWT_ALGORITHM: string;
  JWT_VERIFY_SIGNATURE: boolean;
  JWT_VERIFY_EXP: boolean;
  REQUEST_TIMEOUT: number;
};

export function resolveOAuthConfig(): OAuthConfig | null {
  const IAM_HOST = process.env.OAUTH_IAM_HOST ?? "https://id-staging.item.com";
  const CLIENT_ID = process.env.OAUTH_CLIENT_ID ?? "stag-SAIL000000-ojja7lspTp";
  if (!IAM_HOST || !CLIENT_ID) return null;

  const CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET ?? "7c1f62cc-2d5a-487b-a1f7-a3dc0fb8bd28";
  // Build Basic auth header from clientId:clientSecret
  const AUTHORIZATION =
    process.env.OAUTH_AUTHORIZATION ??
    `Basic ${Buffer.from(`${CLIENT_ID}:${CLIENT_SECRET}`).toString("base64")}`;

  return {
    IAM_HOST,
    CLIENT_ID,
    AUTHORIZATION,
    TOKEN_URL: process.env.OAUTH_TOKEN_URL ?? "/oauth2/token",
    JWKS_URL: process.env.OAUTH_JWKS_URL ?? "/oauth2/jwks",
    JWT_ALGORITHM: process.env.OAUTH_JWT_ALGORITHM ?? "RS256",
    JWT_VERIFY_SIGNATURE: process.env.OAUTH_VERIFY_SIGNATURE !== "false",
    JWT_VERIFY_EXP: process.env.OAUTH_VERIFY_EXP !== "false",
    REQUEST_TIMEOUT: Number(process.env.OAUTH_REQUEST_TIMEOUT_MS ?? "10000"),
  };
}
