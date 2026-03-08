const OAUTH_USER_KEY = "oclaw_oauth_user";

export type OAuthUserData = {
  user_id: string;
  username?: string;
  name?: string | null;
  email?: string | null;
  phone?: string | null;
  tenant_id?: string;
  tenant_name?: string | null;
  roles?: string[];
  exp?: number;
  access_token?: string;
};

export function getOAuthUser(): OAuthUserData | null {
  try {
    const raw = localStorage.getItem(OAUTH_USER_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as OAuthUserData;
    if (!parsed?.user_id) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function getOAuthUserId(): string | null {
  return getOAuthUser()?.user_id ?? null;
}

/** Returns the locked session key: agent:<username>-<user_id>:main, or null if no OAuth user. */
export function getOAuthChatSessionKey(): string | null {
  const user = getOAuthUser();
  if (!user?.user_id) return null;
  const username = user.username?.trim();
  if (!username) return null;
  return `agent:${username}-${user.user_id}:main`;
}
