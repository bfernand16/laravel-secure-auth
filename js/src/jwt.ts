export interface AccessTokenPayload {
  sub?: string;
  sid?: number;
  exp?: number;
  amr?: string[];
  auth_time?: number;
}

/** Reads the payload of a JWT without verifying it (the server verifies; the client only needs `exp`, `sub` and `sid`). */
export function decodeAccessToken(token: string): AccessTokenPayload | null {
  const part = token.split('.')[1];

  if (part === undefined) {
    return null;
  }

  try {
    const base64 = part.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    const json = decodeURIComponent(
      Array.from(atob(padded), (character) => '%' + character.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
    );
    const payload: unknown = JSON.parse(json);

    return typeof payload === 'object' && payload !== null ? (payload as AccessTokenPayload) : null;
  } catch {
    return null;
  }
}
