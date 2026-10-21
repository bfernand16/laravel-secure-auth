import { AuthError } from './errors.js';
import { decodeAccessToken } from './jwt.js';
import type { AuthState, LoginCredentials, LoginResult, MeResponse, StepUpAttempt, TwoFactorAttempt, TwoFactorMethod } from './types.js';

export interface ChannelLike {
  postMessage(message: unknown): void;
  onmessage: ((event: MessageEvent) => void) | null;
  close?(): void;
}

export interface AuthClientOptions {
  /** API root that holds the package routes, e.g. `/api` or `https://example.com/api`. */
  baseUrl: string;
  fetch?: typeof fetch;
  /** Share the in-memory session between tabs with BroadcastChannel (default true). */
  crossTab?: boolean;
  channelName?: string;
  /** Override how the cross-tab channel is opened (tests, older browsers). Return null to disable. */
  openChannel?: (name: string) => ChannelLike | null;
  /** Refresh this many seconds before the access token expires (default 20). */
  refreshMarginSeconds?: number;
  /** Login field sent to `POST /auth/login` (default `email`). */
  loginField?: string;
  /** Called once when the server refuses the refresh cookie: the session is over. */
  onSessionExpired?: () => void;
  /** Called when the server answers 403 `two_factor_required` (the grace period of mandatory 2FA has passed). */
  onTwoFactorRequired?: () => void;
}

export interface AuthClient {
  /** Refreshes with the cookie and loads `/me`. Call it before rendering any protected UI. Rejects on network errors. */
  bootstrap(): Promise<AuthState>;
  login(credentials: LoginCredentials): Promise<LoginResult>;
  verifyTwoFactor(attempt: TwoFactorAttempt): Promise<LoginResult>;
  logout(): Promise<void>;
  /** Exchanges the cookie for a new access token. Concurrent calls share one request. */
  refresh(): Promise<boolean>;
  loadMe(): Promise<MeResponse>;
  /** Re-authenticates for routes behind `secure-auth.recent-mfa` (password, plus a code when TOTP is on). */
  stepUp(attempt: StepUpAttempt): Promise<void>;
  /** `fetch` with the bearer token; refreshes when it is about to expire and retries once after a 401. */
  fetch(path: string, init?: RequestInit): Promise<Response>;
  getAccessToken(): string | null;
  getState(): AuthState;
  subscribe(listener: () => void): () => void;
  currentUserId(): string | null;
  currentSessionId(): number | null;
  /** Closes the cross-tab channel. */
  dispose(): void;
}

type ChannelMessage = { type: 'session'; token: string; expiresAt: number; me: MeResponse | null } | { type: 'logout' };

type Authorization = { token?: unknown; expires_in?: unknown };

const HTTP_NO_CONTENT = 204;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
const MS_PER_SECOND = 1000;
const DEFAULT_MARGIN_SECONDS = 20;
const LOCK_NAME = 'secure-auth-refresh';

function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
}

async function readJson(response: Response): Promise<unknown> {
  if (response.status === HTTP_NO_CONTENT) {
    return null;
  }

  try {
    return await response.clone().json();
  } catch {
    return null;
  }
}

function reasonOf(body: unknown): string | null {
  const reason = (body as { reason?: unknown } | null)?.reason;

  return typeof reason === 'string' ? reason : null;
}

async function toError(response: Response): Promise<AuthError> {
  const body = await readJson(response);
  const message = (body as { message?: unknown } | null)?.message;

  return new AuthError(response.status, reasonOf(body), typeof message === 'string' ? message : `Request failed with status ${response.status}`, body);
}

function defaultChannel(name: string): ChannelLike | null {
  return typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel(name);
}

/**
 * Browser client for laravel-secure-auth. The access token lives only in this closure (never in localStorage or
 * sessionStorage); the refresh secret lives in an HttpOnly cookie the script cannot read.
 */
export function createAuthClient(options: AuthClientOptions): AuthClient {
  const http = options.fetch ?? ((input: RequestInfo | URL, init?: RequestInit) => globalThis.fetch(input, init));
  const marginMs = (options.refreshMarginSeconds ?? DEFAULT_MARGIN_SECONDS) * MS_PER_SECOND;
  const loginField = options.loginField ?? 'email';
  const listeners = new Set<() => void>();

  let token: string | null = null;
  let expiresAt = 0;
  let state: AuthState = { status: 'unknown', me: null };
  let refreshing: Promise<boolean> | null = null;
  let bootstrapping: Promise<AuthState> | null = null;
  let expiredNotified = false;

  const channel = options.crossTab === false ? null : (options.openChannel ?? defaultChannel)(options.channelName ?? 'secure-auth');

  function setState(next: AuthState) {
    state = next;
    listeners.forEach((listener) => listener());
  }

  function broadcast(message: ChannelMessage) {
    try {
      channel?.postMessage(message);
    } catch {
      // Without the channel other tabs simply refresh on their own.
    }
  }

  /** Times the expiry by `expires_in` on this clock, so a client clock that is off does not matter. */
  function expiryOf(next: string, expiresInSeconds: unknown): number {
    return typeof expiresInSeconds === 'number' ? Date.now() + expiresInSeconds * MS_PER_SECOND : (decodeAccessToken(next)?.exp ?? 0) * MS_PER_SECOND;
  }

  function storeToken(next: string, expiry: number) {
    token = next;
    expiresAt = expiry;
    expiredNotified = false;
  }

  function clearSession(notifyOthers: boolean) {
    const hadSession = token !== null || state.status === 'authenticated';

    token = null;
    expiresAt = 0;
    setState({ status: 'guest', me: null });

    if (notifyOthers && hadSession) {
      broadcast({ type: 'logout' });
    }
  }

  function sessionEnded() {
    const wasActive = token !== null || state.status === 'authenticated';

    clearSession(true);

    if (wasActive && !expiredNotified) {
      expiredNotified = true;
      options.onSessionExpired?.();
    }
  }

  if (channel) {
    channel.onmessage = (event: MessageEvent) => {
      const message = event.data as ChannelMessage;

      if (message.type === 'logout') {
        clearSession(false);

        return;
      }

      storeToken(message.token, message.expiresAt);
      setState(message.me ? { status: 'authenticated', me: message.me } : state);
    };
  }

  function isFresh(): boolean {
    return token !== null && expiresAt - marginMs > Date.now();
  }

  function cookieRequest(path: string, body?: unknown): Promise<Response> {
    const headers: Record<string, string> = { Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' };

    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }

    if (token !== null && path === 'auth/logout') {
      headers.Authorization = `Bearer ${token}`;
    }

    return http(joinUrl(options.baseUrl, path), {
      method: 'POST',
      credentials: 'include',
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  }

  async function requestRefresh(): Promise<boolean> {
    let response: Response;

    try {
      response = await cookieRequest('auth/refresh');
    } catch {
      return false;
    }

    if (response.status === HTTP_NO_CONTENT) {
      clearSession(false);

      return false;
    }

    if (response.status === HTTP_UNAUTHORIZED) {
      sessionEnded();

      return false;
    }

    const body = (await readJson(response)) as { authorization?: Authorization } | null;
    const next = body?.authorization?.token;

    if (!response.ok || typeof next !== 'string') {
      return false;
    }

    storeToken(next, expiryOf(next, body?.authorization?.expires_in));
    broadcast({ type: 'session', token: next, expiresAt, me: state.me });

    return true;
  }

  function refreshWithLock(tokenBefore: string | null): Promise<boolean> {
    const run = async () => (token !== null && token !== tokenBefore && isFresh() ? true : requestRefresh());
    const locks = typeof navigator !== 'undefined' ? navigator.locks : undefined;

    return locks ? locks.request(LOCK_NAME, run) : run();
  }

  function refresh(): Promise<boolean> {
    refreshing ??= refreshWithLock(token).finally(() => {
      refreshing = null;
    });

    return refreshing;
  }

  function withBearer(init: RequestInit | undefined, bearer: string | null): RequestInit {
    const headers = new Headers(init?.headers);

    headers.set('Accept', headers.get('Accept') ?? 'application/json');

    if (bearer !== null) {
      headers.set('Authorization', `Bearer ${bearer}`);
    }

    return { ...init, headers };
  }

  async function authorizedFetch(path: string, init?: RequestInit): Promise<Response> {
    if (token !== null && !isFresh()) {
      await refresh();
    }

    const sentWith = token;
    const response = await http(joinUrl(options.baseUrl, path), withBearer(init, sentWith));

    if (response.status === HTTP_FORBIDDEN && reasonOf(await readJson(response)) === 'two_factor_required') {
      options.onTwoFactorRequired?.();

      return response;
    }

    if (response.status !== HTTP_UNAUTHORIZED || sentWith === null) {
      return response;
    }

    const reason = reasonOf(await readJson(response));
    const renewed = token !== sentWith && token !== null ? true : await refresh();

    if (!renewed || token === null) {
      return response;
    }

    if (reason === 'permissions_stale') {
      await loadMeInto();
    }

    return http(joinUrl(options.baseUrl, path), withBearer(init, token));
  }

  async function loadMe(): Promise<MeResponse> {
    const response = await authorizedFetch('me');

    if (!response.ok) {
      throw await toError(response);
    }

    return (await response.json()) as MeResponse;
  }

  async function loadMeInto(): Promise<MeResponse> {
    const me = await loadMe();

    setState({ status: 'authenticated', me });

    if (token !== null) {
      broadcast({ type: 'session', token, expiresAt, me });
    }

    return me;
  }

  async function openSession(response: Response): Promise<LoginResult> {
    const body = (await response.json()) as {
      two_factor?: boolean;
      challenge?: string;
      methods?: TwoFactorMethod[];
      expires_in?: number;
      authorization?: { token: string; expires_in?: unknown };
    };

    if (body.two_factor === true && typeof body.challenge === 'string') {
      return { status: 'two_factor', challenge: body.challenge, methods: body.methods ?? ['totp', 'recovery'], expiresIn: body.expires_in ?? 0 };
    }

    if (typeof body.authorization?.token !== 'string') {
      throw new AuthError(response.status, null, 'The server did not return an access token.', body);
    }

    storeToken(body.authorization.token, expiryOf(body.authorization.token, body.authorization.expires_in));

    return { status: 'authenticated', me: await loadMeInto() };
  }

  async function bootstrap(): Promise<AuthState> {
    bootstrapping ??= (async () => {
      if (!isFresh()) {
        let response: Response;

        try {
          response = await cookieRequest('auth/refresh');
        } catch (error) {
          throw error instanceof Error ? error : new Error('The session could not be checked.');
        }

        if (response.status === HTTP_NO_CONTENT || response.status === HTTP_UNAUTHORIZED || response.status === HTTP_FORBIDDEN) {
          clearSession(false);

          return state;
        }

        if (!response.ok) {
          throw await toError(response);
        }

        const body = (await response.json()) as { authorization?: Authorization };

        if (typeof body.authorization?.token !== 'string') {
          clearSession(false);

          return state;
        }

        storeToken(body.authorization.token, expiryOf(body.authorization.token, body.authorization.expires_in));
      }

      await loadMeInto();

      return state;
    })().finally(() => {
      bootstrapping = null;
    });

    return bootstrapping;
  }

  return {
    bootstrap,
    refresh,
    loadMe: loadMeInto,
    fetch: authorizedFetch,

    async login(credentials) {
      const { password, remember, ...rest } = credentials;
      const response = await cookieRequest('auth/login', { [loginField]: rest[loginField], password, remember: remember === true });

      if (!response.ok) {
        throw await toError(response);
      }

      return openSession(response);
    },

    async verifyTwoFactor(attempt) {
      const response = await cookieRequest('auth/two-factor', attempt);

      if (!response.ok) {
        throw await toError(response);
      }

      return openSession(response);
    },

    async logout() {
      try {
        await cookieRequest('auth/logout');
      } catch {
        // Offline: the local session is closed anyway; the cookie dies with its expiry.
      }

      clearSession(true);
    },

    async stepUp(attempt) {
      const response = await authorizedFetch('me/step-up', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: attempt.password, method: attempt.method, code: attempt.code }),
      });

      if (!response.ok) {
        throw await toError(response);
      }
    },

    getAccessToken: () => token,
    getState: () => state,

    subscribe(listener) {
      listeners.add(listener);

      return () => {
        listeners.delete(listener);
      };
    },

    currentUserId() {
      const sub = token ? decodeAccessToken(token)?.sub : undefined;

      return typeof sub === 'string' ? sub : null;
    },

    currentSessionId() {
      const sid = token ? decodeAccessToken(token)?.sid : undefined;

      return typeof sid === 'number' ? sid : null;
    },

    dispose() {
      channel?.close?.();
      listeners.clear();
    },
  };
}
