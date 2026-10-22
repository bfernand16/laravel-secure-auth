import type { AuthState, LoginCredentials, LoginResult, MeResponse, StepUpAttempt, TwoFactorAttempt } from './types.js';
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
export interface LogoutResult {
    revoked: boolean;
}
export interface AuthClient {
    /** Refreshes with the cookie and loads `/me`. Call it before rendering any protected UI. Rejects on network errors. */
    bootstrap(): Promise<AuthState>;
    login(credentials: LoginCredentials): Promise<LoginResult>;
    verifyTwoFactor(attempt: TwoFactorAttempt): Promise<LoginResult>;
    /** Closes the local session always; `revoked` is false when the server could not be told (offline), so its cookie lives until it expires. */
    logout(): Promise<LogoutResult>;
    /** Exchanges the cookie for a new access token. Concurrent calls share one request. */
    refresh(): Promise<boolean>;
    loadMe(): Promise<MeResponse>;
    /** Re-authenticates for routes behind `secure-auth.recent-mfa` (password, plus a code when TOTP is on). */
    stepUp(attempt: StepUpAttempt): Promise<void>;
    /** `fetch` with the bearer token; refreshes when it is about to expire and retries once after a 401. */
    fetch(path: string, init?: RequestInit): Promise<Response>;
    getAccessToken(): string | null;
    /** The access token, renewed first when it is about to expire. `null` when there is no session. Use it for URLs and sockets that cannot go through `fetch`. */
    getFreshAccessToken(): Promise<string | null>;
    getState(): AuthState;
    subscribe(listener: () => void): () => void;
    currentUserId(): string | null;
    currentSessionId(): number | null;
    /** Closes the cross-tab channel. */
    dispose(): void;
}
/**
 * Browser client for laravel-secure-auth. The access token lives only in this closure (never in localStorage or
 * sessionStorage); the refresh secret lives in an HttpOnly cookie the script cannot read.
 */
export declare function createAuthClient(options: AuthClientOptions): AuthClient;
