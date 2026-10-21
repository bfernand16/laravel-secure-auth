import { AuthError } from './errors.js';
import { decodeAccessToken } from './jwt.js';
const HTTP_NO_CONTENT = 204;
const HTTP_UNAUTHORIZED = 401;
const HTTP_FORBIDDEN = 403;
const MS_PER_SECOND = 1000;
const DEFAULT_MARGIN_SECONDS = 20;
const LOCK_NAME = 'secure-auth-refresh';
function joinUrl(baseUrl, path) {
    return `${baseUrl.replace(/\/+$/, '')}/${path.replace(/^\/+/, '')}`;
}
async function readJson(response) {
    if (response.status === HTTP_NO_CONTENT) {
        return null;
    }
    try {
        return await response.clone().json();
    }
    catch {
        return null;
    }
}
function reasonOf(body) {
    const reason = body?.reason;
    return typeof reason === 'string' ? reason : null;
}
async function toError(response) {
    const body = await readJson(response);
    const message = body?.message;
    return new AuthError(response.status, reasonOf(body), typeof message === 'string' ? message : `Request failed with status ${response.status}`, body);
}
function defaultChannel(name) {
    return typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel(name);
}
/**
 * Browser client for laravel-secure-auth. The access token lives only in this closure (never in localStorage or
 * sessionStorage); the refresh secret lives in an HttpOnly cookie the script cannot read.
 */
export function createAuthClient(options) {
    const http = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
    const marginMs = (options.refreshMarginSeconds ?? DEFAULT_MARGIN_SECONDS) * MS_PER_SECOND;
    const loginField = options.loginField ?? 'email';
    const listeners = new Set();
    let token = null;
    let expiresAt = 0;
    let state = { status: 'unknown', me: null };
    let refreshing = null;
    let bootstrapping = null;
    let expiredNotified = false;
    const channel = options.crossTab === false ? null : (options.openChannel ?? defaultChannel)(options.channelName ?? 'secure-auth');
    function setState(next) {
        state = next;
        listeners.forEach((listener) => listener());
    }
    function broadcast(message) {
        try {
            channel?.postMessage(message);
        }
        catch {
            // Without the channel other tabs simply refresh on their own.
        }
    }
    function storeToken(next) {
        token = next;
        expiresAt = (decodeAccessToken(next)?.exp ?? 0) * MS_PER_SECOND;
        expiredNotified = false;
    }
    function clearSession(notifyOthers) {
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
        channel.onmessage = (event) => {
            const message = event.data;
            if (message.type === 'logout') {
                clearSession(false);
                return;
            }
            storeToken(message.token);
            setState(message.me ? { status: 'authenticated', me: message.me } : state);
        };
    }
    function isFresh() {
        return token !== null && expiresAt - marginMs > Date.now();
    }
    function cookieRequest(path, body) {
        const headers = { Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest' };
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
    async function requestRefresh() {
        let response;
        try {
            response = await cookieRequest('auth/refresh');
        }
        catch {
            return false;
        }
        if (response.status === HTTP_NO_CONTENT) {
            clearSession(false);
            return false;
        }
        if (response.status === HTTP_UNAUTHORIZED || response.status === HTTP_FORBIDDEN) {
            sessionEnded();
            return false;
        }
        const body = (await readJson(response));
        const next = body?.authorization?.token;
        if (!response.ok || typeof next !== 'string') {
            return false;
        }
        storeToken(next);
        broadcast({ type: 'session', token: next, me: state.me });
        return true;
    }
    function refreshWithLock(tokenBefore) {
        const run = async () => (token !== null && token !== tokenBefore && isFresh() ? true : requestRefresh());
        const locks = typeof navigator !== 'undefined' ? navigator.locks : undefined;
        return locks ? locks.request(LOCK_NAME, run) : run();
    }
    function refresh() {
        refreshing ??= refreshWithLock(token).finally(() => {
            refreshing = null;
        });
        return refreshing;
    }
    function withBearer(init, bearer) {
        const headers = new Headers(init?.headers);
        headers.set('Accept', headers.get('Accept') ?? 'application/json');
        if (bearer !== null) {
            headers.set('Authorization', `Bearer ${bearer}`);
        }
        return { ...init, headers };
    }
    async function authorizedFetch(path, init) {
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
    async function loadMe() {
        const response = await authorizedFetch('me');
        if (!response.ok) {
            throw await toError(response);
        }
        return (await response.json());
    }
    async function loadMeInto() {
        const me = await loadMe();
        setState({ status: 'authenticated', me });
        if (token !== null) {
            broadcast({ type: 'session', token, me });
        }
        return me;
    }
    async function openSession(response) {
        const body = (await response.json());
        if (body.two_factor === true && typeof body.challenge === 'string') {
            return { status: 'two_factor', challenge: body.challenge, methods: body.methods ?? ['totp', 'recovery'], expiresIn: body.expires_in ?? 0 };
        }
        if (typeof body.authorization?.token !== 'string') {
            throw new AuthError(response.status, null, 'The server did not return an access token.', body);
        }
        storeToken(body.authorization.token);
        return { status: 'authenticated', me: await loadMeInto() };
    }
    async function bootstrap() {
        bootstrapping ??= (async () => {
            if (!isFresh()) {
                let response;
                try {
                    response = await cookieRequest('auth/refresh');
                }
                catch (error) {
                    throw error instanceof Error ? error : new Error('The session could not be checked.');
                }
                if (response.status === HTTP_NO_CONTENT || response.status === HTTP_UNAUTHORIZED || response.status === HTTP_FORBIDDEN) {
                    clearSession(false);
                    return state;
                }
                if (!response.ok) {
                    throw await toError(response);
                }
                const body = (await response.json());
                if (typeof body.authorization?.token !== 'string') {
                    clearSession(false);
                    return state;
                }
                storeToken(body.authorization.token);
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
            }
            catch {
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
