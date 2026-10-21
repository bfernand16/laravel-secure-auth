import { describe, expect, it, vi } from 'vitest';
import { createAuthClient } from '../src/client';
import { AuthError } from '../src/errors';
import { channelHub, fakeFetch, fakeJwt, me, path, refreshReply, type Reply, type SentRequest } from './kit';

const OK: Reply = { status: 200, body: { ok: true } };

function api(route: (request: SentRequest) => Reply | Promise<Reply>, extra: Partial<Parameters<typeof createAuthClient>[0]> = {}) {
  const transport = fakeFetch(route);
  const client = createAuthClient({ baseUrl: '/api', fetch: transport.fetch, crossTab: false, ...extra });

  return { client, sent: transport.sent };
}

function routes(table: Record<string, Reply | ((request: SentRequest) => Reply)>) {
  return (request: SentRequest): Reply => {
    const handler = table[path(request)];

    if (handler === undefined) {
      return { status: 404 };
    }

    return typeof handler === 'function' ? handler(request) : handler;
  };
}

describe('bootstrap', () => {
  it('treats a visitor without cookie as a guest without asking for /me', async () => {
    const { client, sent } = api(routes({ '/api/auth/refresh': { status: 204 } }));

    const state = await client.bootstrap();

    expect(state.status).toBe('guest');
    expect(sent.map(path)).toEqual(['/api/auth/refresh']);
  });

  it('refreshes with the cookie and loads /me before resolving', async () => {
    const { client } = api(routes({ '/api/auth/refresh': refreshReply(), '/api/me': { status: 200, body: me() } }));

    const state = await client.bootstrap();

    expect(state.status).toBe('authenticated');
    expect(state.me?.user.email).toBe('ana@example.test');
  });

  it('sends the cookie and the XHR header only to the auth routes', async () => {
    const { client, sent } = api(routes({ '/api/auth/refresh': refreshReply(), '/api/me': { status: 200, body: me() } }));

    await client.bootstrap();

    expect([sent[0]?.credentials, sent[0]?.headers.get('X-Requested-With')]).toEqual(['include', 'XMLHttpRequest']);
    expect([sent[1]?.credentials, sent[1]?.headers.has('X-Requested-With')]).toEqual([undefined, false]);
  });

  it('treats a refused cookie as a guest', async () => {
    const { client } = api(routes({ '/api/auth/refresh': { status: 401, body: { reason: 'session_invalid' } } }));

    expect((await client.bootstrap()).status).toBe('guest');
  });

  it('rejects when the server cannot be reached, so the host does not flash the login', async () => {
    const { client } = api(() => {
      throw new TypeError('Failed to fetch');
    });

    await expect(client.bootstrap()).rejects.toThrow('Failed to fetch');
    expect(client.getState().status).toBe('unknown');
  });

  it('shares one request between simultaneous callers', async () => {
    const { client, sent } = api(routes({ '/api/auth/refresh': refreshReply(), '/api/me': { status: 200, body: me() } }));

    await Promise.all([client.bootstrap(), client.bootstrap()]);

    expect(sent.filter((request) => path(request) === '/api/auth/refresh')).toHaveLength(1);
  });

  it('never writes the token to the browser storage', async () => {
    localStorage.clear();
    sessionStorage.clear();
    const { client } = api(routes({ '/api/auth/refresh': refreshReply(), '/api/me': { status: 200, body: me() } }));

    await client.bootstrap();

    expect([localStorage.length, sessionStorage.length, document.cookie]).toEqual([0, 0, '']);
    expect(client.getAccessToken()).not.toBeNull();
  });
});

describe('login', () => {
  it('opens the session and loads the user', async () => {
    const token = fakeJwt();
    const { client, sent } = api(routes({ '/api/auth/login': refreshReply(token), '/api/me': { status: 200, body: me() } }));

    const result = await client.login({ email: 'ana@example.test', password: 'secret', remember: true });

    expect(result.status).toBe('authenticated');
    expect(sent[0]?.body).toEqual({ email: 'ana@example.test', password: 'secret', remember: true });
    expect(sent[1]?.headers.get('Authorization')).toBe(`Bearer ${token}`);
    expect(client.getState().status).toBe('authenticated');
  });

  it('returns the two-factor challenge without a session', async () => {
    const { client } = api(routes({ '/api/auth/login': { status: 200, body: { two_factor: true, challenge: 'abc', methods: ['totp', 'recovery'], expires_in: 300 } } }));

    const result = await client.login({ email: 'ana@example.test', password: 'secret' });

    expect(result).toEqual({ status: 'two_factor', challenge: 'abc', methods: ['totp', 'recovery'], expiresIn: 300 });
    expect(client.getAccessToken()).toBeNull();
  });

  it('completes the second step', async () => {
    const { client, sent } = api(routes({ '/api/auth/two-factor': refreshReply(), '/api/me': { status: 200, body: me() } }));

    const result = await client.verifyTwoFactor({ challenge: 'abc', method: 'totp', code: '123456' });

    expect(result.status).toBe('authenticated');
    expect([sent[0]?.credentials, sent[0]?.body]).toEqual(['include', { challenge: 'abc', method: 'totp', code: '123456' }]);
  });

  it('exposes the reason and the attempts left of a wrong code', async () => {
    const { client } = api(routes({ '/api/auth/two-factor': { status: 422, body: { reason: 'two_factor_code_invalid', message: 'Nope', attempts_remaining: 3 } } }));

    const error = await client.verifyTwoFactor({ challenge: 'abc', method: 'totp', code: '000000' }).catch((caught: unknown) => caught);

    expect(error).toBeInstanceOf(AuthError);
    expect([(error as AuthError).reason, (error as AuthError).attemptsRemaining, (error as AuthError).message]).toEqual(['two_factor_code_invalid', 3, 'Nope']);
  });

  it('sends a custom login field', async () => {
    const { client, sent } = api(routes({ '/api/auth/login': { status: 401, body: { reason: 'invalid_credentials' } } }), { loginField: 'username' });

    await client.login({ username: 'ana', password: 'secret' }).catch(() => undefined);

    expect(sent[0]?.body).toEqual({ username: 'ana', password: 'secret', remember: false });
  });
});

describe('authenticated requests', () => {
  async function signedIn(route: (request: SentRequest) => Reply, token = fakeJwt(), extra = {}) {
    const setup = api((request) => (path(request) === '/api/auth/login' ? refreshReply(token) : path(request) === '/api/me' && request.headers.get('Authorization') === `Bearer ${token}` ? { status: 200, body: me() } : route(request)), extra);
    await setup.client.login({ email: 'ana@example.test', password: 'secret' });
    setup.sent.length = 0;

    return setup;
  }

  it('send the access token kept in memory', async () => {
    const token = fakeJwt();
    const { client, sent } = await signedIn(() => OK, token);

    await client.fetch('reports');

    expect([path(sent[0]!), sent[0]?.headers.get('Authorization')]).toEqual(['/api/reports', `Bearer ${token}`]);
  });

  it('renew a token that is about to expire before sending', async () => {
    const fresh = fakeJwt('7', 30);
    const { client, sent } = await signedIn((request) => (path(request) === '/api/auth/refresh' ? refreshReply(fresh) : OK));
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 9.8 * 60 * 1000);

    await client.fetch('reports');
    vi.useRealTimers();

    expect(sent.map(path)).toEqual(['/api/auth/refresh', '/api/reports']);
    expect(sent[1]?.headers.get('Authorization')).toBe(`Bearer ${fresh}`);
  });

  it('renew once and retry after a 401', async () => {
    const fresh = fakeJwt('7', 15);
    const { client, sent } = await signedIn((request) => {
      if (path(request) === '/api/auth/refresh') {
        return refreshReply(fresh);
      }

      return request.headers.get('Authorization') === `Bearer ${fresh}` ? OK : { status: 401, body: { reason: 'session_revoked' } };
    });

    const response = await client.fetch('reports');

    expect([response.status, sent.map(path)]).toEqual([200, ['/api/reports', '/api/auth/refresh', '/api/reports']]);
  });

  it('share one renewal between simultaneous 401 responses', async () => {
    const fresh = fakeJwt('7', 15);
    const { client, sent } = await signedIn((request) => {
      if (path(request) === '/api/auth/refresh') {
        return refreshReply(fresh);
      }

      return request.headers.get('Authorization') === `Bearer ${fresh}` ? OK : { status: 401 };
    });

    const responses = await Promise.all([client.fetch('a'), client.fetch('b'), client.fetch('c')]);

    expect(responses.map((response) => response.status)).toEqual([200, 200, 200]);
    expect(sent.filter((request) => path(request) === '/api/auth/refresh')).toHaveLength(1);
  });

  it('do not retry more than once', async () => {
    const { client, sent } = await signedIn((request) => (path(request) === '/api/auth/refresh' ? refreshReply(fakeJwt('7', 15)) : { status: 401 }));

    const response = await client.fetch('reports');

    expect(response.status).toBe(401);
    expect(sent.filter((request) => path(request) === '/api/reports')).toHaveLength(2);
  });

  it('end the session once when the renewal is refused', async () => {
    const onSessionExpired = vi.fn();
    const { client } = await signedIn((request) => (path(request) === '/api/auth/refresh' ? { status: 401 } : { status: 401 }), fakeJwt(), { onSessionExpired });

    await Promise.all([client.fetch('a'), client.fetch('b')]);

    expect([client.getState().status, client.getAccessToken(), onSessionExpired.mock.calls.length]).toEqual(['guest', null, 1]);
  });

  it('keep the session when the renewal fails for the network or the rate limit', async () => {
    const { client } = await signedIn((request) => (path(request) === '/api/auth/refresh' ? { status: 429 } : { status: 401 }));

    await client.fetch('reports');

    expect([client.getState().status, client.getAccessToken() !== null]).toEqual(['authenticated', true]);
  });

  it('keep the session when the renewal is refused by the origin check', async () => {
    const onSessionExpired = vi.fn();
    const { client } = await signedIn((request) => (path(request) === '/api/auth/refresh' ? { status: 403, body: { reason: 'csrf_rejected' } } : { status: 401 }), fakeJwt(), { onSessionExpired });

    await client.fetch('reports');

    expect([client.getState().status, onSessionExpired.mock.calls.length]).toEqual(['authenticated', 0]);
  });

  it('pass other errors through without renewing', async () => {
    const { client, sent } = await signedIn(() => ({ status: 403, body: { reason: 'forbidden' } }));

    const response = await client.fetch('admin');

    expect(response.status).toBe(403);
    expect(sent.map(path)).toEqual(['/api/admin']);
  });

  it('reload the permissions after a stale-permissions refusal', async () => {
    const fresh = fakeJwt('7', 15);
    const promoted = me({ permissions: { can: [{ type: 'edit', entity: 'reports' }], cannot: [] } });
    const { client } = await signedIn((request) => {
      if (path(request) === '/api/auth/refresh') {
        return refreshReply(fresh);
      }
      if (path(request) === '/api/me') {
        return { status: 200, body: promoted };
      }

      return request.headers.get('Authorization') === `Bearer ${fresh}` ? OK : { status: 401, body: { reason: 'permissions_stale' } };
    });

    await client.fetch('reports');

    expect(client.getState().me?.permissions.can).toEqual([{ type: 'edit', entity: 'reports' }]);
  });

  it('tell the host when mandatory two-factor setup is due', async () => {
    const onTwoFactorRequired = vi.fn();
    const { client } = await signedIn(() => ({ status: 403, body: { reason: 'two_factor_required' } }), fakeJwt(), { onTwoFactorRequired });

    await client.fetch('reports');

    expect(onTwoFactorRequired).toHaveBeenCalledTimes(1);
  });

  it('step up with the password and a code', async () => {
    const { client, sent } = await signedIn(() => ({ status: 200, body: { last_mfa_at: 'now' } }));

    await client.stepUp({ password: 'secret', method: 'totp', code: '123456' });

    expect([path(sent[0]!), sent[0]?.method, sent[0]?.body]).toEqual(['/api/me/step-up', 'POST', { current_password: 'secret', method: 'totp', code: '123456' }]);
  });

  it('exposes the session and user ids carried by the token', async () => {
    const { client } = await signedIn(() => OK, fakeJwt('42', 10, 9));

    expect([client.currentUserId(), client.currentSessionId()]).toEqual(['42', 9]);
  });
});

describe('logout', () => {
  it('tells the server with the cookie and the token, then forgets the session', async () => {
    const token = fakeJwt();
    const { client, sent } = api(routes({ '/api/auth/login': refreshReply(token), '/api/me': { status: 200, body: me() }, '/api/auth/logout': OK }));
    await client.login({ email: 'ana@example.test', password: 'secret' });

    await client.logout();

    const logout = sent.find((request) => path(request) === '/api/auth/logout');
    expect([logout?.credentials, logout?.headers.get('Authorization')]).toEqual(['include', `Bearer ${token}`]);
    expect([client.getAccessToken(), client.getState().status]).toEqual([null, 'guest']);
  });

  it('closes the local session even if the server cannot be reached', async () => {
    let online = true;
    const { client } = api((request) => {
      if (!online) {
        throw new TypeError('offline');
      }

      return path(request) === '/api/me' ? { status: 200, body: me() } : refreshReply();
    });
    await client.login({ email: 'ana@example.test', password: 'secret' });
    online = false;

    await client.logout();

    expect(client.getAccessToken()).toBeNull();
  });

  it('notifies subscribers of every change', async () => {
    const { client } = api(routes({ '/api/auth/login': refreshReply(), '/api/me': { status: 200, body: me() }, '/api/auth/logout': OK }));
    const listener = vi.fn();
    client.subscribe(listener);

    await client.login({ email: 'ana@example.test', password: 'secret' });
    await client.logout();

    expect(listener.mock.calls.length).toBeGreaterThanOrEqual(2);
  });
});

describe('between tabs', () => {
  function tabs() {
    const openChannel = channelHub();
    const route = routes({ '/api/auth/login': refreshReply(), '/api/me': { status: 200, body: me() }, '/api/auth/logout': OK, '/api/auth/refresh': refreshReply(fakeJwt('7', 30)) });
    const first = createAuthClient({ baseUrl: '/api', fetch: fakeFetch(route).fetch, openChannel });
    const secondTransport = fakeFetch(route);
    const second = createAuthClient({ baseUrl: '/api', fetch: secondTransport.fetch, openChannel });

    return { first, second, secondSent: secondTransport.sent };
  }

  it('another tab learns about a login without asking the server', async () => {
    const { first, second, secondSent } = tabs();

    await first.login({ email: 'ana@example.test', password: 'secret' });

    expect(second.getState().status).toBe('authenticated');
    expect(await second.bootstrap()).toMatchObject({ status: 'authenticated' });
    expect(secondSent.filter((request) => path(request) === '/api/auth/refresh')).toHaveLength(0);
  });

  it('another tab signs out when this one logs out', async () => {
    const { first, second } = tabs();
    await first.login({ email: 'ana@example.test', password: 'secret' });

    await first.logout();

    expect([second.getAccessToken(), second.getState().status]).toEqual([null, 'guest']);
  });

  it('another tab receives the renewed token', async () => {
    const { first, second } = tabs();
    await first.login({ email: 'ana@example.test', password: 'secret' });

    await first.refresh();

    expect(second.getAccessToken()).toBe(first.getAccessToken());
  });

  it('works without BroadcastChannel', async () => {
    const { client } = api(routes({ '/api/auth/login': refreshReply(), '/api/me': { status: 200, body: me() } }), { crossTab: true, openChannel: () => null });

    await client.login({ email: 'ana@example.test', password: 'secret' });

    expect(client.getState().status).toBe('authenticated');
  });
});
