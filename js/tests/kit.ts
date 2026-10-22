import type { ChannelLike } from '../src/client';
import type { MeResponse } from '../src/types';

export interface SentRequest {
  url: string;
  method: string;
  credentials: RequestCredentials | undefined;
  headers: Headers;
  body: unknown;
}

export type Reply = { status: number; body?: unknown };

function base64url(value: unknown): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** An unsigned JWT with the claims the client reads; `minutes` until it expires. */
export function fakeJwt(sub = '7', minutes = 10, sid = 3): string {
  const exp = Math.floor(Date.now() / 1000) + minutes * 60;

  return `${base64url({ alg: 'HS256', typ: 'JWT' })}.${base64url({ sub, sid, exp, amr: ['pwd'] })}.signature`;
}

export function me(overrides: Partial<MeResponse> = {}): MeResponse {
  return {
    user: { id: 7, email: 'ana@example.test' },
    permissions: { can: [{ type: 'view', entity: 'reports' }], cannot: [{ type: 'edit', entity: 'reports' }] },
    two_factor: { enabled: false, required_at: null, setup_required: false },
    session: { id: 3, amr: ['pwd'], authenticated_at: null, last_mfa_at: null },
    ...overrides,
  };
}

export function refreshReply(token = fakeJwt()): Reply {
  return { status: 200, body: { two_factor: false, authorization: { token, type: 'bearer', expires_in: 600 } } };
}

/** A fake `fetch` that records every request and answers with `route(request)`. */
export function fakeFetch(route: (request: SentRequest) => Reply | Promise<Reply>) {
  const sent: SentRequest[] = [];
  const fetchImpl = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const request: SentRequest = {
      url: String(input),
      method: init?.method ?? 'GET',
      credentials: init?.credentials,
      headers: new Headers(init?.headers),
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
    };
    sent.push(request);
    const reply = await route(request);

    return new Response(reply.status === 204 ? null : JSON.stringify(reply.body ?? {}), {
      status: reply.status,
      headers: { 'Content-Type': 'application/json' },
    });
  };

  return { fetch: fetchImpl as typeof fetch, sent };
}

/** Synchronous in-memory BroadcastChannel: what one client posts, the others receive at once. */
export function channelHub() {
  const members = new Set<ChannelLike>();

  return (name: string): ChannelLike => {
    void name;
    const channel: ChannelLike = {
      onmessage: null,
      postMessage(message: unknown) {
        members.forEach((member) => {
          if (member !== channel) {
            member.onmessage?.({ data: message } as MessageEvent);
          }
        });
      },
      close() {
        members.delete(channel);
      },
    };
    members.add(channel);

    return channel;
  };
}

export function path(request: SentRequest): string {
  return new URL(request.url, 'http://localhost').pathname;
}
