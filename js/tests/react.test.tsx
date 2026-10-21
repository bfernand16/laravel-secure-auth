import { act, cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createAuthClient } from '../src/client';
import { AbilityProvider, AuthProvider, Can, RequirePermission, useAbility, useAuth } from '../src/react';
import { fakeFetch, me, path, refreshReply } from './kit';

const rules = { can: [{ type: 'view', entity: 'reports' }], cannot: [{ type: 'edit', entity: 'reports' }] };

afterEach(() => {
  cleanup();
});

describe('Can', () => {
  it('renders its children only with the permission', () => {
    render(
      <AbilityProvider permissions={rules}>
        <Can I="view" a="reports"><span>visible</span></Can>
        <Can I="edit" a="reports"><span>hidden</span></Can>
        <Can do="edit" on="reports" not><span>no-edit</span></Can>
      </AbilityProvider>,
    );

    expect([screen.queryByText('visible'), screen.queryByText('hidden'), screen.queryByText('no-edit')].map(Boolean)).toEqual([true, false, true]);
  });

  it('passes the decision to a render function', () => {
    render(
      <AbilityProvider permissions={rules}>
        <Can I="edit" an="reports">{(allowed) => (allowed ? 'yes' : 'no')}</Can>
      </AbilityProvider>,
    );

    expect(screen.getByText('no')).toBeTruthy();
  });

  it('denies everything without a provider', () => {
    render(<Can I="view" a="reports">visible</Can>);

    expect(screen.queryByText('visible')).toBeNull();
  });
});

describe('RequirePermission', () => {
  it('renders the fallback and calls onDenied without the permission', () => {
    const onDenied = vi.fn();

    render(
      <AbilityProvider permissions={rules}>
        <RequirePermission I="edit" a="reports" fallback={<p>denied</p>} onDenied={onDenied}>
          <p>editor</p>
        </RequirePermission>
      </AbilityProvider>,
    );

    expect([screen.queryByText('editor'), screen.getByText('denied')].map(Boolean)).toEqual([false, true]);
    expect(onDenied).toHaveBeenCalledTimes(1);
  });

  it('renders the children with the permission', () => {
    render(
      <AbilityProvider permissions={rules}>
        <RequirePermission I="view" a="reports">
          <p>report</p>
        </RequirePermission>
      </AbilityProvider>,
    );

    expect(screen.getByText('report')).toBeTruthy();
  });
});

describe('AuthProvider', () => {
  it('follows the client state and feeds the ability from /me', async () => {
    const transport = fakeFetch((request) => (path(request) === '/api/me' ? { status: 200, body: me() } : refreshReply()));
    const client = createAuthClient({ baseUrl: '/api', fetch: transport.fetch, crossTab: false });

    function Status() {
      const { state } = useAuth();
      const ability = useAbility();

      return <p>{`${state.status}:${String(ability.can('view', 'reports'))}`}</p>;
    }

    render(
      <AuthProvider client={client}>
        <Status />
      </AuthProvider>,
    );
    expect(screen.getByText('unknown:false')).toBeTruthy();

    await act(async () => {
      await client.bootstrap();
    });

    expect(screen.getByText('authenticated:true')).toBeTruthy();
  });

  it('useAuth outside the provider is a programming error', () => {
    function Orphan() {
      useAuth();

      return null;
    }

    vi.spyOn(console, 'error').mockImplementation(() => undefined);

    expect(() => render(<Orphan />)).toThrow('useAuth() must be used inside <AuthProvider>.');
  });
});
