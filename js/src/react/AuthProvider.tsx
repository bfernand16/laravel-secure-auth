import { createContext, useContext, useSyncExternalStore, type PropsWithChildren } from 'react';
import type { AuthClient } from '../client.js';
import type { AuthState } from '../types.js';
import { AbilityProvider } from './AbilityContext.js';

interface AuthContextValue {
  client: AuthClient;
  state: AuthState;
}

const AuthContext = createContext<AuthContextValue | null>(null);

/** Exposes the client and its state, and the CASL ability of the signed-in user to `Can`, `useAbility` and `RequirePermission`. */
export function AuthProvider({ client, children }: PropsWithChildren<{ client: AuthClient }>) {
  const state = useSyncExternalStore(client.subscribe, client.getState, client.getState);

  return (
    <AuthContext.Provider value={{ client, state }}>
      <AbilityProvider permissions={state.me?.permissions}>{children}</AbilityProvider>
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const value = useContext(AuthContext);

  if (value === null) {
    throw new Error('useAuth() must be used inside <AuthProvider>.');
  }

  return value;
}
