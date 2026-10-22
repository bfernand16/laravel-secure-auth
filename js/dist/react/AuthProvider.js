import { jsx as _jsx } from "react/jsx-runtime";
import { createContext, useContext, useSyncExternalStore } from 'react';
import { AbilityProvider } from './AbilityContext.js';
const AuthContext = createContext(null);
/** Exposes the client and its state, and the CASL ability of the signed-in user to `Can`, `useAbility` and `RequirePermission`. */
export function AuthProvider({ client, children }) {
    const state = useSyncExternalStore(client.subscribe, client.getState, client.getState);
    return (_jsx(AuthContext.Provider, { value: { client, state }, children: _jsx(AbilityProvider, { permissions: state.me?.permissions, children: children }) }));
}
export function useAuth() {
    const value = useContext(AuthContext);
    if (value === null) {
        throw new Error('useAuth() must be used inside <AuthProvider>.');
    }
    return value;
}
