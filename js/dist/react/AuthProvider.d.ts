import { type PropsWithChildren } from 'react';
import type { AuthClient } from '../client.js';
import type { AuthState } from '../types.js';
interface AuthContextValue {
    client: AuthClient;
    state: AuthState;
}
/** Exposes the client and its state, and the CASL ability of the signed-in user to `Can`, `useAbility` and `RequirePermission`. */
export declare function AuthProvider({ client, children }: PropsWithChildren<{
    client: AuthClient;
}>): import("react").JSX.Element;
export declare function useAuth(): AuthContextValue;
export {};
