import { type PropsWithChildren } from 'react';
import type { AppAbility, PermissionRules } from '../types.js';
type AbilityProviderProps = PropsWithChildren<{
    ability: AppAbility;
} | {
    permissions: PermissionRules | null | undefined;
}>;
/** Provides the CASL ability, either built already or from the `can` / `cannot` lists of `GET /me`. */
export declare function AbilityProvider(props: AbilityProviderProps): import("react").JSX.Element;
/** The ability of the nearest `AbilityProvider` (or `AuthProvider`). Without a provider everything is denied. */
export declare function useAbility(): AppAbility;
export {};
