import { createContext, useContext, useMemo, type PropsWithChildren } from 'react';
import { defineRulesFor } from '../ability.js';
import type { AppAbility, PermissionRules } from '../types.js';

const AbilityContext = createContext<AppAbility | null>(null);

type AbilityProviderProps = PropsWithChildren<{ ability: AppAbility } | { permissions: PermissionRules | null | undefined }>;

/** Provides the CASL ability, either built already or from the `can` / `cannot` lists of `GET /me`. */
export function AbilityProvider(props: AbilityProviderProps) {
  const given = 'ability' in props ? props.ability : null;
  const permissions = 'permissions' in props ? props.permissions : null;
  const ability = useMemo(() => given ?? defineRulesFor(permissions), [given, permissions]);

  return <AbilityContext.Provider value={ability}>{props.children}</AbilityContext.Provider>;
}

/** The ability of the nearest `AbilityProvider` (or `AuthProvider`). Without a provider everything is denied. */
export function useAbility(): AppAbility {
  const ability = useContext(AbilityContext);

  return useMemo(() => ability ?? defineRulesFor(null), [ability]);
}
