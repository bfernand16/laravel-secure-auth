import { jsx as _jsx } from "react/jsx-runtime";
import { createContext, useContext, useMemo } from 'react';
import { defineRulesFor } from '../ability.js';
const AbilityContext = createContext(null);
/** Provides the CASL ability, either built already or from the `can` / `cannot` lists of `GET /me`. */
export function AbilityProvider(props) {
    const given = 'ability' in props ? props.ability : null;
    const permissions = 'permissions' in props ? props.permissions : null;
    const ability = useMemo(() => given ?? defineRulesFor(permissions), [given, permissions]);
    return _jsx(AbilityContext.Provider, { value: ability, children: props.children });
}
/** The ability of the nearest `AbilityProvider` (or `AuthProvider`). Without a provider everything is denied. */
export function useAbility() {
    const ability = useContext(AbilityContext);
    return useMemo(() => ability ?? defineRulesFor(null), [ability]);
}
