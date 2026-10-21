import { Fragment as _Fragment, jsx as _jsx } from "react/jsx-runtime";
import { useEffect } from 'react';
import { useAbility } from './AbilityContext.js';
/** Router-agnostic guard: renders its children only with the permission. Never a substitute for the server check. */
export function RequirePermission({ I, a, fallback = null, onDenied, children }) {
    const ability = useAbility();
    const allowed = ability.can(I, a);
    useEffect(() => {
        if (!allowed) {
            onDenied?.();
        }
    }, [allowed, onDenied]);
    return _jsx(_Fragment, { children: allowed ? children : fallback });
}
