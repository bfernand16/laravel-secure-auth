import { Fragment as _Fragment, jsx as _jsx } from "react/jsx-runtime";
import { useAbility } from './AbilityContext.js';
function pairOf(props) {
    if ('do' in props) {
        return [props.do, props.on];
    }
    return [props.I, 'a' in props ? props.a : props.an];
}
/**
 * `<Can I="edit" a="admin-users">` with the props of @casl/react's `Can`, reading the ability from this package's
 * context, so it works the same whatever @casl/react major the host uses (or none).
 */
export function Can(props) {
    const ability = useAbility();
    const [action, subject] = pairOf(props);
    const allowed = ability.can(action, subject) !== (props.not === true);
    if (typeof props.children === 'function') {
        return _jsx(_Fragment, { children: props.children(allowed, ability) });
    }
    return allowed || props.passThrough === true ? _jsx(_Fragment, { children: props.children }) : null;
}
