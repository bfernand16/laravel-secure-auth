import type { ReactNode } from 'react';
import type { AppAbility } from '../types.js';
import { useAbility } from './AbilityContext.js';

type Subject = { I: string; a: string } | { I: string; an: string } | { do: string; on: string };

export type CanProps = Subject & {
  not?: boolean;
  passThrough?: boolean;
  children: ReactNode | ((allowed: boolean, ability: AppAbility) => ReactNode);
};

function pairOf(props: Subject): [string, string] {
  if ('do' in props) {
    return [props.do, props.on];
  }

  return [props.I, 'a' in props ? props.a : props.an];
}

/**
 * `<Can I="edit" a="admin-users">` with the props of @casl/react's `Can`, reading the ability from this package's
 * context, so it works the same whatever @casl/react major the host uses (or none).
 */
export function Can(props: CanProps) {
  const ability = useAbility();
  const [action, subject] = pairOf(props);
  const allowed = ability.can(action, subject) !== (props.not === true);

  if (typeof props.children === 'function') {
    return <>{props.children(allowed, ability)}</>;
  }

  return allowed || props.passThrough === true ? <>{props.children}</> : null;
}
