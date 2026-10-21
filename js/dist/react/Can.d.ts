import type { ReactNode } from 'react';
import type { AppAbility } from '../types.js';
type Subject = {
    I: string;
    a: string;
} | {
    I: string;
    an: string;
} | {
    do: string;
    on: string;
};
export type CanProps = Subject & {
    not?: boolean;
    passThrough?: boolean;
    children: ReactNode | ((allowed: boolean, ability: AppAbility) => ReactNode);
};
/**
 * `<Can I="edit" a="admin-users">` with the props of @casl/react's `Can`, reading the ability from this package's
 * context, so it works the same whatever @casl/react major the host uses (or none).
 */
export declare function Can(props: CanProps): import("react").JSX.Element | null;
export {};
