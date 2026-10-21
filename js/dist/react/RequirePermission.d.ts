import { type PropsWithChildren, type ReactNode } from 'react';
export type RequirePermissionProps = PropsWithChildren<{
    /** Action, e.g. `view`. */
    I: string;
    /** Subject (entity), e.g. `admin-users`. */
    a: string;
    /** Rendered instead of the children when the permission is missing (default: nothing). */
    fallback?: ReactNode;
    /** Called once when the permission is missing; use it to redirect with your router. */
    onDenied?: () => void;
}>;
/** Router-agnostic guard: renders its children only with the permission. Never a substitute for the server check. */
export declare function RequirePermission({ I, a, fallback, onDenied, children }: RequirePermissionProps): import("react").JSX.Element;
