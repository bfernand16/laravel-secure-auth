import type { MongoAbility } from '@casl/ability';
/** One CASL rule as served by `GET /me`: `type` is the action, `entity` the subject (`edit` + `admin-users`). */
export interface Permission {
    type: string;
    entity: string;
}
export interface PermissionRules {
    can: Permission[];
    cannot: Permission[];
}
export type AppAbility = MongoAbility<[string, string]>;
export interface MeResponse {
    user: Record<string, unknown> & {
        id: number | string;
    };
    permissions: PermissionRules;
    two_factor: {
        enabled: boolean;
        required_at: string | null;
        setup_required: boolean;
    };
    session: {
        id: number | null;
        amr: string[];
        authenticated_at: string | null;
        last_mfa_at: string | null;
    };
}
export type AuthStatus = 'unknown' | 'authenticated' | 'guest';
export interface AuthState {
    status: AuthStatus;
    me: MeResponse | null;
}
export type TwoFactorMethod = 'totp' | 'recovery';
export type LoginResult = {
    status: 'authenticated';
    me: MeResponse;
} | {
    status: 'two_factor';
    challenge: string;
    methods: TwoFactorMethod[];
    expiresIn: number;
};
export interface LoginCredentials {
    password: string;
    remember?: boolean;
    /** The login field (`email` by default, see `loginField`). */
    [field: string]: string | boolean | undefined;
}
export interface TwoFactorAttempt {
    challenge: string;
    method: TwoFactorMethod;
    code: string;
}
export interface StepUpAttempt {
    password: string;
    method?: TwoFactorMethod;
    code?: string;
}
