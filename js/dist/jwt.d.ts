export interface AccessTokenPayload {
    sub?: string;
    sid?: number;
    exp?: number;
    amr?: string[];
    auth_time?: number;
}
/** Reads the payload of a JWT without verifying it (the server verifies; the client only needs `exp`, `sub` and `sid`). */
export declare function decodeAccessToken(token: string): AccessTokenPayload | null;
