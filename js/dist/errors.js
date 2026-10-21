/** A failed auth call. `reason` is the server's stable code (`invalid_credentials`, `two_factor_code_invalid`...). */
export class AuthError extends Error {
    status;
    reason;
    body;
    constructor(status, reason, message, body) {
        super(message);
        this.name = 'AuthError';
        this.status = status;
        this.reason = reason;
        this.body = body;
    }
    /** Attempts left on a login challenge after a wrong code, when the server says so. */
    get attemptsRemaining() {
        const value = this.body?.attempts_remaining;
        return typeof value === 'number' ? value : null;
    }
}
