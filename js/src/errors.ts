/** A failed auth call. `reason` is the server's stable code (`invalid_credentials`, `two_factor_code_invalid`...). */
export class AuthError extends Error {
  readonly status: number;
  readonly reason: string | null;
  readonly body: unknown;

  constructor(status: number, reason: string | null, message: string, body: unknown) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
    this.reason = reason;
    this.body = body;
  }

  /** Attempts left on a login challenge after a wrong code, when the server says so. */
  get attemptsRemaining(): number | null {
    const value = (this.body as { attempts_remaining?: unknown } | null)?.attempts_remaining;

    return typeof value === 'number' ? value : null;
  }
}
