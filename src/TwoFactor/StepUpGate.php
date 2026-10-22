<?php

namespace SecureAuth\TwoFactor;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Validation\ValidationException;
use SecureAuth\Models\TwoFactorMethod;
use SecureAuth\Sessions\SessionTokens;

/**
 * Re-authentication before sensitive actions: the current password and, when the user has TOTP, a current code (TOTP or
 * a recovery code). Failures are capped per account. Returns the `amr` value that was proven.
 */
class StepUpGate
{
    private const FAILURE_WINDOW_SECONDS = 900;

    public function __construct(
        private readonly TwoFactorManager $manager,
        private readonly TwoFactorVerifier $verifier,
    ) {}

    public function authorize(Authenticatable $user, string $password, ?string $method, ?string $code): string
    {
        $this->checkPassword($user, $password);
        $key = LoginChallenges::failureKey($user->getAuthIdentifier());

        if (! $this->manager->enabled($user)) {
            return SessionTokens::AMR_PASSWORD;
        }

        if ($method === null || $code === null || ! $this->verifier->verify($user, $method, $code)) {
            RateLimiter::hit($key, self::FAILURE_WINDOW_SECONDS);

            throw ValidationException::withMessages(['code' => [__('secure-auth::messages.two_factor_invalid')]]);
        }

        return $method === TwoFactorMethod::TOTP ? SessionTokens::AMR_OTP : SessionTokens::AMR_RECOVERY;
    }

    /** Checks the current password under the same per-account failure cap as the rest of the step-up. */
    public function checkPassword(Authenticatable $user, string $password): void
    {
        $key = LoginChallenges::failureKey($user->getAuthIdentifier());

        if (RateLimiter::tooManyAttempts($key, (int) config('secure-auth.rate_limits.two_factor_failures', 15))) {
            $seconds = RateLimiter::availableIn($key);

            throw new ThrottleRequestsException(__('secure-auth::messages.throttled', ['seconds' => $seconds]), null, ['Retry-After' => $seconds]);
        }

        if (! Hash::check($password, $user->getAuthPassword())) {
            RateLimiter::hit($key, self::FAILURE_WINDOW_SECONDS);

            throw ValidationException::withMessages(['current_password' => [__('secure-auth::messages.wrong_password')]]);
        }
    }
}
