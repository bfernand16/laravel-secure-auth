<?php

namespace SecureAuth\TwoFactor;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;
use SecureAuth\Models\LoginChallenge;
use SecureAuth\Support\Tables;

/** Challenges of the login second step: single use, short-lived and with a maximum number of attempts. */
class LoginChallenges
{
    public const OK = 'ok';

    public const INVALID = 'invalid';

    public const WRONG_CODE = 'wrong_code';

    public const EXHAUSTED = 'exhausted';

    public const THROTTLED = 'throttled';

    private const FAILURE_WINDOW_SECONDS = 900;

    public function __construct(private readonly TwoFactorVerifier $verifier) {}

    /** @return array{challenge: string, methods: list<string>, expires_in: int} */
    public function open(Authenticatable $user, bool $remember): array
    {
        $token = Str::random(48);

        LoginChallenge::create([
            'user_id' => $user->getAuthIdentifier(),
            'token_hash' => $this->hashToken($token),
            'remember' => $remember,
            'expires_at' => now()->addMinutes($this->ttlMinutes()),
        ]);

        return ['challenge' => $token, 'methods' => TwoFactorVerifier::METHODS, 'expires_in' => $this->ttlMinutes() * 60];
    }

    public function find(string $token): ?LoginChallenge
    {
        $challenge = LoginChallenge::with('user')->where('token_hash', $this->hashToken($token))->first();

        if (! $challenge || $challenge->isExpired() || ! $challenge->user) {
            $challenge?->delete();

            return null;
        }

        return $challenge;
    }

    /**
     * Checks the challenge's code. When it is right the challenge is consumed and never works again.
     *
     * @return array{status: string, challenge?: LoginChallenge, remaining?: int} the challenge also comes with code failures, to record them
     */
    public function attempt(string $token, string $method, string $code): array
    {
        $challenge = $this->find($token);

        if (! $challenge) {
            return ['status' => self::INVALID];
        }

        $failureKey = self::failureKey($challenge->user_id);

        if (RateLimiter::tooManyAttempts($failureKey, (int) config('secure-auth.rate_limits.two_factor_failures', 15))) {
            return ['status' => self::THROTTLED];
        }

        if (! $this->registerAttempt($challenge)) {
            $challenge->delete();

            return ['status' => self::EXHAUSTED, 'challenge' => $challenge];
        }

        if ($this->verifier->verify($challenge->user, $method, $code)) {
            return LoginChallenge::whereKey($challenge->id)->delete() === 1
                ? ['status' => self::OK, 'challenge' => $challenge]
                : ['status' => self::INVALID];
        }

        RateLimiter::hit($failureKey, self::FAILURE_WINDOW_SECONDS);

        return $this->failure($challenge);
    }

    public function prune(): int
    {
        return LoginChallenge::where('expires_at', '<', now())->delete();
    }

    /** Shared by the login second step and the step-up, so wrong codes add up per account. */
    public static function failureKey(int|string $userId): string
    {
        return 'secure-auth:two-factor-failures|'.$userId;
    }

    /** @return array{status: string, challenge: LoginChallenge, remaining?: int} */
    private function failure(LoginChallenge $challenge): array
    {
        $remaining = max(0, $this->maxAttempts() - ($challenge->attempts + 1));

        if ($remaining === 0) {
            $challenge->delete();

            return ['status' => self::EXHAUSTED, 'challenge' => $challenge];
        }

        return ['status' => self::WRONG_CODE, 'remaining' => $remaining, 'challenge' => $challenge];
    }

    private function registerAttempt(LoginChallenge $challenge): bool
    {
        return DB::table(Tables::name('login_challenges'))
            ->where('id', $challenge->id)
            ->where('attempts', '<', $this->maxAttempts())
            ->increment('attempts') === 1;
    }

    private function ttlMinutes(): int
    {
        return max(1, (int) config('secure-auth.two_factor.challenge_ttl_minutes', 5));
    }

    private function maxAttempts(): int
    {
        return max(1, (int) config('secure-auth.two_factor.challenge_max_attempts', 5));
    }

    private function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }
}
