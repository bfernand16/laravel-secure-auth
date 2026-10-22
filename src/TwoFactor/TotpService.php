<?php

namespace SecureAuth\TwoFactor;

use Illuminate\Support\Facades\DB;
use PragmaRX\Google2FA\Google2FA;
use SecureAuth\Models\TwoFactorMethod;
use SecureAuth\Support\Tables;

/** Authenticator app codes (RFC 6238): ±1 time-step window and a code is never accepted twice. */
class TotpService
{
    public const PERIOD_SECONDS = 30;

    private const WINDOW = 1;

    private const SECRET_LENGTH = 32;

    public function __construct(private readonly Google2FA $google2fa) {}

    /** A 160-bit secret in base32. */
    public function generateSecret(): string
    {
        return $this->google2fa->generateSecretKey(self::SECRET_LENGTH);
    }

    public function otpauthUrl(string $secret, string $account): string
    {
        return $this->google2fa->getQRCodeUrl((string) config('secure-auth.two_factor.issuer', 'Laravel'), $account, $secret);
    }

    public function currentTimestep(): int
    {
        return intdiv(now()->getTimestamp(), self::PERIOD_SECONDS);
    }

    /** A valid code that was not used yet; marks its time step as used atomically. */
    public function consume(TwoFactorMethod $method, string $code): bool
    {
        $replayAllowed = $this->replayAllowed();
        $timestep = $this->matchingTimestep((string) $method->secret, $code, $replayAllowed ? null : $method->last_used_timestep);

        if ($timestep === null) {
            return false;
        }

        if ($replayAllowed) {
            return true;
        }

        $updated = DB::table(Tables::name('two_factor_methods'))
            ->where('id', $method->id)
            ->where(fn ($query) => $query->whereNull('last_used_timestep')->orWhere('last_used_timestep', '<', $timestep))
            ->update(['last_used_timestep' => $timestep, 'last_used_at' => now()]);

        return $updated === 1;
    }

    /** Only for E2E suites that log in many times with one account; never honoured outside `local` and `testing`. */
    private function replayAllowed(): bool
    {
        return (bool) config('secure-auth.two_factor.allow_code_reuse') && app()->environment('local', 'testing');
    }

    private function matchingTimestep(string $secret, string $code, ?int $lastUsedTimestep): ?int
    {
        if (preg_match('/^\d{6}$/', $code) !== 1 || $secret === '') {
            return null;
        }

        $timestep = $this->google2fa->verifyKeyNewer($secret, $code, $lastUsedTimestep ?? 0, self::WINDOW, $this->currentTimestep());

        return is_int($timestep) ? $timestep : null;
    }
}
