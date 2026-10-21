<?php

namespace SecureAuth\Tests\Concerns;

use Illuminate\Support\Carbon;
use PragmaRX\Google2FA\Google2FA;
use SecureAuth\Tests\Fixtures\User;
use SecureAuth\TwoFactor\TotpService;
use SecureAuth\TwoFactor\TwoFactorManager;

trait UsesTwoFactor
{
    /** Code of the authenticator for the current test instant (plus `$steps` periods). */
    protected function totpCode(string $secret, int $steps = 0): string
    {
        return app(Google2FA::class)->oathTotp($secret, intdiv(now()->getTimestamp(), TotpService::PERIOD_SECONDS) + $steps);
    }

    /** Moves the test clock one period forward and returns the current code: it never repeats a used one. */
    protected function freshTotpCode(string $secret): string
    {
        Carbon::setTestNow(now()->addSeconds(TotpService::PERIOD_SECONDS));

        return $this->totpCode($secret);
    }

    /**
     * Enables the authenticator app of the user and returns its secret and recovery codes.
     *
     * @return array{secret: string, recovery_codes: list<string>}
     */
    protected function enableTotp(User $user): array
    {
        $manager = app(TwoFactorManager::class);
        $secret = $manager->startTotp($user);
        $codes = $manager->confirmTotp($user, $this->freshTotpCode($secret));

        return ['secret' => $secret, 'recovery_codes' => $codes ?? []];
    }
}
