<?php

namespace SecureAuth\TwoFactor;

use Illuminate\Contracts\Auth\Authenticatable;
use SecureAuth\Models\TwoFactorMethod;

/** Checks a second-factor code (`totp` or `recovery`) against the user's state; every code works only once. */
class TwoFactorVerifier
{
    public const RECOVERY = 'recovery';

    public const METHODS = [TwoFactorMethod::TOTP, self::RECOVERY];

    public function __construct(
        private readonly TwoFactorManager $manager,
        private readonly TotpService $totp,
        private readonly RecoveryCodeService $recoveryCodes,
    ) {}

    public function verify(Authenticatable $user, string $method, string $code): bool
    {
        $totp = $this->manager->confirmedTotp($user);

        if ($totp === null) {
            return false;
        }

        return match ($method) {
            TwoFactorMethod::TOTP => $this->totp->consume($totp, $code),
            self::RECOVERY => $this->recoveryCodes->consume($user, $code),
            default => false,
        };
    }
}
