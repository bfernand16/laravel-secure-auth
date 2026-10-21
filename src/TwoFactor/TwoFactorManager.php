<?php

namespace SecureAuth\TwoFactor;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use LogicException;
use SecureAuth\Models\TwoFactorMethod;

/** The user's authenticator app: enrol, confirm with the first code, disable. Recovery codes come with the first method. */
class TwoFactorManager
{
    public function __construct(
        private readonly TotpService $totp,
        private readonly RecoveryCodeService $recoveryCodes,
    ) {}

    public function enabled(Authenticatable $user): bool
    {
        return $this->confirmedTotp($user) !== null;
    }

    public function confirmedTotp(Authenticatable $user): ?TwoFactorMethod
    {
        return TwoFactorMethod::where('user_id', $user->getAuthIdentifier())->ofType(TwoFactorMethod::TOTP)->confirmed()->first();
    }

    public function pendingTotp(Authenticatable $user): ?TwoFactorMethod
    {
        return TwoFactorMethod::where('user_id', $user->getAuthIdentifier())->ofType(TwoFactorMethod::TOTP)->whereNull('confirmed_at')->first();
    }

    /** Stores a new unconfirmed secret (replacing a pending one) and returns it. Fails when the app is already active. */
    public function startTotp(Authenticatable $user): string
    {
        if ($this->enabled($user)) {
            throw new LogicException('The authenticator app is already active.');
        }

        $secret = $this->totp->generateSecret();

        TwoFactorMethod::updateOrCreate(
            ['user_id' => $user->getAuthIdentifier(), 'type' => TwoFactorMethod::TOTP],
            ['secret' => $secret, 'confirmed_at' => null, 'last_used_timestep' => null, 'last_used_at' => null],
        );

        return $secret;
    }

    /**
     * Confirms the pending app with a valid code. Returns the new recovery codes, or null when the code is wrong.
     *
     * @return list<string>|null
     */
    public function confirmTotp(Authenticatable $user, string $code): ?array
    {
        $pending = $this->pendingTotp($user);

        if (! $pending || ! $this->totp->consume($pending, $code)) {
            return null;
        }

        return DB::transaction(function () use ($user, $pending) {
            $pending->forceFill(['confirmed_at' => now()])->save();

            return $this->recoveryCodes->regenerate($user);
        });
    }

    public function disable(Authenticatable $user): void
    {
        DB::transaction(function () use ($user) {
            TwoFactorMethod::where('user_id', $user->getAuthIdentifier())->delete();
            $this->recoveryCodes->clear($user);
        });
    }

    /** True when the grace period of `two_factor_required_at` has passed and the user still has no TOTP. */
    public function setupRequired(Authenticatable $user): bool
    {
        $requiredAt = method_exists($user, 'twoFactorRequiredAt') ? $user->twoFactorRequiredAt() : null;

        return $requiredAt !== null && ! $requiredAt->isFuture() && ! $this->enabled($user);
    }

    public function mandatory(Authenticatable $user): bool
    {
        return method_exists($user, 'twoFactorRequiredAt') && $user->twoFactorRequiredAt() !== null;
    }
}
