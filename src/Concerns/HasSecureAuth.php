<?php

namespace SecureAuth\Concerns;

use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;
use SecureAuth\Models\AuthSession;
use SecureAuth\Models\SecurityEvent;
use SecureAuth\Models\TwoFactorMethod;

/**
 * Everything laravel-secure-auth needs from the host's user model. Only `id`, the login field (`email`), `password` and
 * `two_factor_required_at` are read; override the hooks below to expose more.
 */
trait HasSecureAuth
{
    use HasRoles;

    public function authSessions(): HasMany
    {
        return $this->hasMany(AuthSession::class, 'user_id');
    }

    public function twoFactorMethods(): HasMany
    {
        return $this->hasMany(TwoFactorMethod::class, 'user_id');
    }

    public function securityEvents(): HasMany
    {
        return $this->hasMany(SecurityEvent::class, 'user_id');
    }

    /** Return true to stop the account from logging in, refreshing or using its tokens (suspended, banned...). */
    public function secureAuthIsBlocked(): bool
    {
        return false;
    }

    /**
     * The user data served by `GET /me`. Never put it in the access token.
     *
     * @return array<string, mixed>
     */
    public function secureAuthProfile(): array
    {
        return ['id' => $this->getKey(), 'email' => $this->getAttribute((string) config('secure-auth.login_field', 'email'))];
    }

    /** From this moment on, an account without TOTP can only reach the 2FA setup routes. Null: 2FA is optional. */
    public function twoFactorRequiredAt(): ?Carbon
    {
        $value = $this->getAttribute('two_factor_required_at');

        return $value === null ? null : Carbon::parse($value);
    }
}
