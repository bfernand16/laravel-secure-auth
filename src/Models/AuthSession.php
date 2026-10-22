<?php

namespace SecureAuth\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use SecureAuth\Support\Tables;

/**
 * A refresh session. The cookie is `selector.secret`; only the SHA-256 of the secret (and of the previous one, for the
 * reuse grace) is stored.
 *
 * @property int $id
 * @property int|string $user_id
 * @property string $selector
 * @property string $secret_hash
 * @property string|null $previous_secret_hash
 * @property string $family_id
 * @property string|null $device_label
 * @property string|null $device_hash
 * @property string|null $ip
 * @property bool $remember
 * @property list<string>|null $amr
 * @property Carbon|null $authenticated_at
 * @property Carbon|null $last_mfa_at
 * @property Carbon|null $last_used_at
 * @property Carbon $expires_at
 * @property Carbon $absolute_expires_at
 * @property Carbon|null $revoked_at
 * @property Carbon|null $created_at
 */
class AuthSession extends Model
{
    protected $guarded = [];

    protected $hidden = ['selector', 'secret_hash', 'previous_secret_hash', 'device_hash', 'family_id'];

    public function getTable(): string
    {
        return Tables::name('auth_sessions');
    }

    protected function casts(): array
    {
        return [
            'remember' => 'boolean',
            'amr' => 'array',
            'authenticated_at' => 'datetime',
            'last_mfa_at' => 'datetime',
            'last_used_at' => 'datetime',
            'expires_at' => 'datetime',
            'absolute_expires_at' => 'datetime',
            'revoked_at' => 'datetime',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo((string) config('secure-auth.user_model'), 'user_id');
    }

    /** @param  Builder<AuthSession>  $query */
    public function scopeActive(Builder $query): void
    {
        $query->whereNull('revoked_at')->where('expires_at', '>', now())->where('absolute_expires_at', '>', now());
    }

    public function isActive(): bool
    {
        return $this->revoked_at === null && $this->expires_at->isFuture() && $this->absolute_expires_at->isFuture();
    }
}
