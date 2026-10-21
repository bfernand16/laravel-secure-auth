<?php

namespace SecureAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use SecureAuth\Support\Tables;

/**
 * Second step of a login: single use, short-lived, limited attempts. Only the hash of its token is stored.
 *
 * @property int $id
 * @property int|string $user_id
 * @property string $token_hash
 * @property bool $remember
 * @property int $attempts
 * @property Carbon $expires_at
 */
class LoginChallenge extends Model
{
    protected $fillable = ['user_id', 'token_hash', 'remember', 'attempts', 'expires_at'];

    protected $hidden = ['token_hash'];

    public function getTable(): string
    {
        return Tables::name('login_challenges');
    }

    protected function casts(): array
    {
        return ['remember' => 'boolean', 'attempts' => 'integer', 'expires_at' => 'datetime'];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo((string) config('secure-auth.user_model'), 'user_id');
    }

    public function isExpired(): bool
    {
        return $this->expires_at->isPast();
    }
}
