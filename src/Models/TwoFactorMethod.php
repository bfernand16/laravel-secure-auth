<?php

namespace SecureAuth\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use SecureAuth\Support\Tables;

/**
 * @property int $id
 * @property int|string $user_id
 * @property string $type
 * @property string|null $secret decrypted on read (encrypted at rest with the app key)
 * @property Carbon|null $confirmed_at
 * @property int|null $last_used_timestep
 * @property Carbon|null $last_used_at
 */
class TwoFactorMethod extends Model
{
    public const TOTP = 'totp';

    protected $fillable = ['user_id', 'type', 'secret', 'confirmed_at', 'last_used_timestep', 'last_used_at'];

    protected $hidden = ['secret'];

    public function getTable(): string
    {
        return Tables::name('two_factor_methods');
    }

    protected function casts(): array
    {
        return [
            'secret' => 'encrypted',
            'confirmed_at' => 'datetime',
            'last_used_at' => 'datetime',
            'last_used_timestep' => 'integer',
        ];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo((string) config('secure-auth.user_model'), 'user_id');
    }

    /** @param  Builder<TwoFactorMethod>  $query */
    public function scopeConfirmed(Builder $query): void
    {
        $query->whereNotNull('confirmed_at');
    }

    /** @param  Builder<TwoFactorMethod>  $query */
    public function scopeOfType(Builder $query, string $type): void
    {
        $query->where('type', $type);
    }
}
