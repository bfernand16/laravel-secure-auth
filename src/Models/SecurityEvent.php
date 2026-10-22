<?php

namespace SecureAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;
use SecureAuth\Support\Tables;

/**
 * @property int $id
 * @property int|string $user_id
 * @property string $type
 * @property int|string|null $actor_id
 * @property string|null $ip
 * @property string|null $device
 * @property array<string, mixed>|null $meta
 * @property Carbon $created_at
 */
class SecurityEvent extends Model
{
    public const UPDATED_AT = null;

    protected $guarded = [];

    public function getTable(): string
    {
        return Tables::name('security_events');
    }

    protected function casts(): array
    {
        return ['meta' => 'array', 'created_at' => 'datetime'];
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo((string) config('secure-auth.user_model'), 'user_id');
    }

    public function actor(): BelongsTo
    {
        return $this->belongsTo((string) config('secure-auth.user_model'), 'actor_id');
    }
}
