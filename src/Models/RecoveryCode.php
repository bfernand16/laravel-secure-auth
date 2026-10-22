<?php

namespace SecureAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use SecureAuth\Support\Tables;

/**
 * @property int $id
 * @property int|string $user_id
 * @property string $code_hash
 * @property Carbon|null $used_at
 */
class RecoveryCode extends Model
{
    protected $fillable = ['user_id', 'code_hash', 'used_at'];

    protected $hidden = ['code_hash'];

    public function getTable(): string
    {
        return Tables::name('recovery_codes');
    }

    protected function casts(): array
    {
        return ['used_at' => 'datetime'];
    }
}
