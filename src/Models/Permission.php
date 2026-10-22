<?php

namespace SecureAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use SecureAuth\Support\Tables;

/**
 * A `<type>_<entity>` permission. `entity` is the full, flattened entity name (`admin-users`).
 *
 * @property int $id
 * @property string $name
 * @property string $type
 * @property string $entity
 * @property string|null $label
 */
class Permission extends Model
{
    protected $fillable = ['name', 'type', 'entity', 'label'];

    public function getTable(): string
    {
        return Tables::name('permissions');
    }

    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(Role::class, Tables::name('role_permission'))->withTimestamps();
    }

    public static function nameFor(string $type, string $entity): string
    {
        return $type.'_'.$entity;
    }
}
