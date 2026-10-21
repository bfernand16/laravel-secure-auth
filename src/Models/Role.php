<?php

namespace SecureAuth\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use SecureAuth\Permissions\PermissionCache;
use SecureAuth\Support\Tables;

/**
 * @property int $id
 * @property string $name
 * @property string|null $label
 */
class Role extends Model
{
    protected $fillable = ['name', 'label'];

    public function getTable(): string
    {
        return Tables::name('roles');
    }

    public function permissions(): BelongsToMany
    {
        return $this->belongsToMany(Permission::class, Tables::name('role_permission'))->withTimestamps();
    }

    public function users(): BelongsToMany
    {
        return $this->belongsToMany((string) config('secure-auth.user_model'), Tables::name('user_role'))->withTimestamps();
    }

    /**
     * Grants permissions by name and invalidates every cached permission set (and the `pv` of live tokens).
     *
     * @param  list<string>|string  $names
     */
    public function grant(array|string $names): void
    {
        $ids = Permission::whereIn('name', (array) $names)->pluck('id')->all();
        $this->permissions()->syncWithoutDetaching($ids);
        app(PermissionCache::class)->flush();
    }

    /** @param  list<string>|string  $names */
    public function revoke(array|string $names): void
    {
        $ids = Permission::whereIn('name', (array) $names)->pluck('id')->all();
        $this->permissions()->detach($ids);
        app(PermissionCache::class)->flush();
    }
}
