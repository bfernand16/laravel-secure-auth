<?php

namespace SecureAuth\Concerns;

use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use SecureAuth\Models\Role;
use SecureAuth\Permissions\PermissionCache;
use SecureAuth\Permissions\Permissions;
use SecureAuth\Support\Tables;

/** Roles and cached permission checks for the host's user model. Changing roles here bumps the user's `pv`. */
trait HasRoles
{
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(Role::class, Tables::name('user_role'), 'user_id', 'role_id')->withTimestamps();
    }

    public function assignRole(string|Role ...$roles): void
    {
        $this->roles()->syncWithoutDetaching($this->roleIds($roles));
        $this->forgetCachedPermissions();
    }

    public function removeRole(string|Role ...$roles): void
    {
        $this->roles()->detach($this->roleIds($roles));
        $this->forgetCachedPermissions();
    }

    /** @param  list<string|Role>  $roles */
    public function syncRoles(array $roles): void
    {
        $this->roles()->sync($this->roleIds($roles));
        $this->forgetCachedPermissions();
    }

    public function hasRole(string $name): bool
    {
        return $this->roles()->where('name', $name)->exists();
    }

    /** @return list<string> */
    public function permissionNames(): array
    {
        return app(Permissions::class)->names($this);
    }

    public function hasPermission(string $permission): bool
    {
        return app(Permissions::class)->has($this, $permission);
    }

    public function forgetCachedPermissions(): void
    {
        app(PermissionCache::class)->forgetUser($this->getAuthIdentifier());
    }

    /**
     * @param  array<int, string|Role>  $roles
     * @return list<int>
     */
    private function roleIds(array $roles): array
    {
        $names = array_values(array_filter($roles, 'is_string'));
        $ids = array_map(fn (Role $role) => $role->id, array_values(array_filter($roles, fn ($role) => $role instanceof Role)));

        return array_values(array_unique(array_merge($ids, $names === [] ? [] : Role::whereIn('name', $names)->pluck('id')->all())));
    }
}
