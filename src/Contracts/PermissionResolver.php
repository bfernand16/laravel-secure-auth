<?php

namespace SecureAuth\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Where a user's permissions come from. Bound by default to the package's roles and permissions tables
 * (`SecureAuth\Permissions\RolePermissionResolver`); a host can bind its own implementation.
 * Results are cached by `SecureAuth\Permissions\Permissions`, so implementations may query freely.
 */
interface PermissionResolver
{
    /**
     * Full names (`<type>_<entity>`) of the permissions the user has.
     *
     * @return list<string>
     */
    public function permissionsOf(Authenticatable $user): array;

    /**
     * Full names of every permission that exists, used to build the CASL `cannot` list.
     *
     * @return list<string>
     */
    public function catalog(): array;
}
