<?php

namespace SecureAuth\Permissions;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use SecureAuth\Contracts\PermissionResolver;
use SecureAuth\Models\Permission;
use SecureAuth\Support\Tables;

/** Default resolver: the permissions of the user's roles, in one query. */
class RolePermissionResolver implements PermissionResolver
{
    public function permissionsOf(Authenticatable $user): array
    {
        $permissions = Tables::name('permissions');
        $rolePermission = Tables::name('role_permission');
        $userRole = Tables::name('user_role');

        return DB::table($permissions)
            ->join($rolePermission, $rolePermission.'.permission_id', '=', $permissions.'.id')
            ->join($userRole, $userRole.'.role_id', '=', $rolePermission.'.role_id')
            ->where($userRole.'.user_id', $user->getAuthIdentifier())
            ->distinct()
            ->orderBy($permissions.'.name')
            ->pluck($permissions.'.name')
            ->values()
            ->all();
    }

    public function catalog(): array
    {
        return Permission::query()->orderBy('name')->pluck('name')->values()->all();
    }
}
