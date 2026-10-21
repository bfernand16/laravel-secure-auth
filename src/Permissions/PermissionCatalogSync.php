<?php

namespace SecureAuth\Permissions;

use Illuminate\Support\Facades\DB;
use InvalidArgumentException;
use SecureAuth\Models\Permission;
use SecureAuth\Models\Role;

/**
 * Applies `config/secure-auth-permissions.php` to the database without undoing admin changes: creates missing permissions
 * and roles, refreshes labels and only ever adds grants. Never deletes a permission nor removes an assignment.
 */
class PermissionCatalogSync
{
    public function __construct(private readonly PermissionCache $cache) {}

    /**
     * @param  array<string, mixed>|null  $catalog  defaults to the `secure-auth-permissions` config
     * @return array{permissions_created: int, roles_created: int, grants_added: int}
     */
    public function run(?array $catalog = null): array
    {
        $catalog ??= (array) config('secure-auth-permissions');
        $stats = ['permissions_created' => 0, 'roles_created' => 0, 'grants_added' => 0];

        DB::transaction(function () use ($catalog, &$stats) {
            $this->syncEntities((array) ($catalog['entities'] ?? []), null, $catalog, $stats);
            $this->syncRoles((array) ($catalog['roles'] ?? []), $stats);
            $this->syncGrants($catalog, $stats);
            $this->syncInheritance((array) ($catalog['inherits'] ?? []), $stats);
        });

        $this->cache->flush();

        return $stats;
    }

    /**
     * Full names of every permission the catalog declares (without touching the database).
     *
     * @param  array<string, mixed>  $catalog
     * @return list<string>
     */
    public function declaredPermissions(array $catalog): array
    {
        $names = [];
        $this->walk((array) ($catalog['entities'] ?? []), null, $catalog, function (string $entity, string $type) use (&$names) {
            $names[] = Permission::nameFor($type, $entity);
        });

        return $names;
    }

    /**
     * @param  array<string, array<string, mixed>>  $entities
     * @param  array<string, mixed>  $catalog
     * @param  array<string, int>  $stats
     */
    private function syncEntities(array $entities, ?string $parent, array $catalog, array &$stats): void
    {
        $this->walk($entities, $parent, $catalog, function (string $entity, string $type, ?string $label) use (&$stats) {
            $permission = Permission::firstOrCreate(
                ['name' => Permission::nameFor($type, $entity)],
                ['type' => $type, 'entity' => $entity, 'label' => $label],
            );

            if (! $permission->wasRecentlyCreated && $permission->label !== $label) {
                $permission->forceFill(['label' => $label])->save();
            }

            $stats['permissions_created'] += $permission->wasRecentlyCreated ? 1 : 0;
        });
    }

    /**
     * @param  array<string, array<string, mixed>>  $entities
     * @param  array<string, mixed>  $catalog
     * @param  callable(string, string, ?string): void  $visit
     */
    private function walk(array $entities, ?string $parent, array $catalog, callable $visit): void
    {
        $knownTypes = (array) ($catalog['types'] ?? []);
        $defaultTypes = (array) ($catalog['default_types'] ?? $knownTypes);

        foreach ($entities as $name => $definition) {
            $this->assertEntityName((string) $name);
            $entity = $parent === null ? (string) $name : $parent.'-'.$name;

            foreach ((array) ($definition['types'] ?? $defaultTypes) as $type) {
                if ($knownTypes !== [] && ! in_array($type, $knownTypes, true)) {
                    throw new InvalidArgumentException("Unknown permission type [{$type}] on entity [{$entity}].");
                }

                $visit($entity, (string) $type, isset($definition['label']) ? (string) $definition['label'] : null);
            }

            $this->walk((array) ($definition['children'] ?? []), $entity, $catalog, $visit);
        }
    }

    /**
     * @param  array<string, string|null>  $roles
     * @param  array<string, int>  $stats
     */
    private function syncRoles(array $roles, array &$stats): void
    {
        foreach ($roles as $name => $label) {
            $role = Role::firstOrCreate(['name' => $name], ['label' => $label]);

            if (! $role->wasRecentlyCreated && $label !== null && $role->label !== $label) {
                $role->forceFill(['label' => $label])->save();
            }

            $stats['roles_created'] += $role->wasRecentlyCreated ? 1 : 0;
        }
    }

    /**
     * @param  array<string, mixed>  $catalog
     * @param  array<string, int>  $stats
     */
    private function syncGrants(array $catalog, array &$stats): void
    {
        $all = Permission::query()->pluck('id', 'name');
        $adminRole = $catalog['admin_role'] ?? null;
        $adminOnly = (array) ($catalog['admin_only'] ?? []);

        foreach ((array) ($catalog['grants'] ?? []) as $roleName => $grants) {
            $role = Role::where('name', $roleName)->first();

            if (! $role) {
                continue;
            }

            $grants = (array) $grants;
            $excluded = $roleName === $adminRole ? [] : $adminOnly;
            $ids = $all->filter(fn (int $id, string $name) => (in_array('*', $grants, true) || in_array($name, $grants, true)) && ! in_array($name, $excluded, true))
                ->values()->all();

            $stats['grants_added'] += count($role->permissions()->syncWithoutDetaching($ids)['attached']);
        }
    }

    /**
     * @param  array<string, list<string>>  $inherits
     * @param  array<string, int>  $stats
     */
    private function syncInheritance(array $inherits, array &$stats): void
    {
        foreach ($inherits as $roleName => $parents) {
            $role = Role::where('name', $roleName)->first();

            if (! $role) {
                continue;
            }

            $inherited = Permission::whereHas('roles', fn ($query) => $query->whereIn('name', (array) $parents))->pluck('id')->all();
            $stats['grants_added'] += count($role->permissions()->syncWithoutDetaching($inherited)['attached']);
        }
    }

    private function assertEntityName(string $name): void
    {
        if (preg_match('/^[a-z0-9]+(-[a-z0-9]+)*$/', $name) !== 1) {
            throw new InvalidArgumentException("Permission entity [{$name}] must be kebab-case (no underscores).");
        }
    }
}
