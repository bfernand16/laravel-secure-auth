<?php

namespace SecureAuth\Tests\Feature;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use InvalidArgumentException;
use SecureAuth\Contracts\PermissionResolver;
use SecureAuth\Models\Permission;
use SecureAuth\Models\Role;
use SecureAuth\Permissions\PermissionCache;
use SecureAuth\Permissions\PermissionCatalogSync;
use SecureAuth\Permissions\Permissions;
use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\TestCase;

class PermissionsTest extends TestCase
{
    use UsesAuthSessions;

    private const CATALOG = [
        'types' => ['create', 'view', 'edit', 'delete', 'execute'],
        'default_types' => ['view', 'edit'],
        'entities' => [
            'admin' => [
                'label' => 'permissions.admin',
                'types' => ['view'],
                'children' => [
                    'users' => ['label' => 'permissions.admin_users'],
                    'billing' => [
                        'types' => ['view', 'edit'],
                        'children' => ['refunds' => ['types' => ['execute']]],
                    ],
                ],
            ],
            'reports' => ['types' => ['view', 'create']],
        ],
        'roles' => ['admin' => 'roles.admin', 'staff' => 'roles.staff', 'user' => 'roles.user', 'manager' => 'roles.manager'],
        'admin_role' => 'admin',
        'admin_only' => ['edit_admin-billing', 'execute_admin-billing-refunds'],
        'inherits' => ['manager' => ['user']],
        'grants' => [
            'admin' => ['*'],
            'staff' => ['*'],
            'user' => ['view_reports'],
            'manager' => ['create_reports'],
        ],
    ];

    protected function defineRoutes($router): void
    {
        Route::middleware(['api', 'secure-auth', 'permission:view_reports'])->get('/api/reports', fn () => ['ok' => true]);
        Route::middleware(['api', 'secure-auth', 'secure-auth.permission:edit_admin-users|view_admin'])->get('/api/admin', fn () => ['ok' => true]);
    }

    private function sync(): array
    {
        return app(PermissionCatalogSync::class)->run(self::CATALOG);
    }

    public function test_sync_flattens_nested_entities_into_type_entity_names(): void
    {
        $this->sync();

        $this->assertEqualsCanonicalizing([
            'view_admin', 'view_admin-users', 'edit_admin-users', 'view_admin-billing', 'edit_admin-billing',
            'execute_admin-billing-refunds', 'view_reports', 'create_reports',
        ], Permission::pluck('name')->all());
        $this->assertSame('admin-billing-refunds', Permission::where('name', 'execute_admin-billing-refunds')->value('entity'));
        $this->assertSame('permissions.admin_users', Permission::where('name', 'view_admin-users')->value('label'));
    }

    public function test_sync_is_idempotent(): void
    {
        $first = $this->sync();
        $count = Permission::count();
        $grants = DB::table('role_permission')->count();

        $second = $this->sync();

        $this->assertSame(8, $first['permissions_created']);
        $this->assertSame(4, $first['roles_created']);
        $this->assertSame(['permissions_created' => 0, 'roles_created' => 0, 'grants_added' => 0], $second);
        $this->assertSame($count, Permission::count());
        $this->assertSame($grants, DB::table('role_permission')->count());
    }

    public function test_sync_never_removes_a_permission_nor_a_grant_made_by_an_admin(): void
    {
        $this->sync();
        $user = Role::where('name', 'user')->firstOrFail();
        $extra = Permission::where('name', 'view_admin')->firstOrFail();
        $user->permissions()->attach($extra->id);
        $catalog = self::CATALOG;
        unset($catalog['entities']['reports']);

        app(PermissionCatalogSync::class)->run($catalog);

        $this->assertTrue($user->permissions()->whereKey($extra->id)->exists());
        $this->assertTrue(Permission::where('name', 'view_reports')->exists());
        $this->assertTrue($user->permissions()->where('name', 'view_reports')->exists());
    }

    public function test_the_admin_role_gets_everything_including_the_admin_only_permissions(): void
    {
        $this->sync();

        $this->assertSame(Permission::count(), Role::where('name', 'admin')->firstOrFail()->permissions()->count());
    }

    public function test_a_wildcard_role_does_not_get_the_admin_only_permissions(): void
    {
        $this->sync();

        $staff = Role::where('name', 'staff')->firstOrFail()->permissions()->pluck('name')->all();

        $this->assertNotContains('edit_admin-billing', $staff);
        $this->assertNotContains('execute_admin-billing-refunds', $staff);
        $this->assertContains('view_admin-billing', $staff);
    }

    public function test_a_role_inherits_the_permissions_of_its_parents(): void
    {
        $this->sync();

        $this->assertEqualsCanonicalizing(['view_reports', 'create_reports'], Role::where('name', 'manager')->firstOrFail()->permissions()->pluck('name')->all());
    }

    public function test_an_entity_with_an_underscore_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        app(PermissionCatalogSync::class)->run(['types' => ['view'], 'entities' => ['bad_name' => ['types' => ['view']]]]);
    }

    public function test_an_unknown_type_is_rejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        app(PermissionCatalogSync::class)->run(['types' => ['view'], 'entities' => ['reports' => ['types' => ['launch']]]]);
    }

    public function test_the_command_syncs_the_published_catalog(): void
    {
        $this->artisan('secure-auth:permissions-sync')->assertSuccessful()->expectsOutputToContain('Permissions synced');

        $this->assertTrue(Permission::where('name', 'edit_admin-users')->exists());
        $this->assertTrue(Role::where('name', 'admin')->firstOrFail()->permissions()->where('name', 'edit_admin-users')->exists());
    }

    public function test_the_permission_middleware_lets_in_only_users_with_the_permission(): void
    {
        $this->sync();
        $allowed = $this->createUser();
        $allowed->assignRole('user');
        $denied = $this->createUser();

        $this->getJson('/api/reports', $this->bearer($this->loginWithCookie($allowed)['token']))->assertOk();
        $this->getJson('/api/reports', $this->bearer($this->loginWithCookie($denied)['token']))->assertForbidden()->assertJsonPath('reason', 'forbidden');
    }

    public function test_the_permission_middleware_accepts_any_of_several_permissions(): void
    {
        $this->sync();
        $user = $this->createUser();
        $user->assignRole('staff');

        $this->getJson('/api/admin', $this->bearer($this->loginWithCookie($user)['token']))->assertOk();
    }

    public function test_the_permission_middleware_requires_authentication(): void
    {
        $this->getJson('/api/reports')->assertUnauthorized();
    }

    public function test_me_returns_the_casl_rules(): void
    {
        $this->sync();
        $user = $this->createUser();
        $user->assignRole('manager');

        $response = $this->getJson('/api/me', $this->bearer($this->loginWithCookie($user)['token']))->assertOk();

        $this->assertEqualsCanonicalizing([['type' => 'create', 'entity' => 'reports'], ['type' => 'view', 'entity' => 'reports']], $response->json('permissions.can'));
        $this->assertContains(['type' => 'execute', 'entity' => 'admin-billing-refunds'], $response->json('permissions.cannot'));
        $this->assertCount(6, $response->json('permissions.cannot'));
    }

    public function test_user_permissions_are_cached_until_a_role_changes(): void
    {
        $this->sync();
        $user = $this->createUser();
        $user->assignRole('user');
        $this->assertTrue($user->hasPermission('view_reports'));

        DB::table('user_role')->delete();
        $this->assertTrue($user->fresh()->hasPermission('view_reports'), 'served from the cache');

        app(PermissionCache::class)->flush();
        $this->assertFalse($user->fresh()->hasPermission('view_reports'));
    }

    public function test_checking_a_permission_does_not_query_the_roles_on_every_call(): void
    {
        $this->sync();
        $user = $this->createUser();
        $user->assignRole('user');
        $user->hasPermission('view_reports');

        DB::enableQueryLog();
        $user->fresh()->hasPermission('view_reports');
        $user->fresh()->hasPermission('edit_admin-users');

        $this->assertSame([], array_values(array_filter(DB::getQueryLog(), fn ($query) => str_contains($query['query'], 'role_permission'))));
    }

    public function test_granting_and_revoking_on_a_role_refreshes_the_cache(): void
    {
        $this->sync();
        $user = $this->createUser();
        $user->assignRole('user');
        $role = Role::where('name', 'user')->firstOrFail();
        $this->assertFalse($user->hasPermission('view_admin'));

        $role->grant('view_admin');
        $this->assertTrue($user->fresh()->hasPermission('view_admin'));

        $role->revoke('view_admin');
        $this->assertFalse($user->fresh()->hasPermission('view_admin'));
    }

    public function test_roles_can_be_synced_and_removed(): void
    {
        $this->sync();
        $user = $this->createUser();
        $user->syncRoles(['user', 'staff']);
        $this->assertTrue($user->hasRole('staff'));

        $user->removeRole('staff');

        $this->assertFalse($user->hasRole('staff'));
        $this->assertFalse($user->hasPermission('view_admin'));
    }

    public function test_a_host_resolver_replaces_the_roles_tables(): void
    {
        $this->app->instance(PermissionResolver::class, new class implements PermissionResolver
        {
            public function permissionsOf(Authenticatable $user): array
            {
                return ['view_reports'];
            }

            public function catalog(): array
            {
                return ['view_reports', 'edit_reports'];
            }
        });
        $this->app->forgetInstance(Permissions::class);
        $user = $this->createUser();

        $response = $this->getJson('/api/me', $this->bearer($this->loginWithCookie($user)['token']))->assertOk();

        $response->assertJsonPath('permissions.can', [['type' => 'view', 'entity' => 'reports']]);
        $response->assertJsonPath('permissions.cannot', [['type' => 'edit', 'entity' => 'reports']]);
        $this->assertTrue($user->hasPermission('view_reports'));
    }
}
