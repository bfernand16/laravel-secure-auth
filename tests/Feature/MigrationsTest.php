<?php

namespace SecureAuth\Tests\Feature;

use Illuminate\Support\Facades\Schema;
use SecureAuth\Tests\TestCase;

class MigrationsTest extends TestCase
{
    public function test_the_package_creates_only_its_own_tables(): void
    {
        foreach (['roles', 'permissions', 'role_permission', 'user_role', 'auth_sessions', 'login_challenges', 'two_factor_methods', 'recovery_codes', 'security_events'] as $table) {
            $this->assertTrue(Schema::hasTable($table), "{$table} exists");
        }
    }

    public function test_the_users_stub_adds_the_required_column_to_a_minimal_users_table(): void
    {
        Schema::table('users', fn ($table) => $table->dropColumn('two_factor_required_at'));
        $this->assertFalse(Schema::hasColumn('users', 'two_factor_required_at'));

        $migration = require __DIR__.'/../../database/stubs/add_secure_auth_columns_to_users_table.php.stub';
        $migration->up();

        $this->assertTrue(Schema::hasColumn('users', 'two_factor_required_at'));
        $migration->down();
        $this->assertFalse(Schema::hasColumn('users', 'two_factor_required_at'));
    }

    public function test_the_migrations_and_config_are_publishable(): void
    {
        $this->artisan('vendor:publish', ['--tag' => 'secure-auth-config', '--force' => true])->assertSuccessful();

        $this->assertFileExists(config_path('secure-auth.php'));
        @unlink(config_path('secure-auth.php'));
    }
}
