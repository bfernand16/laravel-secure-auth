<?php

namespace SecureAuth\Tests;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Carbon;
use Orchestra\Testbench\TestCase as Orchestra;
use SecureAuth\SecureAuthServiceProvider;
use SecureAuth\Tests\Fixtures\User;

abstract class TestCase extends Orchestra
{
    use RefreshDatabase;

    public const PASSWORD = 'correct horse battery staple';

    protected function setUp(): void
    {
        parent::setUp();
        Carbon::setTestNow(Carbon::parse('2026-10-21 10:00:00'));
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        parent::tearDown();
    }

    protected function getPackageProviders($app): array
    {
        return [SecureAuthServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('auth.providers.users.model', User::class);
        $app['config']->set('secure-auth.user_model', User::class);
        $app['config']->set('app.url', 'http://localhost');
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }

    /** @param  array<string, mixed>  $attributes */
    protected function createUser(array $attributes = []): User
    {
        static $sequence = 0;
        $sequence++;

        return User::create($attributes + [
            'name' => 'User '.$sequence,
            'email' => "user{$sequence}@example.test",
            'password' => self::PASSWORD,
            'email_verified_at' => now(),
        ]);
    }
}
