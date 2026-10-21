<?php

namespace SecureAuth\Tests\Feature;

use SecureAuth\Tests\TestCase;

class RoutesDisabledTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('secure-auth.routes.enabled', false);
    }

    public function test_the_host_can_skip_the_package_routes(): void
    {
        $this->assertFalse($this->app['router']->has('secure-auth.login'));
        $this->postJson('/api/auth/login')->assertNotFound();
    }
}
