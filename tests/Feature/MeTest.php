<?php

namespace SecureAuth\Tests\Feature;

use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\TestCase;

class MeTest extends TestCase
{
    use UsesAuthSessions;

    public function test_me_serves_the_identity_the_token_leaves_out(): void
    {
        $user = $this->createUser(['name' => 'Ana Pérez']);
        $session = $this->loginWithCookie($user);

        $this->getJson('/api/me', $this->bearer($session['token']))
            ->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertJsonPath('user.id', $user->id)
            ->assertJsonPath('user.email', $user->email)
            ->assertJsonPath('user.name', 'Ana Pérez')
            ->assertJsonPath('two_factor.enabled', false)
            ->assertJsonPath('session.id', $this->sessionIdOf($session['cookie']))
            ->assertJsonPath('session.amr', ['pwd'])
            ->assertJsonStructure(['permissions' => ['can', 'cannot']]);
    }

    public function test_me_never_exposes_the_password_hash(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $this->assertStringNotContainsString('$2y$', $this->getJson('/api/me', $this->bearer($session['token']))->getContent());
    }

    public function test_me_requires_authentication(): void
    {
        $this->getJson('/api/me')->assertUnauthorized();
    }
}
