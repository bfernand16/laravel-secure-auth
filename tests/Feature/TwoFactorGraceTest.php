<?php

namespace SecureAuth\Tests\Feature;

use Illuminate\Support\Facades\Route;
use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\Concerns\UsesTwoFactor;
use SecureAuth\Tests\TestCase;

class TwoFactorGraceTest extends TestCase
{
    use UsesAuthSessions;
    use UsesTwoFactor;

    protected function defineRoutes($router): void
    {
        Route::middleware(['api', 'secure-auth'])->get('/api/reports', fn () => ['ok' => true])->name('host.reports');
    }

    public function test_during_the_grace_period_everything_is_reachable(): void
    {
        $user = $this->createUser(['two_factor_required_at' => now()->addDays(3)]);
        $token = $this->loginWithCookie($user)['token'];

        $this->getJson('/api/reports', $this->bearer($token))->assertOk();
        $this->getJson('/api/me', $this->bearer($token))->assertOk()->assertJsonPath('two_factor.setup_required', false)->assertJsonPath('two_factor.required_at', now()->addDays(3)->toIso8601String());
    }

    public function test_after_the_grace_period_without_totp_only_the_setup_routes_are_reachable(): void
    {
        $user = $this->createUser(['two_factor_required_at' => now()->subMinute()]);
        $token = $this->loginWithCookie($user)['token'];

        $this->getJson('/api/reports', $this->bearer($token))->assertForbidden()->assertJsonPath('reason', 'two_factor_required');
        $this->getJson('/api/me/sessions', $this->bearer($token))->assertForbidden();
        $this->getJson('/api/me', $this->bearer($token))->assertOk()->assertJsonPath('two_factor.setup_required', true);
        $this->getJson('/api/me/two-factor', $this->bearer($token))->assertOk()->assertJsonPath('setup_required', true);
        $this->postJson('/api/me/two-factor/totp', [], $this->bearer($token))->assertOk();
    }

    public function test_after_setting_up_totp_everything_is_reachable_again(): void
    {
        $user = $this->createUser(['two_factor_required_at' => now()->subMinute()]);
        $token = $this->loginWithCookie($user)['token'];
        $secret = $this->postJson('/api/me/two-factor/totp', [], $this->bearer($token))->json('secret');

        $this->postJson('/api/me/two-factor/totp/confirm', ['code' => $this->totpCode($secret)], $this->bearer($token))->assertOk();

        $this->getJson('/api/reports', $this->bearer($token))->assertOk();
    }

    public function test_without_a_required_date_two_factor_stays_optional(): void
    {
        $token = $this->loginWithCookie($this->createUser())['token'];

        $this->getJson('/api/reports', $this->bearer($token))->assertOk();
    }

    public function test_the_setup_routes_are_configurable(): void
    {
        config(['secure-auth.two_factor.setup_routes' => ['secure-auth.me', 'host.reports']]);
        $user = $this->createUser(['two_factor_required_at' => now()->subMinute()]);
        $token = $this->loginWithCookie($user)['token'];

        $this->getJson('/api/reports', $this->bearer($token))->assertOk();
    }
}
