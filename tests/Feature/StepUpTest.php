<?php

namespace SecureAuth\Tests\Feature;

use Illuminate\Support\Facades\Route;
use SecureAuth\Audit\SecurityEventType;
use SecureAuth\Models\AuthSession;
use SecureAuth\Models\SecurityEvent;
use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\Concerns\UsesTwoFactor;
use SecureAuth\Tests\Fixtures\User;
use SecureAuth\Tests\TestCase;

class StepUpTest extends TestCase
{
    use UsesAuthSessions;
    use UsesTwoFactor;

    protected function defineRoutes($router): void
    {
        Route::middleware(['api', 'secure-auth', 'secure-auth.recent-mfa:5'])->post('/api/payouts', fn () => ['ok' => true]);
        Route::middleware(['api', 'secure-auth', 'secure-auth.recent-mfa'])->post('/api/api-keys', fn () => ['ok' => true]);
    }

    /** @return array{token: string, cookie: string} */
    private function sessionOlderThan(User $user, int $minutes): array
    {
        $session = $this->loginWithCookie($user);
        $this->travel($minutes)->minutes();
        $response = $this->refreshWith($session['cookie'])->assertOk();

        return ['token' => $response->json('authorization.token'), 'cookie' => $this->cookieValue($response)];
    }

    public function test_a_fresh_login_passes_the_gate(): void
    {
        $token = $this->loginWithCookie($this->createUser())['token'];

        $this->postJson('/api/payouts', [], $this->bearer($token))->assertOk();
    }

    public function test_an_old_authentication_is_asked_to_step_up(): void
    {
        $session = $this->sessionOlderThan($this->createUser(), 6);

        $this->postJson('/api/payouts', [], $this->bearer($session['token']))->assertForbidden()->assertJsonPath('reason', 'mfa_required')->assertJsonPath('max_age', 300);
    }

    public function test_the_window_defaults_to_the_configured_minutes(): void
    {
        $session = $this->sessionOlderThan($this->createUser(), 8);

        $this->postJson('/api/api-keys', [], $this->bearer($session['token']))->assertOk();
        $this->travel(3)->minutes();
        $this->postJson('/api/api-keys', [], $this->bearer($this->refreshWith($session['cookie'])->json('authorization.token')))->assertForbidden();
    }

    public function test_without_totp_the_password_is_enough_to_step_up(): void
    {
        $session = $this->sessionOlderThan($this->createUser(), 6);

        $this->postJson('/api/me/step-up', ['current_password' => self::PASSWORD], $this->bearer($session['token']))->assertOk();

        $this->postJson('/api/payouts', [], $this->bearer($session['token']))->assertOk();
    }

    public function test_a_wrong_password_does_not_step_up_and_is_recorded(): void
    {
        $user = $this->createUser();
        $session = $this->sessionOlderThan($user, 6);

        $this->postJson('/api/me/step-up', ['current_password' => 'wrong'], $this->bearer($session['token']))->assertStatus(422)->assertJsonValidationErrors(['current_password']);

        $this->postJson('/api/payouts', [], $this->bearer($session['token']))->assertForbidden();
        $this->assertTrue(SecurityEvent::where('user_id', $user->id)->where('type', SecurityEventType::STEP_UP_FAILED)->exists());
    }

    public function test_with_totp_a_current_code_is_also_needed(): void
    {
        $user = $this->createUser();
        $totp = $this->enableTotp($user);
        $session = $this->loginThroughTotp($user, $totp['secret']);
        $this->travel(6)->minutes();
        $token = $this->refreshWith($session['cookie'])->json('authorization.token');

        $this->postJson('/api/me/step-up', ['current_password' => self::PASSWORD], $this->bearer($token))->assertStatus(422)->assertJsonValidationErrors(['code']);
        $this->postJson('/api/me/step-up', ['current_password' => self::PASSWORD, 'method' => 'totp', 'code' => $this->freshTotpCode($totp['secret'])], $this->bearer($token))->assertOk();

        $this->postJson('/api/payouts', [], $this->bearer($token))->assertOk();
    }

    public function test_a_recovery_code_can_step_up(): void
    {
        $user = $this->createUser();
        $totp = $this->enableTotp($user);
        $session = $this->loginThroughTotp($user, $totp['secret']);
        $this->travel(6)->minutes();
        $token = $this->refreshWith($session['cookie'])->json('authorization.token');

        $this->postJson('/api/me/step-up', ['current_password' => self::PASSWORD, 'method' => 'recovery', 'code' => $totp['recovery_codes'][0]], $this->bearer($token))->assertOk();

        $this->assertContains('recovery', AuthSession::firstOrFail()->amr);
    }

    public function test_stepping_up_updates_only_the_current_session(): void
    {
        $user = $this->createUser();
        $other = $this->sessionOlderThan($user, 0);
        $mine = $this->sessionOlderThan($user, 6);
        $other['token'] = $this->refreshWith($other['cookie'])->json('authorization.token');

        $this->postJson('/api/me/step-up', ['current_password' => self::PASSWORD], $this->bearer($mine['token']))->assertOk();

        $this->postJson('/api/payouts', [], $this->bearer($other['token']))->assertForbidden();
    }

    public function test_failed_step_ups_are_capped_per_account(): void
    {
        config(['secure-auth.rate_limits.two_factor_failures' => 2]);
        $session = $this->sessionOlderThan($this->createUser(), 6);
        $this->postJson('/api/me/step-up', ['current_password' => 'wrong'], $this->bearer($session['token']))->assertStatus(422);
        $this->postJson('/api/me/step-up', ['current_password' => 'wrong'], $this->bearer($session['token']))->assertStatus(422);

        $this->postJson('/api/me/step-up', ['current_password' => self::PASSWORD], $this->bearer($session['token']))->assertStatus(429);
    }

    public function test_the_step_up_route_requires_authentication(): void
    {
        $this->postJson('/api/me/step-up', ['current_password' => self::PASSWORD])->assertUnauthorized();
    }

    /** @return array{token: string, cookie: string} */
    private function loginThroughTotp(User $user, string $secret): array
    {
        $challenge = $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD])->json('challenge');
        $this->forgetAuthentication();
        $response = $this->postJson('/api/auth/two-factor', ['challenge' => $challenge, 'method' => 'totp', 'code' => $this->freshTotpCode($secret)], $this->xhrHeaders())->assertOk();

        return ['token' => $response->json('authorization.token'), 'cookie' => $this->cookieValue($response)];
    }
}
