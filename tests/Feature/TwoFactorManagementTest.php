<?php

namespace SecureAuth\Tests\Feature;

use Illuminate\Support\Facades\DB;
use SecureAuth\Models\AuthSession;
use SecureAuth\Models\RecoveryCode;
use SecureAuth\Models\TwoFactorMethod;
use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\Concerns\UsesTwoFactor;
use SecureAuth\Tests\Fixtures\User;
use SecureAuth\Tests\TestCase;
use SecureAuth\TwoFactor\TwoFactorManager;

class TwoFactorManagementTest extends TestCase
{
    use UsesAuthSessions;
    use UsesTwoFactor;

    private User $user;

    private string $token;

    private string $cookie;

    protected function setUp(): void
    {
        parent::setUp();
        $this->user = $this->createUser();
        ['token' => $this->token, 'cookie' => $this->cookie] = $this->loginWithCookie($this->user);
    }

    /** @return array<string, string> */
    private function auth(): array
    {
        return $this->bearer($this->token);
    }

    /** @return array{secret: string, codes: list<string>} */
    private function enrol(): array
    {
        $start = $this->postJson('/api/me/two-factor/totp', [], $this->auth())->assertOk();
        $secret = $start->json('secret');
        $confirm = $this->postJson('/api/me/two-factor/totp/confirm', ['code' => $this->totpCode($secret)], $this->auth())->assertOk();

        return ['secret' => $secret, 'codes' => $confirm->json('recovery_codes')];
    }

    public function test_a_guest_cannot_manage_two_factor(): void
    {
        foreach (['GET /api/me/two-factor', 'POST /api/me/two-factor/totp', 'POST /api/me/two-factor/totp/confirm', 'DELETE /api/me/two-factor/totp', 'POST /api/me/two-factor/recovery-codes'] as $route) {
            [$method, $uri] = explode(' ', $route);
            $this->forgetAuthentication();

            $this->json($method, $uri)->assertUnauthorized();
        }
    }

    public function test_the_summary_of_a_user_without_two_factor(): void
    {
        $this->getJson('/api/me/two-factor', $this->auth())->assertOk()->assertExactJson([
            'enabled' => false,
            'confirmed_at' => null,
            'last_used_at' => null,
            'recovery_codes_remaining' => 0,
            'required_at' => null,
            'setup_required' => false,
        ]);
    }

    public function test_starting_returns_the_secret_the_otpauth_url_and_a_server_side_svg_qr(): void
    {
        $response = $this->postJson('/api/me/two-factor/totp', [], $this->auth());

        $response->assertOk()->assertHeader('Cache-Control', 'no-store, private');
        $this->assertMatchesRegularExpression('/^[A-Z2-7]{32}$/', $response->json('secret'));
        $this->assertStringStartsWith('otpauth://totp/', $response->json('otpauth_url'));
        $this->assertStringContainsString('secret='.$response->json('secret'), $response->json('otpauth_url'));
        $this->assertStringContainsString(rawurlencode($this->user->email), $response->json('otpauth_url'));
        $this->assertStringStartsWith('<svg', $response->json('qr_svg'));
        $this->assertStringNotContainsString('http', str_replace(['http://www.w3.org'], '', $response->json('qr_svg')));
    }

    public function test_the_secret_is_stored_encrypted(): void
    {
        $secret = $this->postJson('/api/me/two-factor/totp', [], $this->auth())->json('secret');

        $stored = DB::table('two_factor_methods')->where('user_id', $this->user->id)->value('secret');

        $this->assertNotSame($secret, $stored);
        $this->assertStringNotContainsString($secret, (string) $stored);
        $this->assertSame($secret, decrypt($stored, false));
    }

    public function test_a_pending_app_does_not_count_as_enabled(): void
    {
        $this->postJson('/api/me/two-factor/totp', [], $this->auth())->assertOk();

        $this->getJson('/api/me/two-factor', $this->auth())->assertJsonPath('enabled', false);
    }

    public function test_prune_keeps_an_enrolment_restarted_today_even_if_first_started_days_ago(): void
    {
        $manager = app(TwoFactorManager::class);
        $manager->startTotp($this->user);
        $this->travel(2)->days();
        $manager->startTotp($this->user);

        $this->artisan('secure-auth:prune')->assertSuccessful();

        $this->assertNotNull($manager->pendingTotp($this->user));
    }

    public function test_a_wrong_code_does_not_confirm_the_app(): void
    {
        $this->postJson('/api/me/two-factor/totp', [], $this->auth())->assertOk();

        $this->postJson('/api/me/two-factor/totp/confirm', ['code' => '000000'], $this->auth())->assertStatus(422)->assertJsonValidationErrors(['code']);
    }

    public function test_confirming_without_starting_fails(): void
    {
        $this->postJson('/api/me/two-factor/totp/confirm', ['code' => '123456'], $this->auth())->assertStatus(422);
    }

    public function test_confirming_returns_ten_hashed_recovery_codes(): void
    {
        $result = $this->enrol();

        $this->assertCount(10, $result['codes']);
        $this->assertNull(RecoveryCode::where('code_hash', $result['codes'][0])->first());
        $this->getJson('/api/me/two-factor', $this->auth())->assertJsonPath('enabled', true)->assertJsonPath('recovery_codes_remaining', 10);
    }

    public function test_confirming_counts_as_a_fresh_second_factor_for_the_session(): void
    {
        $this->travel(5)->minutes();

        $this->enrol();

        $session = AuthSession::firstOrFail();
        $this->assertSame(['pwd', 'otp'], $session->amr);
        $this->assertEquals(now()->getTimestamp(), $session->last_mfa_at->getTimestamp());
    }

    public function test_the_secret_is_never_returned_after_the_activation(): void
    {
        $result = $this->enrol();

        $this->getJson('/api/me/two-factor', $this->auth())->assertOk()->assertDontSee($result['secret']);
    }

    public function test_the_app_cannot_be_started_again_while_it_is_active(): void
    {
        $this->enrol();

        $this->postJson('/api/me/two-factor/totp', [], $this->auth())->assertStatus(422)->assertJsonPath('reason', 'two_factor_already_enabled');
    }

    public function test_starting_needs_a_recent_authentication(): void
    {
        $this->token = $this->refreshAfterElevenMinutes();

        $this->postJson('/api/me/two-factor/totp', [], $this->auth())->assertForbidden()->assertJsonPath('reason', 'mfa_required');
    }

    public function test_regenerating_the_recovery_codes_invalidates_the_old_ones(): void
    {
        $old = $this->enrol()['codes'];

        $new = $this->postJson('/api/me/two-factor/recovery-codes', [], $this->auth())->assertOk()->assertHeader('Cache-Control', 'no-store, private')->json('recovery_codes');

        $this->assertCount(10, $new);
        $this->assertSame([], array_intersect($old, $new));
        $this->assertSame(10, RecoveryCode::where('user_id', $this->user->id)->count());
        $this->forgetAuthentication();
        $challenge = $this->postLogin(['email' => $this->user->email, 'password' => self::PASSWORD])->json('challenge');
        $this->postJson('/api/auth/two-factor', ['challenge' => $challenge, 'method' => 'recovery', 'code' => $old[0]], $this->xhrHeaders())->assertStatus(422);
    }

    public function test_recovery_codes_cannot_be_generated_without_the_app(): void
    {
        $this->postJson('/api/me/two-factor/recovery-codes', [], $this->auth())->assertStatus(422)->assertJsonPath('reason', 'two_factor_not_enabled');
    }

    public function test_disabling_removes_the_app_and_the_recovery_codes(): void
    {
        $this->enrol();

        $this->deleteJson('/api/me/two-factor/totp', [], $this->auth())->assertOk()->assertJsonPath('enabled', false);

        $this->assertSame(0, TwoFactorMethod::count());
        $this->assertSame(0, RecoveryCode::count());
    }

    public function test_disabling_needs_a_recent_authentication(): void
    {
        $this->enrol();
        $this->token = $this->refreshAfterElevenMinutes();

        $this->deleteJson('/api/me/two-factor/totp', [], $this->auth())->assertForbidden()->assertJsonPath('reason', 'mfa_required');
        $this->assertSame(1, TwoFactorMethod::count());
    }

    public function test_two_factor_cannot_be_disabled_when_the_account_requires_it(): void
    {
        $this->user->forceFill(['two_factor_required_at' => now()->addDays(7)])->save();
        $this->enrol();

        $this->deleteJson('/api/me/two-factor/totp', [], $this->auth())->assertStatus(422)->assertJsonPath('reason', 'two_factor_mandatory');
    }

    /** The session stays alive (refreshing) but its last strong authentication gets older than ten minutes. */
    private function refreshAfterElevenMinutes(): string
    {
        $this->travel(11)->minutes();
        $response = $this->refreshWith($this->cookie)->assertOk();
        $this->cookie = $this->cookieValue($response);

        return $response->json('authorization.token');
    }
}
