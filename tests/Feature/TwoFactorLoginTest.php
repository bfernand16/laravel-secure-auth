<?php

namespace SecureAuth\Tests\Feature;

use Illuminate\Support\Carbon;
use Illuminate\Testing\TestResponse;
use SecureAuth\Models\AuthSession;
use SecureAuth\Models\LoginChallenge;
use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\Concerns\UsesTwoFactor;
use SecureAuth\Tests\Fixtures\User;
use SecureAuth\Tests\TestCase;
use SecureAuth\Tokens\AccessTokens;

class TwoFactorLoginTest extends TestCase
{
    use UsesAuthSessions;
    use UsesTwoFactor;

    private User $user;

    /** @var array{secret: string, recovery_codes: list<string>} */
    private array $totp;

    protected function setUp(): void
    {
        parent::setUp();
        $this->user = $this->createUser();
        $this->totp = $this->enableTotp($this->user);
    }

    private function challenge(bool $remember = false): string
    {
        return $this->postLogin(['email' => $this->user->email, 'password' => self::PASSWORD, 'remember' => $remember])->assertOk()->json('challenge');
    }

    private function verify(string $challenge, string $method, string $code, ?array $headers = null): TestResponse
    {
        $this->forgetAuthentication();

        return $this->postJson('/api/auth/two-factor', ['challenge' => $challenge, 'method' => $method, 'code' => $code], $headers ?? $this->xhrHeaders());
    }

    public function test_the_challenge_is_stored_only_as_a_hash(): void
    {
        $challenge = $this->challenge();

        $this->assertNull(LoginChallenge::where('token_hash', $challenge)->first());
        $this->assertSame(hash('sha256', $challenge), LoginChallenge::firstOrFail()->token_hash);
    }

    public function test_a_valid_totp_code_opens_the_session_with_both_methods_in_the_token(): void
    {
        $challenge = $this->challenge();

        $response = $this->verify($challenge, 'totp', $this->freshTotpCode($this->totp['secret']));

        $response->assertOk()->assertJsonStructure(['authorization' => ['token', 'type', 'expires_in']]);
        $this->assertNotNull($response->getCookie('secure_auth_session', false));
        $this->assertSame(['pwd', 'otp'], app(AccessTokens::class)->parse($response->json('authorization.token'))->amr);
        $this->assertSame(1, AuthSession::where('user_id', $this->user->id)->count());
    }

    public function test_the_session_keeps_the_remember_me_choice_of_the_first_step(): void
    {
        $challenge = $this->challenge(remember: true);

        $this->verify($challenge, 'totp', $this->freshTotpCode($this->totp['secret']))->assertOk();

        $this->assertTrue(AuthSession::firstOrFail()->remember);
    }

    public function test_the_verify_route_checks_the_origin(): void
    {
        $challenge = $this->challenge();

        $this->verify($challenge, 'totp', $this->freshTotpCode($this->totp['secret']), $this->xhrHeaders('https://evil.example'))->assertForbidden();
    }

    public function test_a_challenge_cannot_be_used_twice(): void
    {
        $challenge = $this->challenge();
        $this->verify($challenge, 'totp', $this->freshTotpCode($this->totp['secret']))->assertOk();

        $this->verify($challenge, 'totp', $this->freshTotpCode($this->totp['secret']))->assertStatus(401)->assertJsonPath('reason', 'two_factor_challenge_invalid');
    }

    public function test_a_totp_code_cannot_be_used_twice(): void
    {
        $first = $this->challenge();
        $second = $this->challenge();
        $code = $this->freshTotpCode($this->totp['secret']);
        $this->verify($first, 'totp', $code)->assertOk();

        $this->verify($second, 'totp', $code)->assertStatus(422)->assertJsonPath('reason', 'two_factor_code_invalid');
    }

    public function test_an_older_code_than_the_last_used_one_is_rejected(): void
    {
        $first = $this->challenge();
        $second = $this->challenge();
        $this->verify($first, 'totp', $this->freshTotpCode($this->totp['secret']))->assertOk();

        $this->verify($second, 'totp', $this->totpCode($this->totp['secret'], -1))->assertStatus(422);
    }

    public function test_the_code_reuse_switch_does_nothing_in_production(): void
    {
        config(['secure-auth.two_factor.allow_code_reuse' => true]);
        $this->app['env'] = 'production';
        $first = $this->challenge();
        $second = $this->challenge();
        $code = $this->freshTotpCode($this->totp['secret']);
        $this->verify($first, 'totp', $code)->assertOk();

        $this->verify($second, 'totp', $code)->assertStatus(422);
    }

    public function test_the_code_reuse_switch_works_in_testing(): void
    {
        config(['secure-auth.two_factor.allow_code_reuse' => true]);
        $first = $this->challenge();
        $second = $this->challenge();
        $code = $this->freshTotpCode($this->totp['secret']);
        $this->verify($first, 'totp', $code)->assertOk();

        $this->verify($second, 'totp', $code)->assertOk();
    }

    public function test_a_totp_code_from_the_neighbour_interval_is_accepted(): void
    {
        $challenge = $this->challenge();
        Carbon::setTestNow(now()->addSeconds(60));

        $this->verify($challenge, 'totp', $this->totpCode($this->totp['secret'], -1))->assertOk();
    }

    public function test_a_totp_code_outside_the_window_is_rejected(): void
    {
        $challenge = $this->challenge();
        Carbon::setTestNow(now()->addSeconds(120));

        $this->verify($challenge, 'totp', $this->totpCode($this->totp['secret'], -2))->assertStatus(422);
    }

    public function test_a_wrong_code_says_how_many_attempts_are_left(): void
    {
        $this->verify($this->challenge(), 'totp', '000000')->assertStatus(422)->assertJsonPath('attempts_remaining', 4);
    }

    public function test_five_wrong_codes_exhaust_the_challenge(): void
    {
        $challenge = $this->challenge();
        foreach (range(1, 4) as $attempt) {
            $this->verify($challenge, 'totp', '000000')->assertStatus(422);
        }

        $this->verify($challenge, 'totp', '000000')->assertStatus(401)->assertJsonPath('reason', 'two_factor_attempts_exhausted');
    }

    public function test_the_right_code_does_not_work_after_the_attempts_are_exhausted(): void
    {
        $challenge = $this->challenge();
        foreach (range(1, 5) as $attempt) {
            $this->verify($challenge, 'totp', '000000');
        }

        $this->verify($challenge, 'totp', $this->freshTotpCode($this->totp['secret']))->assertStatus(401)->assertJsonMissingPath('authorization');
    }

    public function test_the_right_code_on_the_last_attempt_still_works(): void
    {
        $challenge = $this->challenge();
        foreach (range(1, 4) as $attempt) {
            $this->verify($challenge, 'totp', '000000');
        }

        $this->verify($challenge, 'totp', $this->freshTotpCode($this->totp['secret']))->assertOk();
    }

    public function test_a_challenge_expires_after_five_minutes(): void
    {
        $challenge = $this->challenge();
        Carbon::setTestNow(now()->addMinutes(6));

        $this->verify($challenge, 'totp', $this->totpCode($this->totp['secret']))->assertStatus(401)->assertJsonPath('reason', 'two_factor_challenge_invalid');
    }

    public function test_an_unknown_challenge_is_rejected(): void
    {
        $this->verify('not-a-challenge', 'totp', '123456')->assertStatus(401);
    }

    public function test_a_recovery_code_opens_the_session(): void
    {
        $response = $this->verify($this->challenge(), 'recovery', $this->totp['recovery_codes'][0])->assertOk();

        $this->assertSame(['pwd', 'recovery'], app(AccessTokens::class)->parse($response->json('authorization.token'))->amr);
    }

    public function test_a_recovery_code_works_only_once(): void
    {
        $first = $this->challenge();
        $second = $this->challenge();
        $this->verify($first, 'recovery', $this->totp['recovery_codes'][0])->assertOk();

        $this->verify($second, 'recovery', $this->totp['recovery_codes'][0])->assertStatus(422);
    }

    public function test_a_recovery_code_is_accepted_without_the_dash_and_in_upper_case(): void
    {
        $code = strtoupper(str_replace('-', '', $this->totp['recovery_codes'][1]));

        $this->verify($this->challenge(), 'recovery', $code)->assertOk();
    }

    public function test_a_recovery_code_of_another_user_is_rejected(): void
    {
        $otherCodes = $this->enableTotp($this->createUser())['recovery_codes'];

        $this->verify($this->challenge(), 'recovery', $otherCodes[0])->assertStatus(422);
    }

    public function test_a_challenge_belongs_to_the_user_that_logged_in(): void
    {
        $otherTotp = $this->enableTotp($this->createUser());
        $challenge = $this->challenge();

        $this->verify($challenge, 'totp', $this->freshTotpCode($otherTotp['secret']))->assertStatus(422);
    }

    public function test_too_many_failures_on_one_account_are_throttled_across_challenges(): void
    {
        config(['secure-auth.rate_limits.two_factor_failures' => 3]);
        $challenges = [$this->challenge(), $this->challenge()];
        $this->verify($challenges[0], 'totp', '000000');
        $this->verify($challenges[0], 'totp', '000000');
        $this->verify($challenges[1], 'totp', '000000');

        $this->verify($challenges[1], 'totp', $this->freshTotpCode($this->totp['secret']))->assertStatus(429)->assertJsonPath('reason', 'two_factor_throttled');
    }

    public function test_the_verify_route_is_limited_per_challenge(): void
    {
        config(['secure-auth.rate_limits.two_factor_challenge' => 2]);

        $this->verify('unknown', 'totp', '123456')->assertStatus(401);
        $this->verify('unknown', 'totp', '123456')->assertStatus(401);

        $this->verify('unknown', 'totp', '123456')->assertStatus(429)->assertHeader('Retry-After');
    }

    public function test_the_verify_route_is_limited_per_ip(): void
    {
        config(['secure-auth.rate_limits.two_factor_ip' => 2]);

        $this->verify('one', 'totp', '123456')->assertStatus(401);
        $this->verify('two', 'totp', '123456')->assertStatus(401);

        $this->verify('three', 'totp', '123456')->assertStatus(429);
    }

    public function test_the_verify_request_is_validated(): void
    {
        $this->forgetAuthentication();

        $this->postJson('/api/auth/two-factor', ['method' => 'sms'], $this->xhrHeaders())->assertStatus(422)->assertJsonValidationErrors(['challenge', 'method', 'code']);
    }

    public function test_a_blocked_account_gets_no_session_after_the_second_step(): void
    {
        $challenge = $this->challenge();
        $this->user->forceFill(['blocked_at' => now()])->save();

        $this->verify($challenge, 'recovery', $this->totp['recovery_codes'][0])->assertForbidden()->assertJsonMissingPath('authorization');
    }
}
