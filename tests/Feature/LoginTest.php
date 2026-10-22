<?php

namespace SecureAuth\Tests\Feature;

use Illuminate\Support\Facades\Hash;
use SecureAuth\Audit\SecurityEventType;
use SecureAuth\Models\AuthSession;
use SecureAuth\Models\SecurityEvent;
use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\Concerns\UsesTwoFactor;
use SecureAuth\Tests\TestCase;
use SecureAuth\Tokens\AccessTokens;

class LoginTest extends TestCase
{
    use UsesAuthSessions;
    use UsesTwoFactor;

    public function test_valid_credentials_open_a_session_with_a_bearer_token(): void
    {
        $user = $this->createUser();

        $response = $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD]);

        $response->assertOk()
            ->assertJsonPath('two_factor', false)
            ->assertJsonPath('authorization.type', 'bearer')
            ->assertJsonPath('authorization.expires_in', 600)
            ->assertHeader('Cache-Control', 'no-store, private');
        $this->assertSame(1, AuthSession::where('user_id', $user->id)->count());
    }

    public function test_a_password_hashed_with_old_parameters_is_rehashed_on_login(): void
    {
        $old = password_hash(self::PASSWORD, PASSWORD_BCRYPT, ['cost' => 4]);
        $user = $this->createUser();
        $user->forceFill(['password' => $old])->save();
        config(['hashing.driver' => 'bcrypt', 'hashing.bcrypt.rounds' => 12, 'hashing.bcrypt.verify' => false]);
        Hash::forgetDrivers();

        $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD])->assertOk();

        $stored = $user->fresh()->password;
        $this->assertNotSame($old, $stored);
        $this->assertFalse(Hash::needsRehash($stored));
        $this->assertTrue(Hash::check(self::PASSWORD, $stored));
    }

    public function test_a_wrong_password_never_changes_the_stored_hash(): void
    {
        $old = password_hash(self::PASSWORD, PASSWORD_BCRYPT, ['cost' => 4]);
        $user = $this->createUser();
        $user->forceFill(['password' => $old])->save();
        config(['hashing.driver' => 'bcrypt', 'hashing.bcrypt.rounds' => 12, 'hashing.bcrypt.verify' => false]);
        Hash::forgetDrivers();

        $this->postLogin(['email' => $user->email, 'password' => 'wrong-password-1'])->assertUnauthorized();

        $this->assertSame($old, $user->fresh()->password);
    }

    public function test_the_access_token_lifetime_is_configurable(): void
    {
        config(['secure-auth.access_token.ttl_minutes' => 3]);
        $user = $this->createUser();

        $token = $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD])->json('authorization.token');
        $claims = app(AccessTokens::class)->parse($token);

        $this->assertSame(180, $claims->expiresAt - $claims->issuedAt);
    }

    public function test_the_token_carries_the_session_and_no_personal_data(): void
    {
        $user = $this->createUser(['name' => 'Ana Pérez']);
        $token = $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD])->json('authorization.token');

        $payload = json_decode(base64_decode(strtr(explode('.', $token)[1], '-_', '+/')), true);

        $this->assertSame(AuthSession::firstOrFail()->id, $payload['sid']);
        $this->assertSame((string) $user->id, $payload['sub']);
        $this->assertSame(['pwd'], $payload['amr']);
        $this->assertSame(now()->getTimestamp(), $payload['auth_time']);
        $this->assertArrayHasKey('pv', $payload);
        $this->assertSame([], array_intersect(['email', 'name'], array_keys($payload)));
        $this->assertStringNotContainsString('Ana', json_encode($payload));
    }

    public function test_a_wrong_password_gets_a_generic_error(): void
    {
        $user = $this->createUser();

        $this->postLogin(['email' => $user->email, 'password' => 'wrong'])
            ->assertStatus(401)
            ->assertJsonPath('reason', 'invalid_credentials')
            ->assertJsonMissingPath('authorization');
    }

    public function test_an_unknown_account_gets_exactly_the_same_error(): void
    {
        $user = $this->createUser();
        $wrong = $this->postLogin(['email' => $user->email, 'password' => 'wrong'])->json();

        $unknown = $this->postLogin(['email' => 'nobody@example.test', 'password' => 'wrong'])->assertStatus(401)->json();

        $this->assertSame($wrong, $unknown);
    }

    public function test_a_failed_login_on_an_existing_account_is_recorded_without_the_password(): void
    {
        $user = $this->createUser();

        $this->postLogin(['email' => $user->email, 'password' => 'my-guess'])->assertStatus(401);

        $event = SecurityEvent::where('user_id', $user->id)->firstOrFail();
        $this->assertSame(SecurityEventType::LOGIN_FAILED, $event->type);
        $this->assertStringNotContainsString('my-guess', json_encode($event->getAttributes()));
    }

    public function test_a_successful_login_is_recorded(): void
    {
        $user = $this->createUser();

        $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD])->assertOk();

        $this->assertTrue(SecurityEvent::where('user_id', $user->id)->where('type', SecurityEventType::LOGIN)->exists());
    }

    public function test_the_login_request_is_validated(): void
    {
        $this->postLogin([])->assertStatus(422)->assertJsonValidationErrors(['email', 'password']);
    }

    public function test_a_blocked_account_cannot_log_in(): void
    {
        $user = $this->createUser(['blocked_at' => now()]);

        $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD])->assertForbidden()->assertJsonPath('reason', 'account_blocked');
        $this->assertSame(0, AuthSession::count());
    }

    public function test_an_unverified_email_cannot_log_in(): void
    {
        $user = $this->createUser(['email_verified_at' => null]);

        $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD])->assertForbidden()->assertJsonPath('reason', 'email_unverified');
    }

    public function test_the_email_verification_requirement_can_be_turned_off(): void
    {
        config(['secure-auth.require_verified_email' => false]);
        $user = $this->createUser(['email_verified_at' => null]);

        $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD])->assertOk();
    }

    public function test_logins_are_limited_per_account_and_ip(): void
    {
        config(['secure-auth.rate_limits.login_account' => 2]);
        $user = $this->createUser();

        $this->postLogin(['email' => $user->email, 'password' => 'wrong'])->assertStatus(401);
        $this->postLogin(['email' => $user->email, 'password' => 'wrong'])->assertStatus(401);

        $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD])->assertStatus(429)->assertHeader('Retry-After');
    }

    public function test_the_account_limit_ignores_the_case_of_the_email(): void
    {
        config(['secure-auth.rate_limits.login_account' => 1]);
        $user = $this->createUser();

        $this->postLogin(['email' => $user->email, 'password' => 'wrong'])->assertStatus(401);

        $this->postLogin(['email' => strtoupper($user->email), 'password' => 'wrong'])->assertStatus(429);
    }

    public function test_logins_are_limited_per_ip_across_accounts(): void
    {
        config(['secure-auth.rate_limits.login_ip' => 2]);

        $this->postLogin(['email' => 'a@example.test', 'password' => 'wrong'])->assertStatus(401);
        $this->postLogin(['email' => 'b@example.test', 'password' => 'wrong'])->assertStatus(401);

        $this->postLogin(['email' => 'c@example.test', 'password' => 'wrong'])->assertStatus(429);
    }

    public function test_logging_in_requires_the_xhr_header_and_an_allowed_origin(): void
    {
        $user = $this->createUser();

        $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD], ['Origin' => 'http://localhost'])->assertForbidden()->assertJsonPath('reason', 'csrf_rejected');
        $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD], $this->xhrHeaders('https://evil.example'))->assertForbidden();
    }

    public function test_with_totp_the_first_step_returns_a_challenge_and_no_session(): void
    {
        $user = $this->createUser();
        $this->enableTotp($user);

        $response = $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD]);

        $response->assertOk()
            ->assertJsonPath('two_factor', true)
            ->assertJsonPath('methods', ['totp', 'recovery'])
            ->assertJsonPath('expires_in', 300)
            ->assertJsonMissingPath('authorization');
        $this->assertNotEmpty($response->json('challenge'));
        $this->assertNull($response->getCookie('secure_auth_session', false));
        $this->assertSame(0, AuthSession::count());
    }

    public function test_the_login_field_is_configurable(): void
    {
        config(['secure-auth.login_field' => 'name']);
        $user = $this->createUser(['name' => 'ana']);

        $this->postLogin(['name' => 'ana', 'password' => self::PASSWORD])->assertOk();
        $this->assertSame(1, AuthSession::where('user_id', $user->id)->count());
    }
}
