<?php

namespace SecureAuth\Tests\Feature;

use Illuminate\Support\Facades\Event;
use SecureAuth\Audit\SecurityEventType;
use SecureAuth\Events\SessionRevoked;
use SecureAuth\Models\AuthSession;
use SecureAuth\Models\SecurityEvent;
use SecureAuth\Sessions\SessionCookie;
use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\TestCase;
use SecureAuth\Tokens\AccessTokens;
use Symfony\Component\HttpFoundation\Cookie;

class RefreshSessionTest extends TestCase
{
    use UsesAuthSessions;

    private function loginCookie(bool $remember = false): Cookie
    {
        $user = $this->createUser();
        $response = $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD, 'remember' => $remember])->assertOk();

        return $response->getCookie(SessionCookie::name(), false);
    }

    private function travelPastTheReuseGrace(): void
    {
        $this->travel((int) config('secure-auth.session.reuse_grace_seconds') + 1)->seconds();
    }

    public function test_login_sets_a_http_only_strict_secure_cookie_scoped_to_the_auth_routes(): void
    {
        $cookie = $this->loginCookie();

        $this->assertTrue($cookie->isHttpOnly());
        $this->assertSame('strict', $cookie->getSameSite());
        $this->assertSame('/api/auth', $cookie->getPath());
        $this->assertTrue($cookie->isSecure());
    }

    public function test_the_cookie_path_follows_the_route_prefix(): void
    {
        config(['secure-auth.routes.prefix' => 'v2/api']);

        $this->assertSame('/v2/api/auth', SessionCookie::path());
    }

    public function test_the_cookie_name_is_configurable(): void
    {
        config(['secure-auth.session.cookie' => 'host_session']);

        $this->assertSame('host_session', $this->loginCookie()->getName());
    }

    public function test_the_cookie_is_selector_dot_secret_and_never_stores_the_secret(): void
    {
        [$selector, $secret] = explode('.', $this->loginCookie()->getValue());

        $session = AuthSession::firstOrFail();

        $this->assertSame($selector, $session->selector);
        $this->assertSame(hash('sha256', $secret), $session->secret_hash);
        $this->assertStringNotContainsString($secret, json_encode($session->getAttributes()));
    }

    public function test_the_secure_attribute_can_be_turned_off_for_local_http(): void
    {
        config(['secure-auth.session.cookie_secure' => false]);

        $this->assertFalse($this->loginCookie()->isSecure());
    }

    public function test_without_remember_me_the_cookie_dies_with_the_browser(): void
    {
        $this->assertSame(0, $this->loginCookie(false)->getExpiresTime());
    }

    public function test_remember_me_keeps_the_cookie_for_thirty_days(): void
    {
        $this->assertSame(now()->addDays(30)->getTimestamp(), $this->loginCookie(true)->getExpiresTime());
    }

    public function test_login_does_not_return_a_refresh_token_in_the_body(): void
    {
        $user = $this->createUser();

        $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD])->assertOk()->assertJsonMissingPath('authorization.refresh_token');
    }

    public function test_the_session_keeps_a_readable_device_and_not_the_raw_user_agent(): void
    {
        $user = $this->createUser();
        $agent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36';

        $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD], $this->xhrHeaders() + ['User-Agent' => $agent])->assertOk();

        $this->assertSame('Chrome · Windows', AuthSession::firstOrFail()->device_label);
        $this->assertNotContains($agent, AuthSession::firstOrFail()->getAttributes());
    }

    public function test_refreshing_returns_a_new_access_token(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $response = $this->refreshWith($session['cookie']);

        $response->assertOk()->assertJsonPath('authorization.type', 'bearer')->assertJsonPath('authorization.expires_in', 600);
        $this->getJson('/api/me', $this->bearer($response->json('authorization.token')))->assertOk();
    }

    public function test_refreshing_rotates_the_secret_and_keeps_the_selector(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $rotated = $this->cookieValue($this->refreshWith($session['cookie'])->assertOk());

        $this->assertNotSame($session['cookie'], $rotated);
        $this->assertSame(explode('.', $session['cookie'])[0], explode('.', $rotated)[0]);
    }

    public function test_the_rotated_cookie_keeps_the_hardened_attributes(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $cookie = $this->refreshWith($session['cookie'])->getCookie(SessionCookie::name(), false);

        $this->assertTrue($cookie->isHttpOnly() && $cookie->isSecure());
        $this->assertSame('strict', $cookie->getSameSite());
        $this->assertSame('/api/auth', $cookie->getPath());
    }

    public function test_the_rotated_cookie_works_for_the_next_refresh(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $rotated = $this->cookieValue($this->refreshWith($session['cookie']));

        $this->refreshWith($rotated)->assertOk();
    }

    public function test_reusing_a_rotated_secret_is_rejected(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $this->refreshWith($session['cookie'])->assertOk();
        $this->travelPastTheReuseGrace();

        $this->refreshWith($session['cookie'])->assertStatus(401)->assertJsonPath('reason', 'session_invalid');
    }

    public function test_a_rotated_secret_arriving_right_after_the_rotation_is_accepted_without_a_new_cookie(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $rotated = $this->cookieValue($this->refreshWith($session['cookie']));

        $again = $this->refreshWith($session['cookie'])->assertOk();

        $this->assertNull($again->getCookie(SessionCookie::name(), false), 'it does not rotate again');
        $this->refreshWith($rotated)->assertOk();
    }

    public function test_reusing_a_rotated_secret_closes_the_whole_family_even_for_the_legitimate_holder(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $legitimate = $this->cookieValue($this->refreshWith($session['cookie']));
        $this->travelPastTheReuseGrace();
        $this->refreshWith($session['cookie'])->assertStatus(401);

        $this->refreshWith($legitimate)->assertStatus(401);
    }

    public function test_reuse_detection_cuts_the_live_access_token(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $fresh = $this->refreshWith($session['cookie'])->json('authorization.token');
        $this->travelPastTheReuseGrace();
        $this->refreshWith($session['cookie'])->assertStatus(401);

        $this->getJson('/api/me', $this->bearer($fresh))->assertUnauthorized()->assertJsonPath('reason', 'session_revoked');
    }

    public function test_reuse_detection_announces_the_revocation_and_records_it(): void
    {
        $user = $this->createUser();
        $session = $this->loginWithCookie($user);
        $this->refreshWith($session['cookie'])->assertOk();
        $this->travelPastTheReuseGrace();
        Event::fake([SessionRevoked::class]);

        $this->refreshWith($session['cookie'])->assertStatus(401);

        Event::assertDispatched(SessionRevoked::class, fn (SessionRevoked $event) => $event->reason === SessionRevoked::REASON_REUSE);
    }

    public function test_reuse_detection_is_written_to_the_security_history(): void
    {
        $user = $this->createUser();
        $session = $this->loginWithCookie($user);
        $this->refreshWith($session['cookie'])->assertOk();
        $this->travelPastTheReuseGrace();

        $this->refreshWith($session['cookie'])->assertStatus(401);

        $this->assertTrue(SecurityEvent::where('user_id', $user->id)->where('type', SecurityEventType::SESSION_REUSE_DETECTED)->exists());
    }

    public function test_a_secret_older_than_the_previous_one_also_closes_the_session_and_is_recorded(): void
    {
        $user = $this->createUser();
        $session = $this->loginWithCookie($user);
        $first = $this->cookieValue($this->refreshWith($session['cookie']));
        $this->travelPastTheReuseGrace();
        $latest = $this->cookieValue($this->refreshWith($first));
        $this->travelPastTheReuseGrace();

        $this->refreshWith($session['cookie'])->assertStatus(401);

        $this->refreshWith($latest)->assertStatus(401);
        $this->assertTrue(SecurityEvent::where('user_id', $user->id)->where('type', SecurityEventType::SESSION_REUSE_DETECTED)->exists());
    }

    public function test_a_wrong_secret_with_a_valid_selector_closes_the_session(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $selector = explode('.', $session['cookie'])[0];

        $this->refreshWith($selector.'.'.str_repeat('a', 48))->assertStatus(401);

        $this->refreshWith($session['cookie'])->assertStatus(401);
    }

    public function test_an_unknown_selector_is_rejected(): void
    {
        $this->refreshWith(str_repeat('b', 24).'.'.str_repeat('a', 48))->assertStatus(401);
    }

    public function test_a_malformed_cookie_is_rejected(): void
    {
        $this->refreshWith('not-a-session-cookie')->assertStatus(401);
    }

    public function test_a_rejected_refresh_clears_the_cookie(): void
    {
        $cookie = $this->refreshWith(str_repeat('b', 24).'.'.str_repeat('a', 48))->getCookie(SessionCookie::name(), false);

        $this->assertTrue($cookie->isCleared());
    }

    public function test_refreshing_without_a_cookie_answers_no_content(): void
    {
        $this->postJson('/api/auth/refresh', [], $this->xhrHeaders())->assertNoContent();
    }

    public function test_refreshing_requires_the_xhr_header(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $this->refreshWith($session['cookie'], ['Origin' => 'http://localhost'])->assertForbidden();
    }

    public function test_refreshing_from_a_foreign_origin_is_rejected(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $this->refreshWith($session['cookie'], $this->xhrHeaders('https://evil.example'))->assertForbidden();
    }

    public function test_a_rejected_cross_site_refresh_does_not_rotate_the_secret(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $this->refreshWith($session['cookie'], $this->xhrHeaders('https://evil.example'))->assertForbidden();

        $this->refreshWith($session['cookie'])->assertOk();
    }

    public function test_refreshing_without_origin_or_referer_is_rejected(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $this->refreshWith($session['cookie'], ['X-Requested-With' => 'XMLHttpRequest'])->assertForbidden();
    }

    public function test_the_referer_is_accepted_when_there_is_no_origin(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $this->refreshWith($session['cookie'], ['X-Requested-With' => 'XMLHttpRequest', 'Referer' => 'http://localhost/login'])->assertOk();
    }

    public function test_the_configured_origins_are_accepted(): void
    {
        config(['secure-auth.allowed_origins' => ['https://app.example']]);
        $session = $this->loginWithCookie($this->createUser());

        $this->refreshWith($session['cookie'], $this->xhrHeaders('https://app.example'))->assertOk();
    }

    public function test_the_cors_origins_are_used_when_none_are_configured(): void
    {
        config(['cors.allowed_origins' => ['https://spa.example']]);
        $session = $this->loginWithCookie($this->createUser());

        $this->refreshWith($session['cookie'], $this->xhrHeaders('https://spa.example'))->assertOk();
    }

    public function test_a_wildcard_cors_origin_is_never_trusted(): void
    {
        config(['cors.allowed_origins' => ['*']]);
        $session = $this->loginWithCookie($this->createUser());

        $this->refreshWith($session['cookie'], $this->xhrHeaders('https://evil.example'))->assertForbidden();
    }

    public function test_an_idle_session_expires(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $this->travelTo(now()->addHours(25));

        $this->refreshWith($session['cookie'])->assertStatus(401);
    }

    public function test_activity_slides_the_expiry_forward(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $this->travelTo(now()->addHours(20));
        $this->refreshWith($session['cookie'])->assertOk();

        $this->assertEquals(now()->addHours(24)->getTimestamp(), AuthSession::firstOrFail()->expires_at->getTimestamp());
    }

    public function test_the_sliding_expiry_never_goes_beyond_the_absolute_limit(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $stored = AuthSession::firstOrFail();
        $stored->forceFill(['absolute_expires_at' => now()->addHours(2)])->save();

        $this->refreshWith($session['cookie'])->assertOk();

        $this->assertEquals(now()->addHours(2)->getTimestamp(), $stored->fresh()->expires_at->getTimestamp());
    }

    public function test_the_absolute_limit_ends_the_session_even_with_activity(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        AuthSession::firstOrFail()->forceFill(['absolute_expires_at' => now()->addHours(2)])->save();
        $this->travelTo(now()->addHours(3));

        $this->refreshWith($session['cookie'])->assertStatus(401);
    }

    public function test_the_absolute_limit_is_seven_days_without_remember_me(): void
    {
        $this->loginWithCookie($this->createUser(), false);

        $this->assertSame(now()->addDays(7)->getTimestamp(), AuthSession::firstOrFail()->absolute_expires_at->getTimestamp());
    }

    public function test_the_absolute_limit_is_thirty_days_with_remember_me(): void
    {
        $this->loginWithCookie($this->createUser(), true);

        $this->assertSame(now()->addDays(30)->getTimestamp(), AuthSession::firstOrFail()->absolute_expires_at->getTimestamp());
    }

    public function test_a_revoked_session_cannot_be_refreshed(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        AuthSession::firstOrFail()->forceFill(['revoked_at' => now()])->save();

        $this->refreshWith($session['cookie'])->assertStatus(401);
    }

    public function test_a_blocked_account_cannot_refresh(): void
    {
        $user = $this->createUser();
        $session = $this->loginWithCookie($user);
        $user->forceFill(['blocked_at' => now()])->save();

        $this->refreshWith($session['cookie'])->assertStatus(401);
    }

    public function test_a_refreshed_token_keeps_the_original_authentication_time(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $loggedInAt = now()->getTimestamp();
        $this->travel(2)->hours();

        $token = $this->refreshWith($session['cookie'])->json('authorization.token');

        $this->assertSame($loggedInAt, app(AccessTokens::class)->parse($token)->authTime);
    }

    public function test_logging_out_closes_the_session_and_clears_the_cookie(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $response = $this->withSessionCookie($session['cookie'])->postJson('/api/auth/logout', [], $this->xhrHeaders());

        $response->assertOk()->assertJsonPath('status', 'success');
        $this->assertTrue($response->getCookie(SessionCookie::name(), false)->isCleared());
        $this->assertNotNull(AuthSession::firstOrFail()->revoked_at);
    }

    public function test_a_session_closed_by_logging_out_cannot_be_refreshed(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $this->withSessionCookie($session['cookie'])->postJson('/api/auth/logout', [], $this->xhrHeaders())->assertOk();

        $this->refreshWith($session['cookie'])->assertStatus(401);
    }

    public function test_logging_out_cuts_the_access_token_of_the_session(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $this->withSessionCookie($session['cookie'])->postJson('/api/auth/logout', [], $this->xhrHeaders())->assertOk();

        $this->getJson('/api/me', $this->bearer($session['token']))->assertUnauthorized()->assertJsonPath('reason', 'session_revoked');
    }

    public function test_logging_out_with_only_the_bearer_token_closes_its_session(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $this->postJson('/api/auth/logout', [], $this->xhrHeaders() + $this->bearer($session['token']))->assertOk();

        $this->assertNotNull(AuthSession::firstOrFail()->revoked_at);
    }

    public function test_logging_out_works_with_an_expired_access_token(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $this->travelTo(now()->addMinutes(20));

        $this->withSessionCookie($session['cookie'])->postJson('/api/auth/logout', [], $this->xhrHeaders() + ['Authorization' => 'Bearer '.$session['token']])->assertOk();

        $this->assertNotNull(AuthSession::firstOrFail()->revoked_at);
    }

    public function test_logging_out_requires_the_xhr_header(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $this->withSessionCookie($session['cookie'])->postJson('/api/auth/logout', [], ['Origin' => 'http://localhost'])->assertForbidden();
    }

    public function test_logging_out_only_closes_the_session_of_the_cookie(): void
    {
        $user = $this->createUser();
        $first = $this->loginWithCookie($user);
        $second = $this->loginWithCookie($user);

        $this->withSessionCookie($first['cookie'])->postJson('/api/auth/logout', [], $this->xhrHeaders())->assertOk();

        $this->refreshWith($second['cookie'])->assertOk();
    }

    public function test_logging_out_without_a_session_is_harmless(): void
    {
        $this->postJson('/api/auth/logout', [], $this->xhrHeaders())->assertOk();
    }

    public function test_refreshing_is_rate_limited_per_session(): void
    {
        config(['secure-auth.rate_limits.refresh_session' => 2]);
        $session = $this->loginWithCookie($this->createUser());
        $rotated = $this->cookieValue($this->refreshWith($session['cookie']));
        $this->refreshWith($rotated)->assertOk();

        $this->refreshWith($rotated)->assertStatus(429);
    }
}
