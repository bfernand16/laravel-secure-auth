<?php

namespace SecureAuth\Tests\Feature;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use SecureAuth\Events\SessionRevoked;
use SecureAuth\Models\AuthSession;
use SecureAuth\Sessions\SessionCookie;
use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\TestCase;

class SessionsTest extends TestCase
{
    use UsesAuthSessions;

    public function test_the_sessions_of_the_account_are_listed_with_the_current_one_marked(): void
    {
        $user = $this->createUser();
        $first = $this->loginWithCookie($user);
        $second = $this->loginWithCookie($user);

        $response = $this->getJson('/api/me/sessions', $this->bearer($second['token']))->assertOk();

        $this->assertSame([$this->sessionIdOf($second['cookie'])], collect($response->json('sessions'))->where('current', true)->pluck('id')->all());
        $this->assertCount(2, $response->json('sessions'));
        $this->assertContains($this->sessionIdOf($first['cookie']), collect($response->json('sessions'))->pluck('id')->all());
    }

    public function test_a_listed_session_shows_the_device_and_dates_but_no_secrets(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        $response = $this->getJson('/api/me/sessions', $this->bearer($session['token']))->assertOk();

        $response->assertJsonStructure(['sessions' => [['id', 'device_label', 'ip', 'remember', 'amr', 'created_at', 'last_used_at', 'expires_at', 'absolute_expires_at', 'current']]]);
        $this->assertStringNotContainsString('secret', $response->getContent());
        $this->assertStringNotContainsString('selector', $response->getContent());
        $this->assertStringNotContainsString(explode('.', $session['cookie'])[0], $response->getContent());
    }

    public function test_the_list_never_includes_the_sessions_of_other_accounts(): void
    {
        $mine = $this->loginWithCookie($this->createUser());
        $this->loginWithCookie($this->createUser());

        $this->assertCount(1, $this->getJson('/api/me/sessions', $this->bearer($mine['token']))->json('sessions'));
    }

    public function test_closed_and_expired_sessions_are_not_listed(): void
    {
        $user = $this->createUser();
        $live = $this->loginWithCookie($user);
        $this->loginWithCookie($user);
        $this->loginWithCookie($user);
        $liveId = $this->sessionIdOf($live['cookie']);
        AuthSession::whereKeyNot($liveId)->orderBy('id')->firstOrFail()->forceFill(['revoked_at' => now()])->save();
        AuthSession::whereKeyNot($liveId)->whereNull('revoked_at')->firstOrFail()->forceFill(['expires_at' => now()->subMinute()])->save();

        $response = $this->getJson('/api/me/sessions', $this->bearer($live['token']))->assertOk();

        $this->assertSame([$liveId], collect($response->json('sessions'))->pluck('id')->all());
    }

    public function test_closing_another_session_stops_its_cookie_and_its_token_at_once(): void
    {
        $user = $this->createUser();
        $mine = $this->loginWithCookie($user);
        $other = $this->loginWithCookie($user);

        $this->deleteJson('/api/me/sessions/'.$this->sessionIdOf($other['cookie']), [], $this->bearer($mine['token']))->assertOk();

        $this->getJson('/api/me', $this->bearer($other['token']))->assertUnauthorized()->assertJsonPath('reason', 'session_revoked');
        $this->refreshWith($other['cookie'])->assertStatus(401);
        $this->getJson('/api/me', $this->bearer($mine['token']))->assertOk();
    }

    public function test_nobody_can_close_the_session_of_another_account(): void
    {
        $mine = $this->loginWithCookie($this->createUser());
        $victim = $this->loginWithCookie($this->createUser());

        $this->deleteJson('/api/me/sessions/'.$this->sessionIdOf($victim['cookie']), [], $this->bearer($mine['token']))->assertNotFound();

        $this->refreshWith($victim['cookie'])->assertOk();
    }

    public function test_closing_a_session_that_does_not_exist_is_not_found(): void
    {
        $mine = $this->loginWithCookie($this->createUser());

        $this->deleteJson('/api/me/sessions/999999', [], $this->bearer($mine['token']))->assertNotFound();
    }

    public function test_closing_the_current_session_also_clears_the_cookie(): void
    {
        $mine = $this->loginWithCookie($this->createUser());

        $response = $this->deleteJson('/api/me/sessions/'.$this->sessionIdOf($mine['cookie']), [], $this->bearer($mine['token']))->assertOk();

        $this->assertTrue($response->getCookie(SessionCookie::name(), false)->isCleared());
    }

    public function test_closing_all_the_others_keeps_only_the_current_session(): void
    {
        $user = $this->createUser();
        $mine = $this->loginWithCookie($user);
        $other = $this->loginWithCookie($user);
        $third = $this->loginWithCookie($user);
        $stranger = $this->loginWithCookie($this->createUser());

        $this->deleteJson('/api/me/sessions', [], $this->bearer($mine['token']))->assertOk()->assertJsonPath('closed', 2);

        $this->refreshWith($other['cookie'])->assertStatus(401);
        $this->refreshWith($third['cookie'])->assertStatus(401);
        $this->refreshWith($mine['cookie'])->assertOk();
        $this->refreshWith($stranger['cookie'])->assertOk();
    }

    public function test_closing_a_session_announces_the_revocation(): void
    {
        $user = $this->createUser();
        $mine = $this->loginWithCookie($user);
        $other = $this->loginWithCookie($user);
        Event::fake([SessionRevoked::class]);

        $this->deleteJson('/api/me/sessions/'.$this->sessionIdOf($other['cookie']), [], $this->bearer($mine['token']))->assertOk();

        Event::assertDispatched(SessionRevoked::class, fn (SessionRevoked $event) => $event->sessionId === $this->sessionIdOf($other['cookie']) && $event->reason === SessionRevoked::REASON_USER);
    }

    public function test_the_session_routes_require_authentication(): void
    {
        $this->getJson('/api/me/sessions')->assertUnauthorized();
        $this->deleteJson('/api/me/sessions')->assertUnauthorized();
        $this->deleteJson('/api/me/sessions/1')->assertUnauthorized();
    }

    public function test_changing_the_password_closes_every_session_and_opens_a_new_one_here(): void
    {
        $user = $this->createUser();
        $mine = $this->loginWithCookie($user);
        $other = $this->loginWithCookie($user);

        $response = $this->putJson('/api/me/password', ['current_password' => self::PASSWORD, 'password' => 'brand-new-pass-1', 'password_confirmation' => 'brand-new-pass-1'], $this->bearer($mine['token']));

        $response->assertOk()->assertJsonStructure(['authorization' => ['token']]);
        $this->assertTrue(Hash::check('brand-new-pass-1', $user->fresh()->password));
        $this->getJson('/api/me', $this->bearer($mine['token']))->assertUnauthorized();
        $this->getJson('/api/me', $this->bearer($other['token']))->assertUnauthorized();
        $this->refreshWith($other['cookie'])->assertStatus(401);
        $this->refreshWith($mine['cookie'])->assertStatus(401);
        $this->getJson('/api/me', $this->bearer($response->json('authorization.token')))->assertOk();
        $this->refreshWith($this->cookieValue($response))->assertOk();
    }

    public function test_changing_the_password_needs_the_current_one(): void
    {
        $user = $this->createUser();
        $mine = $this->loginWithCookie($user);

        $this->putJson('/api/me/password', ['current_password' => 'wrong', 'password' => 'brand-new-pass-1', 'password_confirmation' => 'brand-new-pass-1'], $this->bearer($mine['token']))
            ->assertStatus(422)->assertJsonValidationErrors(['current_password']);

        $this->getJson('/api/me', $this->bearer($mine['token']))->assertOk();
    }

    public function test_changing_the_password_needs_a_recent_authentication(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $this->travel(11)->minutes();
        $token = $this->refreshWith($session['cookie'])->json('authorization.token');

        $this->putJson('/api/me/password', ['current_password' => self::PASSWORD, 'password' => 'brand-new-pass-1', 'password_confirmation' => 'brand-new-pass-1'], $this->bearer($token))
            ->assertForbidden()->assertJsonPath('reason', 'mfa_required');
    }

    public function test_a_password_reset_by_the_host_closes_every_session(): void
    {
        $user = $this->createUser();
        $session = $this->loginWithCookie($user);

        event(new PasswordReset($user));

        $this->getJson('/api/me', $this->bearer($session['token']))->assertUnauthorized();
        $this->refreshWith($session['cookie'])->assertStatus(401);
    }

    public function test_the_password_route_is_registered_by_default(): void
    {
        $this->assertTrue($this->app['router']->has('secure-auth.password'));
    }
}
