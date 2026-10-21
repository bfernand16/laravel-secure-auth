<?php

namespace SecureAuth\Tests\Feature;

use Illuminate\Http\Request;
use SecureAuth\Audit\SecurityEvents;
use SecureAuth\Audit\SecurityEventType;
use SecureAuth\Models\AuthSession;
use SecureAuth\Models\LoginChallenge;
use SecureAuth\Models\SecurityEvent;
use SecureAuth\Models\TwoFactorMethod;
use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\TestCase;

class SecurityEventsTest extends TestCase
{
    use UsesAuthSessions;

    private function request(): Request
    {
        return Request::create('/x', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7', 'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0']);
    }

    public function test_only_whitelisted_meta_keys_are_stored(): void
    {
        $user = $this->createUser();

        $event = app(SecurityEvents::class)->record($user, SecurityEventType::LOGIN, $this->request(), [
            'method' => 'pwd', 'password' => 'hunter2', 'code' => '123456', 'token' => 'abc', 'email' => 'x@example.test',
        ]);

        $this->assertSame(['method' => 'pwd'], $event->fresh()->meta);
    }

    public function test_the_host_can_whitelist_more_meta_keys(): void
    {
        config(['secure-auth.security_events.meta_keys' => ['ticket']]);

        $event = app(SecurityEvents::class)->record($this->createUser(), 'support_unlock', null, ['ticket' => 'T-1']);

        $this->assertSame(['ticket' => 'T-1'], $event->fresh()->meta);
    }

    public function test_the_holder_acting_on_their_account_gets_ip_and_readable_device(): void
    {
        $event = app(SecurityEvents::class)->record($this->createUser(), SecurityEventType::LOGIN, $this->request());

        $this->assertSame('203.0.113.7', $event->ip);
        $this->assertSame('Firefox · Linux', $event->device);
    }

    public function test_an_admin_acting_on_someone_else_does_not_leave_their_ip_there(): void
    {
        $admin = $this->createUser();

        $event = app(SecurityEvents::class)->record($this->createUser(), SecurityEventType::SESSIONS_REVOKED_ALL, $this->request(), [], $admin);

        $this->assertNull($event->ip);
        $this->assertNull($event->device);
        $this->assertSame($admin->id, $event->actor_id);
    }

    public function test_the_account_lists_its_own_history_newest_first(): void
    {
        $user = $this->createUser();
        $session = $this->loginWithCookie($user);
        app(SecurityEvents::class)->record($this->createUser(), SecurityEventType::LOGIN);
        $this->travel(1)->minutes();
        $this->deleteJson('/api/me/sessions', [], $this->bearer($session['token']));
        $this->loginWithCookie($user);

        $response = $this->getJson('/api/me/security-events', $this->bearer($session['token']))->assertOk();

        $this->assertSame([SecurityEventType::LOGIN, SecurityEventType::LOGIN], collect($response->json('data'))->pluck('type')->all());
        $response->assertJsonPath('meta.total', 2);
    }

    public function test_prune_deletes_old_data_and_keeps_the_recent(): void
    {
        $user = $this->createUser();
        $live = $this->loginWithCookie($user);
        $this->loginWithCookie($user);
        AuthSession::whereKeyNot($this->sessionIdOf($live['cookie']))->update(['expires_at' => now()->subMinute()]);
        LoginChallenge::create(['user_id' => $user->id, 'token_hash' => str_repeat('a', 64), 'expires_at' => now()->subMinute()]);
        $pending = TwoFactorMethod::create(['user_id' => $user->id, 'type' => 'totp', 'secret' => 'X']);
        $pending->forceFill(['created_at' => now()->subDays(2), 'updated_at' => now()->subDays(2)])->save();
        SecurityEvent::create(['user_id' => $user->id, 'type' => 'login', 'created_at' => now()->subDays(181)]);

        $this->artisan('secure-auth:prune')->assertSuccessful();

        $this->assertSame([$this->sessionIdOf($live['cookie'])], AuthSession::pluck('id')->all());
        $this->assertSame(0, LoginChallenge::count());
        $this->assertSame(0, TwoFactorMethod::count());
        $this->assertSame(2, SecurityEvent::count());
    }

    public function test_prune_keeps_recently_revoked_sessions_for_the_history(): void
    {
        $user = $this->createUser();
        $this->loginWithCookie($user);
        AuthSession::query()->update(['revoked_at' => now()->subDays(5)]);

        $this->artisan('secure-auth:prune')->assertSuccessful();
        $this->assertSame(1, AuthSession::count());

        AuthSession::query()->update(['revoked_at' => now()->subDays(31)]);
        $this->artisan('secure-auth:prune')->assertSuccessful();
        $this->assertSame(0, AuthSession::count());
    }
}
