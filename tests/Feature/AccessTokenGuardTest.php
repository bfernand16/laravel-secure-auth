<?php

namespace SecureAuth\Tests\Feature;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use SecureAuth\Models\AuthSession;
use SecureAuth\Models\Role;
use SecureAuth\Permissions\PermissionCache;
use SecureAuth\Tests\Concerns\UsesAuthSessions;
use SecureAuth\Tests\TestCase;
use SecureAuth\Tokens\AccessTokens;

class AccessTokenGuardTest extends TestCase
{
    use UsesAuthSessions;

    public function test_a_request_without_token_is_unauthenticated(): void
    {
        $this->getJson('/api/me')->assertUnauthorized()->assertJsonPath('reason', 'token_missing');
    }

    public function test_a_garbage_token_is_rejected(): void
    {
        $this->getJson('/api/me', $this->bearer('not.a.jwt'))->assertUnauthorized()->assertJsonPath('reason', 'token_invalid');
    }

    public function test_a_token_signed_with_another_key_is_rejected(): void
    {
        $user = $this->createUser();
        $this->loginWithCookie($user);
        $forged = $this->forge(str_repeat('x', 32), ['sub' => (string) $user->id, 'sid' => AuthSession::firstOrFail()->id]);

        $this->getJson('/api/me', $this->bearer($forged))->assertUnauthorized()->assertJsonPath('reason', 'token_invalid');
    }

    public function test_a_token_from_another_issuer_is_rejected(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        config(['secure-auth.access_token.issuer' => 'https://other.example']);
        $this->app->forgetInstance(AccessTokens::class);

        $this->getJson('/api/me', $this->bearer($session['token']))->assertUnauthorized()->assertJsonPath('reason', 'token_invalid');
    }

    public function test_an_expired_token_is_rejected(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $this->travel(11)->minutes();

        $this->getJson('/api/me', $this->bearer($session['token']))->assertUnauthorized()->assertJsonPath('reason', 'token_invalid');
    }

    public function test_a_token_is_accepted_until_it_expires(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        $this->travel(9)->minutes();

        $this->getJson('/api/me', $this->bearer($session['token']))->assertOk();
    }

    public function test_a_token_of_a_revoked_session_is_rejected_at_once(): void
    {
        $session = $this->loginWithCookie($this->createUser());
        AuthSession::firstOrFail()->forceFill(['revoked_at' => now()])->save();

        $this->getJson('/api/me', $this->bearer($session['token']))->assertUnauthorized()->assertJsonPath('reason', 'session_revoked');
    }

    public function test_a_token_whose_session_belongs_to_someone_else_is_rejected(): void
    {
        $victim = $this->createUser();
        $this->loginWithCookie($victim);
        $attacker = $this->createUser();
        $this->loginWithCookie($attacker);
        $victimSession = AuthSession::where('user_id', $victim->id)->firstOrFail();
        $secret = hash_hmac('sha256', 'secure-auth:access-token', (string) config('app.key'), true);
        $token = $this->forge($secret, ['sub' => (string) $attacker->id, 'sid' => $victimSession->id]);

        $this->getJson('/api/me', $this->bearer($token))->assertUnauthorized()->assertJsonPath('reason', 'session_revoked');
    }

    public function test_changing_the_roles_of_the_user_makes_live_tokens_stale(): void
    {
        $user = $this->createUser();
        Role::create(['name' => 'editor']);
        $session = $this->loginWithCookie($user);

        $user->assignRole('editor');

        $this->getJson('/api/me', $this->bearer($session['token']))->assertUnauthorized()->assertJsonPath('reason', 'permissions_stale');
        $fresh = $this->refreshWith($session['cookie'])->json('authorization.token');
        $this->getJson('/api/me', $this->bearer($fresh))->assertOk();
    }

    public function test_changing_a_role_makes_every_live_token_stale(): void
    {
        $session = $this->loginWithCookie($this->createUser());

        app(PermissionCache::class)->flush();

        $this->getJson('/api/me', $this->bearer($session['token']))->assertUnauthorized()->assertJsonPath('reason', 'permissions_stale');
    }

    public function test_a_blocked_account_loses_access_with_a_live_token(): void
    {
        $user = $this->createUser();
        $session = $this->loginWithCookie($user);
        $user->forceFill(['blocked_at' => now()])->save();

        $this->getJson('/api/me', $this->bearer($session['token']))->assertForbidden()->assertJsonPath('reason', 'account_blocked');
    }

    public function test_a_configured_secret_signs_the_tokens(): void
    {
        config(['secure-auth.access_token.secret' => str_repeat('k', 40)]);
        $this->app->forgetInstance(AccessTokens::class);
        $user = $this->createUser();
        $session = $this->loginWithCookie($user);

        $config = Configuration::forSymmetricSigner(new Sha256, InMemory::plainText(str_repeat('k', 40)));
        $token = $config->parser()->parse($session['token']);

        $this->assertTrue($config->validator()->validate($token, new SignedWith($config->signer(), $config->verificationKey())));
    }

    public function test_the_package_guard_is_registered_in_the_auth_config(): void
    {
        $this->assertSame('secure-auth', config('auth.guards.secure-auth.driver'));
    }

    /** @param  array{sub: string, sid: int}  $claims */
    private function forge(string $key, array $claims): string
    {
        $config = Configuration::forSymmetricSigner(new Sha256, InMemory::plainText($key));
        $now = new \DateTimeImmutable('@'.now()->getTimestamp());

        return $config->builder()
            ->issuedBy((string) config('secure-auth.access_token.issuer'))
            ->relatedTo($claims['sub'])
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->modify('+5 minutes'))
            ->withClaim('sid', $claims['sid'])
            ->withClaim('pv', app(PermissionCache::class)->version($claims['sub']))
            ->withClaim('amr', ['pwd'])
            ->withClaim('auth_time', $now->getTimestamp())
            ->getToken($config->signer(), $config->signingKey())
            ->toString();
    }
}
