<?php

namespace SecureAuth\Guard;

use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use SecureAuth\Models\AuthSession;
use SecureAuth\Permissions\Permissions;
use SecureAuth\Tokens\AccessTokenClaims;
use SecureAuth\Tokens\AccessTokens;

/**
 * Bearer guard for the package's access tokens. A token is accepted only while its refresh session (`sid`) is alive and its
 * permission version (`pv`) is current, so revoking a session or changing roles cuts its tokens at once.
 */
class TokenGuard implements Guard
{
    use GuardHelpers;

    public const TOKEN_MISSING = 'token_missing';

    public const TOKEN_INVALID = 'token_invalid';

    public const SESSION_REVOKED = 'session_revoked';

    public const PERMISSIONS_STALE = 'permissions_stale';

    public const ACCOUNT_BLOCKED = 'account_blocked';

    private bool $resolved = false;

    private ?AuthSession $session = null;

    private ?AccessTokenClaims $claims = null;

    private ?string $failure = null;

    public function __construct(
        UserProvider $provider,
        private Request $request,
        private readonly AccessTokens $tokens,
        private readonly Permissions $permissions,
    ) {
        $this->provider = $provider;
    }

    public function user(): ?Authenticatable
    {
        if (! $this->resolved) {
            $this->resolved = true;
            $this->user = $this->resolve();
        }

        return $this->user;
    }

    /** @param  array<string, mixed>  $credentials */
    public function validate(array $credentials = []): bool
    {
        return false;
    }

    public function setUser(Authenticatable $user): static
    {
        $this->user = $user;
        $this->resolved = true;

        return $this;
    }

    public function forgetUser(): static
    {
        $this->user = null;
        $this->session = null;
        $this->claims = null;
        $this->failure = null;
        $this->resolved = false;

        return $this;
    }

    public function setRequest(Request $request): static
    {
        $this->request = $request;

        return $this->forgetUser();
    }

    /** The refresh session the access token belongs to. */
    public function session(): ?AuthSession
    {
        $this->user();

        return $this->session;
    }

    public function claims(): ?AccessTokenClaims
    {
        $this->user();

        return $this->claims;
    }

    /** Why the request is not authenticated (`token_missing`, `token_invalid`, `session_revoked`, ...). */
    public function failureReason(): ?string
    {
        $this->user();

        return $this->failure;
    }

    private function resolve(): ?Authenticatable
    {
        $jwt = $this->request->bearerToken();

        if ($jwt === null || $jwt === '') {
            return $this->fail(self::TOKEN_MISSING);
        }

        $claims = $this->tokens->parse($jwt);

        if ($claims === null) {
            return $this->fail(self::TOKEN_INVALID);
        }

        $session = AuthSession::find($claims->sessionId);

        if (! $session || (string) $session->user_id !== $claims->subject || ! $session->isActive()) {
            return $this->fail(self::SESSION_REVOKED);
        }

        $user = $this->provider->retrieveById($claims->subject);

        if (! $user) {
            return $this->fail(self::TOKEN_INVALID);
        }

        if (method_exists($user, 'secureAuthIsBlocked') && $user->secureAuthIsBlocked()) {
            return $this->fail(self::ACCOUNT_BLOCKED);
        }

        if (! hash_equals($this->permissions->version($user), $claims->permissionVersion)) {
            return $this->fail(self::PERMISSIONS_STALE);
        }

        $this->session = $session;
        $this->claims = $claims;

        return $user;
    }

    private function fail(string $reason): null
    {
        $this->failure = $reason;

        return null;
    }
}
