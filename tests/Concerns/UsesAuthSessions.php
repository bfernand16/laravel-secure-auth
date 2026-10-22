<?php

namespace SecureAuth\Tests\Concerns;

use Illuminate\Testing\TestResponse;
use SecureAuth\Models\AuthSession;
use SecureAuth\Sessions\SessionCookie;
use SecureAuth\Tests\Fixtures\User;

/** Logging in and refreshing the way the browser does: the access token in the body, the refresh cookie apart. */
trait UsesAuthSessions
{
    /** @return array<string, string> */
    protected function xhrHeaders(?string $origin = null): array
    {
        return ['X-Requested-With' => 'XMLHttpRequest', 'Origin' => $origin ?? 'http://localhost'];
    }

    /** @param  array<string, mixed>  $payload */
    protected function postLogin(array $payload, ?array $headers = null): TestResponse
    {
        $this->forgetAuthentication();

        return $this->postJson('/api/auth/login', $payload, $headers ?? $this->xhrHeaders());
    }

    /** @return array{token: string, cookie: string} */
    protected function loginWithCookie(User $user, bool $remember = false): array
    {
        $response = $this->postLogin(['email' => $user->email, 'password' => self::PASSWORD, 'remember' => $remember])->assertOk();

        return ['token' => $response->json('authorization.token'), 'cookie' => $this->cookieValue($response)];
    }

    protected function cookieValue(TestResponse $response): string
    {
        $cookie = $response->getCookie(SessionCookie::name(), false);
        $this->assertNotNull($cookie, 'the response sets the session cookie');

        return $cookie->getValue();
    }

    protected function withSessionCookie(string $cookie): static
    {
        return $this->withCredentials()->withUnencryptedCookie(SessionCookie::name(), $cookie);
    }

    /** @param  array<string, string>|null  $headers */
    protected function refreshWith(string $cookie, ?array $headers = null): TestResponse
    {
        $this->forgetAuthentication();

        return $this->withSessionCookie($cookie)->postJson('/api/auth/refresh', [], $headers ?? $this->xhrHeaders());
    }

    /** @return array<string, string> */
    protected function bearer(string $token): array
    {
        $this->forgetAuthentication();

        return ['Authorization' => 'Bearer '.$token];
    }

    protected function sessionIdOf(string $cookie): int
    {
        return (int) AuthSession::where('selector', explode('.', $cookie)[0])->value('id');
    }

    /** Clears the cookies, the resolved guard user and the default headers between simulated requests. */
    protected function forgetAuthentication(): void
    {
        $this->defaultCookies = [];
        $this->unencryptedCookies = [];
        $this->defaultHeaders = [];
        $this->app['auth']->forgetGuards();
    }
}
