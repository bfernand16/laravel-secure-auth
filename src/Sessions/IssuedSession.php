<?php

namespace SecureAuth\Sessions;

use Illuminate\Http\JsonResponse;
use SecureAuth\Models\AuthSession;
use SecureAuth\Tokens\AccessTokens;
use Symfony\Component\HttpFoundation\Cookie;

/** Result of opening or refreshing a session: the access token for the body and the refresh cookie for the headers. */
final class IssuedSession
{
    public function __construct(
        public readonly AuthSession $session,
        public readonly string $accessToken,
        public readonly ?Cookie $cookie,
    ) {}

    /** @return array{token: string, type: string, expires_in: int} */
    public function authorization(): array
    {
        return ['token' => $this->accessToken, 'type' => 'bearer', 'expires_in' => AccessTokens::ttlSeconds()];
    }

    public function attachTo(JsonResponse $response): JsonResponse
    {
        if ($this->cookie !== null) {
            $response->headers->setCookie($this->cookie);
        }

        return $response->header('Cache-Control', 'no-store');
    }
}
