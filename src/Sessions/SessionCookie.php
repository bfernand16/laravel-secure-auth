<?php

namespace SecureAuth\Sessions;

use Illuminate\Http\Request;
use SecureAuth\Models\AuthSession;
use Symfony\Component\HttpFoundation\Cookie;

/**
 * The refresh cookie: `selector.secret`, HttpOnly, Secure (configurable for local HTTP), SameSite=Strict and scoped to
 * `/<prefix>/auth`. Without "remember me" it is a browser-session cookie.
 */
final class SessionCookie
{
    public static function name(): string
    {
        return (string) config('secure-auth.session.cookie', 'secure_auth_session');
    }

    public static function path(): string
    {
        $prefix = trim((string) config('secure-auth.routes.prefix', 'api'), '/');

        return '/'.($prefix === '' ? '' : $prefix.'/').'auth';
    }

    public static function make(AuthSession $session, string $secret): Cookie
    {
        return self::build($session->selector.'.'.$secret, $session->remember ? $session->absolute_expires_at : 0);
    }

    public static function forget(): Cookie
    {
        return self::build('', 1);
    }

    /** @return array{0: string, 1: string}|null selector and secret, or null when missing or malformed */
    public static function parse(Request $request): ?array
    {
        $value = $request->cookies->get(self::name());

        if (! is_string($value) || preg_match('/^([A-Za-z0-9]{16,32})\.([A-Za-z0-9]{32,128})$/', $value, $parts) !== 1) {
            return null;
        }

        return [$parts[1], $parts[2]];
    }

    public static function present(Request $request): bool
    {
        return $request->cookies->has(self::name());
    }

    private static function build(string $value, mixed $expires): Cookie
    {
        return new Cookie(
            self::name(),
            $value,
            $expires,
            self::path(),
            config('secure-auth.session.cookie_domain'),
            (bool) config('secure-auth.session.cookie_secure', true),
            true,
            false,
            Cookie::SAMESITE_STRICT,
        );
    }
}
