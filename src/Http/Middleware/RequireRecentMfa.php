<?php

namespace SecureAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use SecureAuth\Guard\TokenGuard;
use SecureAuth\Http\Responses;
use Symfony\Component\HttpFoundation\Response;

/**
 * `secure-auth.recent-mfa:<minutes>`: the session must have re-authenticated (login or `POST /me/step-up`) within the last
 * minutes. Otherwise 403 `mfa_required`, and the client asks for the password (and TOTP code) and retries.
 */
class RequireRecentMfa
{
    public function handle(Request $request, Closure $next, ?string $minutes = null): Response
    {
        $guard = Auth::guard((string) config('secure-auth.guard', 'secure-auth'));
        $session = $guard instanceof TokenGuard ? $guard->session() : null;

        if ($session === null) {
            return Responses::error(TokenGuard::TOKEN_MISSING, 401);
        }

        $window = (int) ($minutes ?? config('secure-auth.recent_mfa_minutes', 10));

        if ($session->last_mfa_at === null || $session->last_mfa_at->lessThan(now()->subMinutes($window))) {
            return Responses::error('mfa_required', 403, ['max_age' => $window * 60]);
        }

        return $next($request);
    }
}
