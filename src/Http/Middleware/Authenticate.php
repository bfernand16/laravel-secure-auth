<?php

namespace SecureAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use SecureAuth\Guard\TokenGuard;
use SecureAuth\Http\Responses;
use SecureAuth\TwoFactor\TwoFactorManager;
use Symfony\Component\HttpFoundation\Response;

/**
 * `secure-auth`: requires a valid access token and makes the package guard the default for the request. Once
 * `two_factor_required_at` has passed without TOTP, only the 2FA setup routes are reachable (403 `two_factor_required`).
 */
class Authenticate
{
    public function __construct(private readonly TwoFactorManager $twoFactor) {}

    public function handle(Request $request, Closure $next): Response
    {
        $name = (string) config('secure-auth.guard', 'secure-auth');
        Auth::shouldUse($name);

        /** @var TokenGuard $guard */
        $guard = Auth::guard($name);
        $user = $guard->user();

        if ($user === null) {
            $reason = $guard->failureReason() ?? TokenGuard::TOKEN_MISSING;

            return Responses::error($reason, $reason === TokenGuard::ACCOUNT_BLOCKED ? 403 : 401);
        }

        if ($this->twoFactor->setupRequired($user) && ! $this->isSetupRoute($request)) {
            return Responses::error('two_factor_required', 403);
        }

        return $next($request);
    }

    private function isSetupRoute(Request $request): bool
    {
        return $request->routeIs(...(array) config('secure-auth.two_factor.setup_routes', []));
    }
}
