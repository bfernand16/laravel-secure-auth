<?php

namespace SecureAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use SecureAuth\Http\Responses;
use SecureAuth\Permissions\Permissions;
use Symfony\Component\HttpFoundation\Response;

/**
 * `permission:<name>` (alias `secure-auth.permission`): the user needs the permission. `a|b` accepts any of them.
 * Goes after `secure-auth`.
 */
class RequirePermission
{
    public function __construct(private readonly Permissions $permissions) {}

    public function handle(Request $request, Closure $next, string $permission): Response
    {
        $user = $request->user();

        if ($user === null) {
            return Responses::error('token_missing', 401);
        }

        foreach (explode('|', $permission) as $candidate) {
            if ($this->permissions->has($user, $candidate)) {
                return $next($request);
            }
        }

        return Responses::error('forbidden', 403);
    }
}
