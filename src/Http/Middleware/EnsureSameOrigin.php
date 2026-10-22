<?php

namespace SecureAuth\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use SecureAuth\Http\Responses;
use Symfony\Component\HttpFoundation\Response;

/**
 * CSRF protection of the routes that use the refresh cookie (the rest use `Authorization: Bearer`): requires
 * `X-Requested-With: XMLHttpRequest` and an `Origin` (or `Referer`) among the allowed origins.
 */
class EnsureSameOrigin
{
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->header('X-Requested-With') !== 'XMLHttpRequest' || ! $this->originAllowed($request)) {
            return Responses::error('csrf_rejected', 403);
        }

        return $next($request);
    }

    private function originAllowed(Request $request): bool
    {
        $source = $request->headers->get('Origin') ?: $request->headers->get('Referer');
        $parts = $source ? parse_url($source) : false;

        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host'])) {
            return false;
        }

        $origin = strtolower($parts['scheme'].'://'.$parts['host'].(isset($parts['port']) ? ':'.$parts['port'] : ''));

        return in_array($origin, $this->allowedOrigins($request), true);
    }

    /** @return list<string> */
    private function allowedOrigins(Request $request): array
    {
        $configured = (array) config('secure-auth.allowed_origins', []);

        if ($configured === []) {
            $configured = (array) config('cors.allowed_origins', []);
        }

        $origins = array_merge([$request->getSchemeAndHttpHost()], $configured);

        return array_values(array_map(fn ($origin) => strtolower(rtrim((string) $origin, '/')), array_filter($origins, fn ($origin) => $origin !== '*')));
    }
}
