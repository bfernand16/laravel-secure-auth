<?php

namespace SecureAuth;

use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use SecureAuth\Audit\SecurityEvents;
use SecureAuth\Audit\SecurityEventType;
use SecureAuth\Console\PruneCommand;
use SecureAuth\Console\SyncPermissionsCommand;
use SecureAuth\Contracts\PermissionResolver;
use SecureAuth\Events\SessionRevoked;
use SecureAuth\Guard\TokenGuard;
use SecureAuth\Http\Middleware\Authenticate;
use SecureAuth\Http\Middleware\EnsureSameOrigin;
use SecureAuth\Http\Middleware\RequirePermission;
use SecureAuth\Http\Middleware\RequireRecentMfa;
use SecureAuth\Permissions\PermissionCache;
use SecureAuth\Permissions\Permissions;
use SecureAuth\Permissions\RolePermissionResolver;
use SecureAuth\Sessions\SessionCookie;
use SecureAuth\Sessions\SessionTokens;
use SecureAuth\Tokens\AccessTokens;

class SecureAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/secure-auth.php', 'secure-auth');
        $this->mergeConfigFrom(__DIR__.'/../config/secure-auth-permissions.php', 'secure-auth-permissions');

        $this->app->bindIf(PermissionResolver::class, RolePermissionResolver::class, true);
        $this->app->singleton(PermissionCache::class);
        $this->app->singleton(Permissions::class);
        $this->app->singleton(AccessTokens::class);

        $guard = (string) config('secure-auth.guard', 'secure-auth');

        if (config('auth.guards.'.$guard) === null) {
            config(['auth.guards.'.$guard => ['driver' => 'secure-auth', 'provider' => config('secure-auth.user_provider', 'users')]]);
        }
    }

    public function boot(Router $router): void
    {
        $this->loadTranslationsFrom(__DIR__.'/../lang', 'secure-auth');
        $this->registerGuard();
        $this->registerMiddleware($router);
        $this->registerRateLimiters();
        $this->registerListeners();

        if (config('secure-auth.routes.enabled', true)) {
            $this->loadRoutesFrom(__DIR__.'/../routes/secure-auth.php');
        }

        if ($this->app->runningInConsole()) {
            $this->registerPublishing();
            $this->commands([SyncPermissionsCommand::class, PruneCommand::class]);
        }
    }

    private function registerGuard(): void
    {
        Auth::extend('secure-auth', function (Application $app, string $name, array $config) {
            $guard = new TokenGuard(
                Auth::createUserProvider($config['provider'] ?? null),
                $app['request'],
                $app->make(AccessTokens::class),
                $app->make(Permissions::class),
            );

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });
    }

    private function registerMiddleware(Router $router): void
    {
        $router->aliasMiddleware('secure-auth', Authenticate::class);
        $router->aliasMiddleware('secure-auth.recent-mfa', RequireRecentMfa::class);
        $router->aliasMiddleware('secure-auth.permission', RequirePermission::class);
        $router->aliasMiddleware('secure-auth.same-origin', EnsureSameOrigin::class);

        if (config('secure-auth.permissions.short_middleware_alias', true)) {
            $router->aliasMiddleware('permission', RequirePermission::class);
        }
    }

    private function registerRateLimiters(): void
    {
        RateLimiter::for('secure-auth.login', function (Request $request) {
            $login = mb_strtolower((string) $request->input((string) config('secure-auth.login_field', 'email')));

            return [
                Limit::perMinute((int) config('secure-auth.rate_limits.login_account', 10))->by('secure-auth:login-account|'.sha1($login).'|'.$request->ip()),
                Limit::perMinute((int) config('secure-auth.rate_limits.login_ip', 30))->by('secure-auth:login-ip|'.$request->ip()),
            ];
        });

        RateLimiter::for('secure-auth.two-factor', fn (Request $request) => [
            Limit::perMinute((int) config('secure-auth.rate_limits.two_factor_challenge', 10))->by('secure-auth:two-factor-challenge|'.sha1((string) $request->input('challenge')).'|'.$request->ip()),
            Limit::perMinute((int) config('secure-auth.rate_limits.two_factor_ip', 30))->by('secure-auth:two-factor-ip|'.$request->ip()),
        ]);

        RateLimiter::for('secure-auth.refresh', function (Request $request) {
            $parts = SessionCookie::parse($request);
            $sessionKey = $parts !== null ? sha1($parts[0]) : 'ip:'.$request->ip();

            return [
                Limit::perMinute((int) config('secure-auth.rate_limits.refresh_session', 30))->by('secure-auth:refresh-session|'.$sessionKey),
                Limit::perMinute((int) config('secure-auth.rate_limits.refresh_ip', 120))->by('secure-auth:refresh-ip|'.$request->ip()),
            ];
        });

        RateLimiter::for('secure-auth.step-up', fn (Request $request) => Limit::perMinute((int) config('secure-auth.rate_limits.step_up', 10))
            ->by('secure-auth:step-up|'.($request->user()?->getAuthIdentifier() ?? $request->ip())));

        RateLimiter::for('secure-auth.account', fn (Request $request) => Limit::perMinute(120)
            ->by('secure-auth:account|'.($request->user()?->getAuthIdentifier() ?? $request->ip())));
    }

    private function registerListeners(): void
    {
        Event::listen(PasswordReset::class, function (PasswordReset $event) {
            $this->app->make(SessionTokens::class)->revokeAll($event->user, SessionRevoked::REASON_PASSWORD);
        });

        Event::listen(SessionRevoked::class, function (SessionRevoked $event) {
            if ($event->reason !== SessionRevoked::REASON_REUSE) {
                return;
            }

            $model = (string) config('secure-auth.user_model');
            $user = $model::query()->find($event->userId);

            if ($user instanceof Authenticatable) {
                $this->app->make(SecurityEvents::class)->record($user, SecurityEventType::SESSION_REUSE_DETECTED, null, ['session_id' => $event->sessionId]);
            }
        });
    }

    private function registerPublishing(): void
    {
        $this->publishes([__DIR__.'/../config/secure-auth.php' => config_path('secure-auth.php')], 'secure-auth-config');
        $this->publishes([__DIR__.'/../config/secure-auth-permissions.php' => config_path('secure-auth-permissions.php')], 'secure-auth-permissions');
        $this->publishesMigrations([__DIR__.'/../database/migrations' => database_path('migrations')], 'secure-auth-migrations');
        $this->publishes([
            __DIR__.'/../database/stubs/add_secure_auth_columns_to_users_table.php.stub' => database_path('migrations/'.date('Y_m_d_His').'_add_secure_auth_columns_to_users_table.php'),
        ], 'secure-auth-users-migration');
        $this->publishes([__DIR__.'/../lang' => $this->app->langPath('vendor/secure-auth')], 'secure-auth-lang');
    }
}
