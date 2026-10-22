<?php

return [

    /*
    | The host application's user model. It must use the `SecureAuth\Concerns\HasSecureAuth` trait.
    */
    'user_model' => env('SECURE_AUTH_USER_MODEL', 'App\\Models\\User'),

    /*
    | Type of the users primary key, used by the migrations' foreign keys: `int`, `uuid` or `ulid`.
    */
    'user_key_type' => 'int',

    /*
    | Name of the auth guard the package registers (driver `secure-auth`) and the user provider it reads from.
    */
    'guard' => 'secure-auth',

    'user_provider' => 'users',

    /*
    | Column used as the login identifier.
    */
    'login_field' => 'email',

    /*
    | When the user model implements MustVerifyEmail, unverified accounts cannot log in.
    */
    'require_verified_email' => true,

    'routes' => [
        'enabled' => (bool) env('SECURE_AUTH_ROUTES', true),
        'prefix' => env('SECURE_AUTH_ROUTE_PREFIX', 'api'),
        'middleware' => ['api'],
        'password_change' => true,
    ],

    'access_token' => [
        'ttl_minutes' => (int) env('SECURE_AUTH_ACCESS_TTL', 10),
        // HMAC-SHA256 key (at least 32 bytes). When empty, a key is derived from APP_KEY.
        'secret' => env('SECURE_AUTH_JWT_SECRET'),
        'issuer' => env('SECURE_AUTH_JWT_ISSUER', env('APP_URL', 'http://localhost')),
        'leeway_seconds' => (int) env('SECURE_AUTH_JWT_LEEWAY', 0),
    ],

    'session' => [
        'cookie' => env('SECURE_AUTH_COOKIE', 'secure_auth_session'),
        // Only disable for plain-HTTP local development.
        'cookie_secure' => (bool) env('SECURE_AUTH_COOKIE_SECURE', true),
        'cookie_domain' => env('SECURE_AUTH_COOKIE_DOMAIN'),
        'absolute_days' => ['remember' => 30, 'default' => 7],
        'sliding_hours' => ['remember' => 168, 'default' => 24],
        'reuse_grace_seconds' => (int) env('SECURE_AUTH_REUSE_GRACE', 10),
        'revoked_retention_days' => 30,
    ],

    /*
    | Origins allowed to call the cookie routes (login, refresh, logout, 2FA verify). The request's own scheme and host is
    | always allowed. When empty, `cors.allowed_origins` is used as well.
    */
    'allowed_origins' => array_values(array_filter(explode(',', (string) env('SECURE_AUTH_ALLOWED_ORIGINS', '')))),

    /*
    | Requests per minute (per account and IP, and per IP) of the public auth routes.
    */
    'rate_limits' => [
        'login_account' => (int) env('SECURE_AUTH_LOGIN_ACCOUNT_LIMIT', 10),
        'login_ip' => (int) env('SECURE_AUTH_LOGIN_IP_LIMIT', 30),
        'two_factor_challenge' => (int) env('SECURE_AUTH_TWO_FACTOR_CHALLENGE_LIMIT', 10),
        'two_factor_ip' => (int) env('SECURE_AUTH_TWO_FACTOR_IP_LIMIT', 30),
        // Wrong codes per account in 15 minutes, across challenges and step-up attempts.
        'two_factor_failures' => (int) env('SECURE_AUTH_TWO_FACTOR_FAILURES_LIMIT', 15),
        'refresh_session' => (int) env('SECURE_AUTH_REFRESH_SESSION_LIMIT', 30),
        'refresh_ip' => (int) env('SECURE_AUTH_REFRESH_IP_LIMIT', 120),
        'step_up' => (int) env('SECURE_AUTH_STEP_UP_LIMIT', 10),
    ],

    'two_factor' => [
        // Issuer shown in the authenticator app.
        'issuer' => env('SECURE_AUTH_TOTP_ISSUER', env('APP_NAME', 'Laravel')),
        'challenge_ttl_minutes' => 5,
        'challenge_max_attempts' => 5,
        'recovery_codes' => 10,
        'qr_size' => 200,
        // Only honoured in the `local` and `testing` environments (E2E suites log in many times with one account).
        'allow_code_reuse' => (bool) env('SECURE_AUTH_TOTP_ALLOW_REUSE', false),
        // Route names a user may still reach once `two_factor_required_at` has passed without TOTP.
        'setup_routes' => [
            'secure-auth.me',
            'secure-auth.step-up',
            'secure-auth.two-factor.*',
        ],
    ],

    /*
    | Default window of `secure-auth.recent-mfa` when no minutes are given.
    */
    'recent_mfa_minutes' => 10,

    'security_events' => [
        'retention_days' => (int) env('SECURE_AUTH_SECURITY_EVENTS_RETENTION_DAYS', 180),
        // Extra `meta` keys the host may record, on top of the built-in whitelist. Never secrets.
        'meta_keys' => [],
    ],

    'permissions' => [
        'cache_ttl_seconds' => 600,
        'cache_store' => env('SECURE_AUTH_PERMISSION_CACHE_STORE'),
        // Also register the short `permission:<name>` middleware alias (`secure-auth.permission` always exists).
        'short_middleware_alias' => true,
    ],

    'tables' => [
        'roles' => 'roles',
        'permissions' => 'permissions',
        'role_permission' => 'role_permission',
        'user_role' => 'user_role',
        'auth_sessions' => 'auth_sessions',
        'login_challenges' => 'login_challenges',
        'two_factor_methods' => 'two_factor_methods',
        'recovery_codes' => 'recovery_codes',
        'security_events' => 'security_events',
    ],

];
