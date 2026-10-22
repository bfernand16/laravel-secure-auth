<?php

namespace SecureAuth\Permissions;

use Closure;
use Illuminate\Contracts\Cache\Factory;
use Illuminate\Contracts\Cache\Repository;

/**
 * Cache of each user's permissions, versioned. `flush()` bumps the global version (a role or the catalog changed) and
 * `forgetUser()` bumps one user's version (their roles changed). Access tokens carry the combined version as `pv`, so a
 * token issued before the change is rejected and the client refreshes it.
 */
class PermissionCache
{
    private const VERSION_KEY = 'secure-auth:permissions:version';

    private const USER_VERSION_KEY = 'secure-auth:permissions:user-version:';

    public function __construct(private readonly Factory $cache) {}

    public function version(int|string $userId): string
    {
        return $this->globalVersion().'.'.(int) $this->store()->get(self::USER_VERSION_KEY.$userId, 0);
    }

    /**
     * @param  Closure(): list<string>  $resolve
     * @return list<string>
     */
    public function remember(int|string $userId, Closure $resolve): array
    {
        return $this->store()->remember('secure-auth:permissions:v'.$this->version($userId).':'.$userId, $this->ttl(), $resolve);
    }

    /**
     * @param  Closure(): list<string>  $resolve
     * @return list<string>
     */
    public function rememberCatalog(Closure $resolve): array
    {
        return $this->store()->remember('secure-auth:permissions:catalog:v'.$this->globalVersion(), $this->ttl(), $resolve);
    }

    public function forgetUser(int|string $userId): void
    {
        $this->store()->forever(self::USER_VERSION_KEY.$userId, (int) $this->store()->get(self::USER_VERSION_KEY.$userId, 0) + 1);
    }

    public function flush(): void
    {
        $this->store()->forever(self::VERSION_KEY, $this->globalVersion() + 1);
    }

    private function globalVersion(): int
    {
        return (int) $this->store()->get(self::VERSION_KEY, 1);
    }

    private function ttl(): int
    {
        return (int) config('secure-auth.permissions.cache_ttl_seconds', 600);
    }

    private function store(): Repository
    {
        return $this->cache->store(config('secure-auth.permissions.cache_store'));
    }
}
