<?php

namespace SecureAuth\Permissions;

use Illuminate\Contracts\Auth\Authenticatable;
use SecureAuth\Contracts\PermissionResolver;

/** Cached permission checks and the CASL rules (`can` / `cannot`) served by `GET /me`. */
class Permissions
{
    public function __construct(
        private readonly PermissionResolver $resolver,
        private readonly PermissionCache $cache,
    ) {}

    /** @return list<string> */
    public function names(Authenticatable $user): array
    {
        return $this->cache->remember($user->getAuthIdentifier(), fn () => array_values(array_unique($this->resolver->permissionsOf($user))));
    }

    public function has(Authenticatable $user, string $permission): bool
    {
        return in_array($permission, $this->names($user), true);
    }

    public function version(Authenticatable $user): string
    {
        return $this->cache->version($user->getAuthIdentifier());
    }

    /**
     * @return array{can: list<array{type: string, entity: string}>, cannot: list<array{type: string, entity: string}>}
     */
    public function rules(Authenticatable $user): array
    {
        $granted = $this->names($user);
        $catalog = $this->cache->rememberCatalog(fn () => array_values($this->resolver->catalog()));

        return [
            'can' => $this->toRules($granted),
            'cannot' => $this->toRules(array_values(array_diff($catalog, $granted))),
        ];
    }

    /**
     * @param  list<string>  $names
     * @return list<array{type: string, entity: string}>
     */
    private function toRules(array $names): array
    {
        $rules = [];

        foreach ($names as $name) {
            $parts = explode('_', $name, 2);

            if (count($parts) === 2) {
                $rules[] = ['type' => $parts[0], 'entity' => $parts[1]];
            }
        }

        return $rules;
    }
}
