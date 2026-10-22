<?php

namespace SecureAuth\Audit;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use SecureAuth\Models\SecurityEvent;
use SecureAuth\Sessions\DeviceLabel;

/**
 * Single write point of the security history. IP and readable device are stored only when the account holder acts on
 * their own account (an admin's data is not copied to someone else's history), and only whitelisted `meta` keys are kept:
 * never passwords, codes, tokens or emails.
 */
class SecurityEvents
{
    public const META_KEYS = ['session_id', 'device', 'method', 'reason', 'closed', 'step'];

    /** @param  array<string, mixed>  $meta */
    public function record(Authenticatable $user, string $type, ?Request $request = null, array $meta = [], ?Authenticatable $actor = null): SecurityEvent
    {
        $ownRequest = $request !== null && $actor === null;
        $meta = array_intersect_key($meta, array_flip($this->metaKeys()));

        return SecurityEvent::create([
            'user_id' => $user->getAuthIdentifier(),
            'type' => $type,
            'actor_id' => $actor?->getAuthIdentifier(),
            'ip' => $ownRequest ? $request->ip() : null,
            'device' => $ownRequest ? DeviceLabel::fromUserAgent($request->header('User-Agent')) : null,
            'meta' => $meta === [] ? null : $meta,
        ]);
    }

    public function prune(): int
    {
        return SecurityEvent::where('created_at', '<', now()->subDays((int) config('secure-auth.security_events.retention_days', 180)))->delete();
    }

    /** @return list<string> */
    private function metaKeys(): array
    {
        return array_values(array_unique(array_merge(self::META_KEYS, (array) config('secure-auth.security_events.meta_keys', []))));
    }
}
