<?php

namespace SecureAuth\Events;

use Illuminate\Foundation\Events\Dispatchable;

/** A refresh session was closed. Hosts can listen to it (for example to push a realtime "you were logged out"). */
class SessionRevoked
{
    use Dispatchable;

    public const REASON_LOGOUT = 'logout';

    public const REASON_USER = 'user';

    public const REASON_REUSE = 'reuse';

    public const REASON_ACCOUNT = 'account';

    public const REASON_PASSWORD = 'password';

    public function __construct(
        public readonly int $sessionId,
        public readonly int|string $userId,
        public readonly string $reason,
    ) {}
}
