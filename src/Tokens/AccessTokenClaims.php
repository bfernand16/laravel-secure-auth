<?php

namespace SecureAuth\Tokens;

/** The verified claims of an access token. Identity is minimal on purpose: no email, no name. */
final class AccessTokenClaims
{
    /** @param  list<string>  $amr */
    public function __construct(
        public readonly string $subject,
        public readonly int $sessionId,
        public readonly string $permissionVersion,
        public readonly array $amr,
        public readonly int $authTime,
        public readonly int $issuedAt,
        public readonly int $expiresAt,
        public readonly string $id,
    ) {}
}
