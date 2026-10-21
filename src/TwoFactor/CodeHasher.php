<?php

namespace SecureAuth\TwoFactor;

/** Keyed hash of short codes (recovery codes): the database alone is not enough to brute-force them back. */
final class CodeHasher
{
    public static function hash(string $code): string
    {
        return hash_hmac('sha256', $code, (string) config('app.key'));
    }

    public static function matches(string $hash, string $code): bool
    {
        return hash_equals($hash, self::hash($code));
    }
}
