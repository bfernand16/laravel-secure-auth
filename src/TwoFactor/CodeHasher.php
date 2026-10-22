<?php

namespace SecureAuth\TwoFactor;

/** Keyed hash of short codes (recovery codes): the database alone is not enough to brute-force them back. */
final class CodeHasher
{
    public static function hash(string $code): string
    {
        return self::hashWith($code, (string) config('app.key'));
    }

    /**
     * The hash under the current key and under each of `app.previous_keys`, so rotating APP_KEY keeps the codes valid.
     *
     * @return list<string>
     */
    public static function candidates(string $code): array
    {
        $keys = [(string) config('app.key'), ...array_map('strval', (array) config('app.previous_keys', []))];

        return array_values(array_unique(array_map(fn (string $key) => self::hashWith($code, $key), array_filter($keys))));
    }

    public static function matches(string $hash, string $code): bool
    {
        foreach (self::candidates($code) as $candidate) {
            if (hash_equals($hash, $candidate)) {
                return true;
            }
        }

        return false;
    }

    private static function hashWith(string $code, string $key): string
    {
        return hash_hmac('sha256', $code, $key);
    }
}
