<?php

namespace SecureAuth\Sessions;

/** Readable browser and system from the user agent, so the raw user agent is never stored. */
final class DeviceLabel
{
    public const UNKNOWN = 'Unknown';

    private const BROWSERS = [
        'Edge' => '/Edg(e|A|iOS)?\//',
        'Opera' => '/OPR\/|Opera/',
        'Firefox' => '/Firefox\/|FxiOS\//',
        'Chrome' => '/Chrome\/|CriOS\//',
        'Safari' => '/Safari\//',
    ];

    private const SYSTEMS = [
        'Android' => '/Android/',
        'iOS' => '/iPhone|iPad|iPod/',
        'Windows' => '/Windows/',
        'macOS' => '/Mac OS X|Macintosh/',
        'Linux' => '/Linux|X11/',
    ];

    public static function fromUserAgent(?string $userAgent): string
    {
        $agent = (string) $userAgent;

        return self::match(self::BROWSERS, $agent).' · '.self::match(self::SYSTEMS, $agent);
    }

    public static function hash(?string $userAgent): ?string
    {
        return $userAgent === null || $userAgent === '' ? null : hash('sha256', $userAgent);
    }

    /** @param  array<string, string>  $patterns */
    private static function match(array $patterns, string $agent): string
    {
        foreach ($patterns as $name => $pattern) {
            if (preg_match($pattern, $agent) === 1) {
                return $name;
            }
        }

        return self::UNKNOWN;
    }
}
