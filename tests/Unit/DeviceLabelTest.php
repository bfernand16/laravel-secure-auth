<?php

namespace SecureAuth\Tests\Unit;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SecureAuth\Sessions\DeviceLabel;

class DeviceLabelTest extends TestCase
{
    /** @return array<string, array{string|null, string}> */
    public static function agents(): array
    {
        return [
            'chrome on windows' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36', 'Chrome · Windows'],
            'edge on windows' => ['Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0', 'Edge · Windows'],
            'safari on iphone' => ['Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1', 'Safari · iOS'],
            'firefox on android' => ['Mozilla/5.0 (Android 14; Mobile; rv:127.0) Gecko/127.0 Firefox/127.0', 'Firefox · Android'],
            'firefox on macos' => ['Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:127.0) Gecko/20100101 Firefox/127.0', 'Firefox · macOS'],
            'nothing' => [null, 'Unknown · Unknown'],
        ];
    }

    #[DataProvider('agents')]
    public function test_it_reads_the_browser_and_the_system(?string $agent, string $label): void
    {
        $this->assertSame($label, DeviceLabel::fromUserAgent($agent));
    }

    public function test_the_hash_of_an_empty_agent_is_null(): void
    {
        $this->assertNull(DeviceLabel::hash(''));
        $this->assertSame(64, strlen((string) DeviceLabel::hash('agent')));
    }
}
