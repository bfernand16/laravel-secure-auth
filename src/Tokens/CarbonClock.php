<?php

namespace SecureAuth\Tokens;

use DateTimeImmutable;
use Illuminate\Support\Carbon;
use Psr\Clock\ClockInterface;

/** PSR-20 clock that follows Carbon, so token validation honours `Carbon::setTestNow()` and `travel()` in tests. */
final class CarbonClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return Carbon::now()->toDateTimeImmutable();
    }
}
