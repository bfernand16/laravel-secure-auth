<?php

namespace SecureAuth\Console;

use Illuminate\Console\Command;
use SecureAuth\Audit\SecurityEvents;
use SecureAuth\Models\TwoFactorMethod;
use SecureAuth\Sessions\SessionTokens;
use SecureAuth\TwoFactor\LoginChallenges;

class PruneCommand extends Command
{
    protected $signature = 'secure-auth:prune';

    protected $description = 'Delete expired or long-revoked sessions, expired login challenges, abandoned TOTP enrolments and old security events';

    public function handle(SessionTokens $sessions, LoginChallenges $challenges, SecurityEvents $events): int
    {
        $sessionCount = $sessions->prune();
        $challengeCount = $challenges->prune();
        $pendingCount = TwoFactorMethod::whereNull('confirmed_at')->where('created_at', '<', now()->subDay())->delete();
        $eventCount = $events->prune();

        $this->info("Sessions: {$sessionCount}. Challenges: {$challengeCount}. Pending TOTP: {$pendingCount}. Security events: {$eventCount}.");

        return self::SUCCESS;
    }
}
