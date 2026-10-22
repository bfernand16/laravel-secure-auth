<?php

namespace SecureAuth\Tests\Unit;

use SecureAuth\Tests\TestCase;
use SecureAuth\TwoFactor\CodeHasher;
use SecureAuth\TwoFactor\RecoveryCodeService;

class CodeHashingTest extends TestCase
{
    public function test_codes_are_hashed_with_the_app_key(): void
    {
        $hash = CodeHasher::hash('abcde12345');

        $this->assertNotSame(hash('sha256', 'abcde12345'), $hash);
        $this->assertTrue(CodeHasher::matches($hash, 'abcde12345'));
        $this->assertFalse(CodeHasher::matches($hash, 'abcde12346'));
    }

    public function test_recovery_codes_survive_an_app_key_rotation(): void
    {
        $user = $this->createUser();
        $codes = app(RecoveryCodeService::class)->regenerate($user);
        $oldKey = config('app.key');

        config(['app.key' => 'base64:'.base64_encode(random_bytes(32)), 'app.previous_keys' => [$oldKey]]);

        $this->assertTrue(app(RecoveryCodeService::class)->consume($user, $codes[0]));
    }

    public function test_recovery_codes_have_the_configured_count_and_no_ambiguous_characters(): void
    {
        config(['secure-auth.two_factor.recovery_codes' => 8]);

        $codes = app(RecoveryCodeService::class)->regenerate($this->createUser());

        $this->assertCount(8, $codes);
        $this->assertCount(8, array_unique($codes));
        foreach ($codes as $code) {
            $this->assertMatchesRegularExpression('/^[a-hjkmnp-z2-9]{5}-[a-hjkmnp-z2-9]{5}$/', $code);
        }
    }
}
