<?php

namespace SecureAuth\TwoFactor;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\DB;
use SecureAuth\Models\RecoveryCode;

/** Single-use codes to log in without the authenticator; shown once, only their keyed hash is stored. */
class RecoveryCodeService
{
    private const ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

    private const HALF_LENGTH = 5;

    /**
     * Replaces every previous code of the user with a new set.
     *
     * @return list<string>
     */
    public function regenerate(Authenticatable $user): array
    {
        $codes = [];

        for ($index = 0; $index < $this->count(); $index++) {
            $codes[] = $this->randomHalf().'-'.$this->randomHalf();
        }

        DB::transaction(function () use ($user, $codes) {
            RecoveryCode::where('user_id', $user->getAuthIdentifier())->delete();
            RecoveryCode::insert(array_map(fn (string $code) => [
                'user_id' => $user->getAuthIdentifier(),
                'code_hash' => CodeHasher::hash($this->normalize($code)),
                'created_at' => now(),
                'updated_at' => now(),
            ], $codes));
        });

        return $codes;
    }

    public function consume(Authenticatable $user, string $code): bool
    {
        $row = RecoveryCode::where('user_id', $user->getAuthIdentifier())
            ->where('code_hash', CodeHasher::hash($this->normalize($code)))
            ->whereNull('used_at')
            ->first();

        if (! $row) {
            return false;
        }

        return RecoveryCode::whereKey($row->id)->whereNull('used_at')->update(['used_at' => now()]) === 1;
    }

    public function remaining(Authenticatable $user): int
    {
        return RecoveryCode::where('user_id', $user->getAuthIdentifier())->whereNull('used_at')->count();
    }

    public function clear(Authenticatable $user): void
    {
        RecoveryCode::where('user_id', $user->getAuthIdentifier())->delete();
    }

    private function count(): int
    {
        return max(1, (int) config('secure-auth.two_factor.recovery_codes', 10));
    }

    private function normalize(string $code): string
    {
        return strtolower((string) preg_replace('/[\s-]+/', '', $code));
    }

    private function randomHalf(): string
    {
        $half = '';

        for ($position = 0; $position < self::HALF_LENGTH; $position++) {
            $half .= self::ALPHABET[random_int(0, strlen(self::ALPHABET) - 1)];
        }

        return $half;
    }
}
