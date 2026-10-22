<?php

namespace SecureAuth\Http;

use Illuminate\Http\JsonResponse;

/** JSON error bodies: a translated `message` for people and a stable `reason` code for clients. */
final class Responses
{
    /** @param  array<string, mixed>  $extra */
    public static function error(string $reason, int $status, array $extra = []): JsonResponse
    {
        return new JsonResponse(['message' => __('secure-auth::messages.'.$reason), 'reason' => $reason] + $extra, $status);
    }
}
