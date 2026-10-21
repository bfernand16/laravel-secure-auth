<?php

namespace SecureAuth\Tokens;

use DateInterval;
use DateTimeImmutable;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Str;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token\Plain;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use SecureAuth\Models\AuthSession;
use SecureAuth\Permissions\Permissions;
use Throwable;

/**
 * Short-lived HS256 access tokens. Claims: `sub`, `sid` (refresh session), `pv` (permission version), `amr`, `auth_time`,
 * plus the registered `iss`, `iat`, `nbf`, `exp` and `jti`.
 */
class AccessTokens
{
    private ?Configuration $configuration = null;

    public function __construct(private readonly Permissions $permissions) {}

    public function issue(Authenticatable $user, AuthSession $session): string
    {
        $now = new DateTimeImmutable('@'.now()->getTimestamp());
        $authTime = $session->authenticated_at ?? $session->created_at ?? now();

        return $this->configuration()->builder()
            ->issuedBy($this->issuer())
            ->identifiedBy(Str::random(32))
            ->relatedTo((string) $user->getAuthIdentifier())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($now->add(new DateInterval('PT'.self::ttlSeconds().'S')))
            ->withClaim('sid', (int) $session->id)
            ->withClaim('pv', $this->permissions->version($user))
            ->withClaim('amr', array_values($session->amr ?? ['pwd']))
            ->withClaim('auth_time', $authTime->getTimestamp())
            ->getToken($this->configuration()->signer(), $this->configuration()->signingKey())
            ->toString();
    }

    /** Verified claims, or null when the token is malformed, forged, expired or from another issuer. */
    public function parse(string $jwt): ?AccessTokenClaims
    {
        try {
            $token = $this->configuration()->parser()->parse($jwt);
        } catch (Throwable) {
            return null;
        }

        if (! $token instanceof Plain || ! $this->configuration()->validator()->validate($token, ...$this->configuration()->validationConstraints())) {
            return null;
        }

        return $this->claimsOf($token);
    }

    public static function ttlSeconds(): int
    {
        return max(1, (int) config('secure-auth.access_token.ttl_minutes', 10)) * 60;
    }

    private function claimsOf(Plain $token): ?AccessTokenClaims
    {
        $claims = $token->claims();
        $sid = $claims->get('sid');
        $sub = $claims->get('sub');
        $pv = $claims->get('pv');
        $amr = $claims->get('amr', []);

        if (! is_int($sid) || ! is_string($sub) || $sub === '' || ! is_string($pv) || ! is_array($amr)) {
            return null;
        }

        return new AccessTokenClaims(
            subject: $sub,
            sessionId: $sid,
            permissionVersion: $pv,
            amr: array_values(array_filter($amr, 'is_string')),
            authTime: (int) $claims->get('auth_time', 0),
            issuedAt: $claims->get('iat')->getTimestamp(),
            expiresAt: $claims->get('exp')->getTimestamp(),
            id: (string) $claims->get('jti', ''),
        );
    }

    private function configuration(): Configuration
    {
        if ($this->configuration !== null) {
            return $this->configuration;
        }

        $configuration = Configuration::forSymmetricSigner(new Sha256, InMemory::plainText($this->secret()));
        $leeway = new DateInterval('PT'.max(0, (int) config('secure-auth.access_token.leeway_seconds', 0)).'S');

        return $this->configuration = $configuration->withValidationConstraints(
            new SignedWith($configuration->signer(), $configuration->verificationKey()),
            new StrictValidAt(new CarbonClock, $leeway),
            new IssuedBy($this->issuer()),
        );
    }

    /** The configured secret, or a key derived from APP_KEY (32 bytes) so the package works without extra setup. */
    private function secret(): string
    {
        $secret = (string) config('secure-auth.access_token.secret');

        if ($secret !== '') {
            return $secret;
        }

        return hash_hmac('sha256', 'secure-auth:access-token', (string) config('app.key'), true);
    }

    private function issuer(): string
    {
        return (string) config('secure-auth.access_token.issuer', 'secure-auth');
    }
}
