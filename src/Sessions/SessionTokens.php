<?php

namespace SecureAuth\Sessions;

use DateTimeInterface;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SecureAuth\Events\SessionRevoked;
use SecureAuth\Models\AuthSession;
use SecureAuth\Tokens\AccessTokens;

/**
 * Refresh sessions: issue, refresh with secret rotation, revoke and prune. Every lookup is by `selector` (unique index) or
 * scoped to the user, never a scan of the whole table.
 */
class SessionTokens
{
    public const AMR_PASSWORD = 'pwd';

    public const AMR_OTP = 'otp';

    public const AMR_RECOVERY = 'recovery';

    public function __construct(private readonly AccessTokens $accessTokens) {}

    /**
     * Opens a new session and returns the access token and the refresh cookie. Single issuing point.
     *
     * @param  list<string>  $amr  authentication methods used (`pwd`, `otp`, `recovery`)
     */
    public function issueSession(Authenticatable $user, Request $request, bool $remember, array $amr = [self::AMR_PASSWORD]): IssuedSession
    {
        $secret = Str::random(48);
        $absolute = now()->addDays((int) config('secure-auth.session.absolute_days.'.($remember ? 'remember' : 'default'), 7));
        $userAgent = $request->header('User-Agent');

        $session = AuthSession::create([
            'user_id' => $user->getAuthIdentifier(),
            'selector' => Str::random(24),
            'secret_hash' => $this->hashSecret($secret),
            'family_id' => (string) Str::uuid(),
            'device_label' => DeviceLabel::fromUserAgent($userAgent),
            'device_hash' => DeviceLabel::hash($userAgent),
            'ip' => $request->ip(),
            'remember' => $remember,
            'amr' => array_values(array_unique($amr)),
            'authenticated_at' => now(),
            'last_mfa_at' => now(),
            'last_used_at' => now(),
            'absolute_expires_at' => $absolute,
            'expires_at' => $this->slidingExpiry($remember, $absolute),
        ]);

        return new IssuedSession($session, $this->accessTokens->issue($user, $session), SessionCookie::make($session, $secret));
    }

    /**
     * Exchanges the refresh cookie for a new access token and rotates the secret. A secret that was already rotated
     * reveals a stolen copy: the whole family is revoked. Returns null when the cookie is not valid.
     */
    public function refresh(Request $request): ?IssuedSession
    {
        $parts = SessionCookie::parse($request);

        return $parts === null ? null : DB::transaction(fn () => $this->rotate($parts[0], $parts[1]));
    }

    public function sessionForCookie(Request $request): ?AuthSession
    {
        $parts = SessionCookie::parse($request);
        $session = $parts === null ? null : AuthSession::where('selector', $parts[0])->first();

        return $session && $session->revoked_at === null && $this->secretMatches($session->secret_hash, $parts[1]) ? $session : null;
    }

    /** Records a fresh strong authentication (step-up) on the session. */
    public function markStepUp(AuthSession $session, string $method): void
    {
        $session->forceFill([
            'last_mfa_at' => now(),
            'amr' => array_values(array_unique(array_merge($session->amr ?? [], [$method]))),
        ])->save();
    }

    public function revoke(AuthSession $session, string $reason): void
    {
        if ($session->revoked_at === null) {
            $session->forceFill(['revoked_at' => now()])->save();
        }

        SessionRevoked::dispatch($session->id, $session->user_id, $reason);
    }

    /** Closes every session of the user but one. Returns how many were closed. */
    public function revokeOthers(Authenticatable $user, ?int $keepSessionId, string $reason = SessionRevoked::REASON_USER): int
    {
        $sessions = AuthSession::where('user_id', $user->getAuthIdentifier())
            ->whereNull('revoked_at')
            ->when($keepSessionId !== null, fn ($query) => $query->whereKeyNot($keepSessionId))
            ->get();

        $sessions->each(fn (AuthSession $session) => $this->revoke($session, $reason));

        return $sessions->count();
    }

    /** Closes every session of the user; their access tokens stop working at once (the guard checks `sid`). */
    public function revokeAll(Authenticatable $user, string $reason = SessionRevoked::REASON_ACCOUNT): int
    {
        return $this->revokeOthers($user, null, $reason);
    }

    /** Deletes sessions that expired (idle or absolute limit) and the ones revoked a while ago. */
    public function prune(): int
    {
        return AuthSession::where('expires_at', '<', now())
            ->orWhere('absolute_expires_at', '<', now())
            ->orWhere('revoked_at', '<', now()->subDays((int) config('secure-auth.session.revoked_retention_days', 30)))
            ->delete();
    }

    private function rotate(string $selector, string $secret): ?IssuedSession
    {
        $session = AuthSession::where('selector', $selector)->lockForUpdate()->first();

        if (! $session || $session->revoked_at !== null) {
            return null;
        }

        $user = $session->user;

        if (! $this->secretMatches($session->secret_hash, $secret)) {
            return $this->isRecentRotation($session, $secret) && $this->canUse($user)
                ? new IssuedSession($session, $this->accessTokens->issue($user, $session), null)
                : $this->rejectReusedSecret($session);
        }

        if ($session->expires_at->isPast() || $session->absolute_expires_at->isPast() || ! $this->canUse($user)) {
            $this->revoke($session, SessionRevoked::REASON_ACCOUNT);

            return null;
        }

        $newSecret = Str::random(48);
        $session->forceFill([
            'previous_secret_hash' => $session->secret_hash,
            'secret_hash' => $this->hashSecret($newSecret),
            'last_used_at' => now(),
            'expires_at' => $this->slidingExpiry($session->remember, $session->absolute_expires_at),
        ])->save();

        return new IssuedSession($session, $this->accessTokens->issue($user, $session), SessionCookie::make($session, $newSecret));
    }

    private function canUse(?Authenticatable $user): bool
    {
        return $user !== null && ! (method_exists($user, 'secureAuthIsBlocked') && $user->secureAuthIsBlocked());
    }

    /** A reload or a second tab may arrive with the previous secret right after a rotation: that is not a theft. */
    private function isRecentRotation(AuthSession $session, string $secret): bool
    {
        return $session->previous_secret_hash !== null
            && $this->secretMatches($session->previous_secret_hash, $secret)
            && $session->last_used_at !== null
            && $session->last_used_at->greaterThan(now()->subSeconds((int) config('secure-auth.session.reuse_grace_seconds', 10)));
    }

    /**
     * The selector is as secret as the cookie, so a valid selector with any secret that is not the current one (nor the
     * previous one inside the grace) means someone holds an old copy of the cookie: the whole family is closed.
     */
    private function rejectReusedSecret(AuthSession $session): null
    {
        AuthSession::where('family_id', $session->family_id)->whereNull('revoked_at')->get()
            ->each(fn (AuthSession $family) => $this->revoke($family, SessionRevoked::REASON_REUSE));

        return null;
    }

    private function slidingExpiry(bool $remember, DateTimeInterface $absolute): Carbon
    {
        $sliding = now()->addHours((int) config('secure-auth.session.sliding_hours.'.($remember ? 'remember' : 'default'), 24));
        $limit = Carbon::instance($absolute);

        return $sliding->greaterThan($limit) ? $limit : $sliding;
    }

    private function hashSecret(string $secret): string
    {
        return hash('sha256', $secret);
    }

    private function secretMatches(string $hash, string $secret): bool
    {
        return hash_equals($hash, $this->hashSecret($secret));
    }
}
