<?php

namespace SecureAuth\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rule;
use SecureAuth\Audit\SecurityEvents;
use SecureAuth\Audit\SecurityEventType;
use SecureAuth\Events\SessionRevoked;
use SecureAuth\Http\Responses;
use SecureAuth\Models\AuthSession;
use SecureAuth\Models\LoginChallenge;
use SecureAuth\Models\TwoFactorMethod;
use SecureAuth\Sessions\SessionCookie;
use SecureAuth\Sessions\SessionTokens;
use SecureAuth\Tokens\AccessTokens;
use SecureAuth\TwoFactor\LoginChallenges;
use SecureAuth\TwoFactor\TwoFactorManager;
use SecureAuth\TwoFactor\TwoFactorVerifier;

/** Login (with the TOTP second step), refresh and logout. The only routes that use the refresh cookie. */
class AuthController extends Controller
{
    private static ?string $timingHash = null;

    public function __construct(
        private readonly SessionTokens $sessions,
        private readonly SecurityEvents $events,
        private readonly TwoFactorManager $twoFactor,
        private readonly LoginChallenges $challenges,
    ) {}

    public function login(Request $request): JsonResponse
    {
        $field = (string) config('secure-auth.login_field', 'email');
        $data = $request->validate([
            $field => ['required', 'string', 'max:255'],
            'password' => ['required', 'string', 'max:1024'],
            'remember' => ['sometimes', 'boolean'],
        ]);

        $user = $this->findUser($field, (string) $data[$field]);

        if (! $user || ! Hash::check((string) $data['password'], $user->getAuthPassword())) {
            $user ? $this->events->record($user, SecurityEventType::LOGIN_FAILED, $request, ['reason' => 'bad_credentials']) : $this->spendHashTime((string) $data['password']);

            return Responses::error('invalid_credentials', 401);
        }

        if ($blocked = $this->refuse($user)) {
            return $blocked;
        }

        $this->rehashPassword($user, (string) $data['password']);

        if ($this->twoFactor->enabled($user)) {
            return new JsonResponse(['two_factor' => true] + $this->challenges->open($user, $request->boolean('remember')));
        }

        return $this->openSession($user, $request, $request->boolean('remember'), [SessionTokens::AMR_PASSWORD]);
    }

    private function rehashPassword(Authenticatable $user, string $password): void
    {
        if (! Hash::needsRehash($user->getAuthPassword())) {
            return;
        }

        $user->forceFill([$user->getAuthPasswordName() => Hash::make($password)])->save();
    }

    public function verifyTwoFactor(Request $request): JsonResponse
    {
        $data = $request->validate([
            'challenge' => ['required', 'string', 'max:128'],
            'method' => ['required', 'string', Rule::in(TwoFactorVerifier::METHODS)],
            'code' => ['required', 'string', 'max:64'],
        ]);

        $result = $this->challenges->attempt($data['challenge'], $data['method'], $data['code']);

        if ($result['status'] !== LoginChallenges::OK) {
            $this->recordFailedCode($result, $request);

            return $this->challengeFailure($result);
        }

        /** @var LoginChallenge $challenge */
        $challenge = $result['challenge'];
        $user = $challenge->user;

        if ($blocked = $this->refuse($user)) {
            return $blocked;
        }

        $second = $data['method'] === TwoFactorMethod::TOTP ? SessionTokens::AMR_OTP : SessionTokens::AMR_RECOVERY;

        return $this->openSession($user, $request, $challenge->remember, [SessionTokens::AMR_PASSWORD, $second]);
    }

    public function refresh(Request $request): JsonResponse|Response
    {
        if (! SessionCookie::present($request)) {
            return response()->noContent()->header('Cache-Control', 'no-store');
        }

        $issued = $this->sessions->refresh($request);

        if ($issued === null) {
            return $this->withoutCookie(Responses::error('session_invalid', 401));
        }

        return $issued->attachTo(new JsonResponse(['two_factor' => false, 'authorization' => $issued->authorization()]));
    }

    public function logout(Request $request, AccessTokens $tokens): JsonResponse
    {
        $session = $this->sessions->sessionForCookie($request) ?? $this->sessionOfBearer($request, $tokens);

        if ($session) {
            $this->sessions->revoke($session, SessionRevoked::REASON_LOGOUT);

            if ($session->user) {
                $this->events->record($session->user, SecurityEventType::LOGOUT, $request, ['session_id' => $session->id]);
            }
        }

        return $this->withoutCookie(new JsonResponse(['status' => 'success']));
    }

    /** @param  list<string>  $amr */
    private function openSession(Authenticatable $user, Request $request, bool $remember, array $amr): JsonResponse
    {
        $issued = $this->sessions->issueSession($user, $request, $remember, $amr);
        $this->events->record($user, SecurityEventType::LOGIN, $request, ['session_id' => $issued->session->id, 'method' => implode('+', $amr)]);

        return $issued->attachTo(new JsonResponse(['two_factor' => false, 'authorization' => $issued->authorization()]));
    }

    private function refuse(Authenticatable $user): ?JsonResponse
    {
        if (method_exists($user, 'secureAuthIsBlocked') && $user->secureAuthIsBlocked()) {
            return Responses::error('account_blocked', 403);
        }

        if (config('secure-auth.require_verified_email', true) && $user instanceof MustVerifyEmail && ! $user->hasVerifiedEmail()) {
            return Responses::error('email_unverified', 403);
        }

        return null;
    }

    private function findUser(string $field, string $value): ?Authenticatable
    {
        $model = (string) config('secure-auth.user_model');

        return $model::query()->where($field, $value)->first();
    }

    /** Unknown accounts cost the same hash check as known ones, so response times do not reveal which emails exist. */
    private function spendHashTime(string $password): void
    {
        self::$timingHash ??= Hash::make('secure-auth-timing-equaliser');
        Hash::check($password, self::$timingHash);
    }

    private function sessionOfBearer(Request $request, AccessTokens $tokens): ?AuthSession
    {
        $jwt = $request->bearerToken();
        $claims = $jwt ? $tokens->parse($jwt) : null;
        $session = $claims ? AuthSession::find($claims->sessionId) : null;

        return $session && (string) $session->user_id === $claims->subject && $session->revoked_at === null ? $session : null;
    }

    /** @param  array{status: string, challenge?: LoginChallenge}  $result */
    private function recordFailedCode(array $result, Request $request): void
    {
        if (isset($result['challenge']) && $result['challenge']->user && in_array($result['status'], [LoginChallenges::WRONG_CODE, LoginChallenges::EXHAUSTED], true)) {
            $this->events->record($result['challenge']->user, SecurityEventType::LOGIN_FAILED, $request, ['reason' => 'two_factor_code', 'step' => 'two_factor']);
        }
    }

    /** @param  array{status: string, remaining?: int}  $result */
    private function challengeFailure(array $result): JsonResponse
    {
        return match ($result['status']) {
            LoginChallenges::WRONG_CODE => Responses::error('two_factor_code_invalid', 422, ['attempts_remaining' => $result['remaining'] ?? 0]),
            LoginChallenges::EXHAUSTED => Responses::error('two_factor_attempts_exhausted', 401),
            LoginChallenges::THROTTLED => Responses::error('two_factor_throttled', 429),
            default => Responses::error('two_factor_challenge_invalid', 401),
        };
    }

    private function withoutCookie(JsonResponse $response): JsonResponse
    {
        $response->headers->setCookie(SessionCookie::forget());

        return $response->header('Cache-Control', 'no-store');
    }
}
