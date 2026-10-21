<?php

namespace SecureAuth\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use SecureAuth\Audit\SecurityEvents;
use SecureAuth\Audit\SecurityEventType;
use SecureAuth\Http\Responses;
use SecureAuth\Models\TwoFactorMethod;
use SecureAuth\Sessions\SessionTokens;
use SecureAuth\TwoFactor\QrCodeRenderer;
use SecureAuth\TwoFactor\RecoveryCodeService;
use SecureAuth\TwoFactor\TotpService;
use SecureAuth\TwoFactor\TwoFactorManager;

/**
 * The account's authenticator app. Enrolling, regenerating codes and disabling sit behind `secure-auth.recent-mfa`. The
 * secret is only returned when enrolment starts; recovery codes only when they are created.
 */
class TwoFactorController extends Controller
{
    public function __construct(
        private readonly TwoFactorManager $manager,
        private readonly RecoveryCodeService $recoveryCodes,
        private readonly SecurityEvents $events,
    ) {}

    public function show(Request $request): JsonResponse
    {
        return new JsonResponse($this->summary($this->user($request)));
    }

    public function start(Request $request, TotpService $totp, QrCodeRenderer $qr): JsonResponse
    {
        $user = $this->user($request);

        if ($this->manager->enabled($user)) {
            return Responses::error('two_factor_already_enabled', 422);
        }

        $secret = $this->manager->startTotp($user);
        $account = (string) $user->getAttribute((string) config('secure-auth.login_field', 'email'));
        $url = $totp->otpauthUrl($secret, $account);

        return $this->noStore(new JsonResponse(['secret' => $secret, 'otpauth_url' => $url, 'qr_svg' => $qr->svg($url)]));
    }

    public function confirm(Request $request, SessionTokens $sessions): JsonResponse
    {
        $user = $this->user($request);
        $code = (string) $request->validate(['code' => ['required', 'string', 'max:16']])['code'];
        $codes = $this->manager->confirmTotp($user, $code);

        if ($codes === null) {
            throw ValidationException::withMessages(['code' => [__('secure-auth::messages.two_factor_invalid')]]);
        }

        if ($session = $this->currentSession()) {
            $sessions->markStepUp($session, SessionTokens::AMR_OTP);
        }

        $this->events->record($user, SecurityEventType::TWO_FACTOR_ENABLED, $request, ['method' => TwoFactorMethod::TOTP]);

        return $this->noStore(new JsonResponse($this->summary($user) + ['recovery_codes' => $codes]));
    }

    public function regenerateRecoveryCodes(Request $request): JsonResponse
    {
        $user = $this->user($request);

        if (! $this->manager->enabled($user)) {
            return Responses::error('two_factor_not_enabled', 422);
        }

        $codes = $this->recoveryCodes->regenerate($user);
        $this->events->record($user, SecurityEventType::RECOVERY_CODES_REGENERATED, $request);

        return $this->noStore(new JsonResponse($this->summary($user) + ['recovery_codes' => $codes]));
    }

    public function disable(Request $request): JsonResponse
    {
        $user = $this->user($request);

        if (! $this->manager->enabled($user)) {
            return Responses::error('two_factor_not_enabled', 422);
        }

        if ($this->manager->mandatory($user)) {
            return Responses::error('two_factor_mandatory', 422);
        }

        $this->manager->disable($user);
        $this->events->record($user, SecurityEventType::TWO_FACTOR_DISABLED, $request, ['method' => TwoFactorMethod::TOTP]);

        return new JsonResponse($this->summary($user));
    }

    /** @return array<string, mixed> */
    private function summary(Authenticatable $user): array
    {
        $method = $this->manager->confirmedTotp($user);
        $requiredAt = method_exists($user, 'twoFactorRequiredAt') ? $user->twoFactorRequiredAt() : null;

        return [
            'enabled' => $method !== null,
            'confirmed_at' => $method?->confirmed_at?->toIso8601String(),
            'last_used_at' => $method?->last_used_at?->toIso8601String(),
            'recovery_codes_remaining' => $method ? $this->recoveryCodes->remaining($user) : 0,
            'required_at' => $requiredAt?->toIso8601String(),
            'setup_required' => $this->manager->setupRequired($user),
        ];
    }

    private function noStore(JsonResponse $response): JsonResponse
    {
        return $response->header('Cache-Control', 'no-store');
    }
}
