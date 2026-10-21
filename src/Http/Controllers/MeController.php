<?php

namespace SecureAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rule;
use Illuminate\Validation\Rules\Password;
use Illuminate\Validation\ValidationException;
use SecureAuth\Audit\SecurityEvents;
use SecureAuth\Audit\SecurityEventType;
use SecureAuth\Events\SessionRevoked;
use SecureAuth\Permissions\Permissions;
use SecureAuth\Sessions\SessionTokens;
use SecureAuth\TwoFactor\StepUpGate;
use SecureAuth\TwoFactor\TwoFactorManager;
use SecureAuth\TwoFactor\TwoFactorVerifier;

/** The signed-in user: identity and CASL rules, step-up and password change. */
class MeController extends Controller
{
    public function __construct(
        private readonly SessionTokens $sessions,
        private readonly SecurityEvents $events,
    ) {}

    public function show(Request $request, Permissions $permissions, TwoFactorManager $twoFactor): JsonResponse
    {
        $user = $this->user($request);
        $session = $this->currentSession();
        $requiredAt = method_exists($user, 'twoFactorRequiredAt') ? $user->twoFactorRequiredAt() : null;
        $profile = method_exists($user, 'secureAuthProfile') ? $user->secureAuthProfile() : ['id' => $user->getAuthIdentifier()];

        return (new JsonResponse([
            'user' => $profile,
            'permissions' => $permissions->rules($user),
            'two_factor' => [
                'enabled' => $twoFactor->enabled($user),
                'required_at' => $requiredAt?->toIso8601String(),
                'setup_required' => $twoFactor->setupRequired($user),
            ],
            'session' => [
                'id' => $session?->id,
                'amr' => $session?->amr ?? [],
                'authenticated_at' => $session?->authenticated_at?->toIso8601String(),
                'last_mfa_at' => $session?->last_mfa_at?->toIso8601String(),
            ],
        ]))->header('Cache-Control', 'no-store');
    }

    public function stepUp(Request $request, StepUpGate $gate): JsonResponse
    {
        $user = $this->user($request);
        $data = $request->validate([
            'current_password' => ['required', 'string', 'max:1024'],
            'method' => ['nullable', 'string', Rule::in(TwoFactorVerifier::METHODS)],
            'code' => ['nullable', 'string', 'max:64'],
        ]);

        try {
            $method = $gate->authorize($user, $data['current_password'], $data['method'] ?? null, $data['code'] ?? null);
        } catch (ValidationException $exception) {
            $this->events->record($user, SecurityEventType::STEP_UP_FAILED, $request, ['reason' => array_key_first($exception->errors())]);

            throw $exception;
        }

        $session = $this->currentSession();
        abort_if($session === null, 401);
        $this->sessions->markStepUp($session, $method);
        $this->events->record($user, SecurityEventType::STEP_UP, $request, ['session_id' => $session->id, 'method' => $method]);

        return new JsonResponse(['last_mfa_at' => $session->last_mfa_at?->toIso8601String()]);
    }

    /** Changes the password, closes every session (and their tokens) and opens a fresh one for this device. */
    public function password(Request $request): JsonResponse
    {
        $user = $this->user($request);
        $data = $request->validate([
            'current_password' => ['required', 'string', 'max:1024'],
            'password' => ['required', 'string', 'max:1024', 'confirmed', 'different:current_password', Password::defaults()],
        ]);

        if (! Hash::check($data['current_password'], $user->getAuthPassword())) {
            throw ValidationException::withMessages(['current_password' => [__('secure-auth::messages.wrong_password')]]);
        }

        $user->forceFill([$user->getAuthPasswordName() => Hash::make($data['password'])])->save();

        $remember = (bool) $this->currentSession()?->remember;
        $this->sessions->revokeAll($user, SessionRevoked::REASON_PASSWORD);
        $this->events->record($user, SecurityEventType::PASSWORD_CHANGED, $request);
        $issued = $this->sessions->issueSession($user, $request, $remember, [SessionTokens::AMR_PASSWORD]);

        return $issued->attachTo(new JsonResponse(['status' => 'success', 'authorization' => $issued->authorization()]));
    }
}
