<?php

namespace SecureAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SecureAuth\Audit\SecurityEvents;
use SecureAuth\Audit\SecurityEventType;
use SecureAuth\Events\SessionRevoked;
use SecureAuth\Models\AuthSession;
use SecureAuth\Sessions\SessionCookie;
use SecureAuth\Sessions\SessionTokens;

/** The account's open sessions: list, close one, close every other one. */
class SessionsController extends Controller
{
    public function __construct(
        private readonly SessionTokens $sessions,
        private readonly SecurityEvents $events,
    ) {}

    public function index(Request $request): JsonResponse
    {
        $current = $this->currentSession()?->id;
        $sessions = AuthSession::where('user_id', $this->user($request)->getAuthIdentifier())
            ->active()
            ->orderByDesc('last_used_at')
            ->orderByDesc('id')
            ->get();

        return new JsonResponse(['sessions' => $sessions->map(fn (AuthSession $session) => [
            'id' => $session->id,
            'device_label' => $session->device_label,
            'ip' => $session->ip,
            'remember' => $session->remember,
            'amr' => $session->amr ?? [],
            'created_at' => $session->created_at?->toIso8601String(),
            'last_used_at' => $session->last_used_at?->toIso8601String(),
            'expires_at' => $session->expires_at->toIso8601String(),
            'absolute_expires_at' => $session->absolute_expires_at->toIso8601String(),
            'current' => $session->id === $current,
        ])->values()]);
    }

    public function destroy(Request $request, int $session): JsonResponse
    {
        $user = $this->user($request);
        $target = AuthSession::where('user_id', $user->getAuthIdentifier())->active()->findOrFail($session);

        $this->sessions->revoke($target, SessionRevoked::REASON_USER);
        $this->events->record($user, SecurityEventType::SESSION_REVOKED, $request, ['session_id' => $target->id, 'device' => $target->device_label]);

        $response = new JsonResponse(['status' => 'success']);

        if ($target->id === $this->currentSession()?->id) {
            $response->headers->setCookie(SessionCookie::forget());
        }

        return $response;
    }

    public function destroyOthers(Request $request): JsonResponse
    {
        $user = $this->user($request);
        $closed = $this->sessions->revokeOthers($user, $this->currentSession()?->id);

        if ($closed > 0) {
            $this->events->record($user, SecurityEventType::SESSIONS_REVOKED_ALL, $request, ['closed' => $closed]);
        }

        return new JsonResponse(['status' => 'success', 'closed' => $closed]);
    }
}
