<?php

namespace SecureAuth\Http\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use SecureAuth\Models\SecurityEvent;

/** The account's own security history, newest first. */
class SecurityEventsController extends Controller
{
    private const PER_PAGE = 20;

    public function index(Request $request): JsonResponse
    {
        $page = SecurityEvent::where('user_id', $this->user($request)->getAuthIdentifier())->orderByDesc('id')->paginate(self::PER_PAGE);

        return new JsonResponse([
            'data' => $page->getCollection()->map(fn (SecurityEvent $event) => [
                'id' => $event->id,
                'type' => $event->type,
                'ip' => $event->ip,
                'device' => $event->device,
                'meta' => $event->meta ?? (object) [],
                'by_admin' => $event->actor_id !== null,
                'created_at' => $event->created_at->toIso8601String(),
            ])->values(),
            'meta' => ['current_page' => $page->currentPage(), 'last_page' => $page->lastPage(), 'per_page' => $page->perPage(), 'total' => $page->total()],
        ]);
    }
}
