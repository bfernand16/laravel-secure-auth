<?php

namespace SecureAuth\Http\Controllers;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use SecureAuth\Guard\TokenGuard;
use SecureAuth\Models\AuthSession;

abstract class Controller
{
    protected function guard(): TokenGuard
    {
        /** @var TokenGuard $guard */
        $guard = Auth::guard((string) config('secure-auth.guard', 'secure-auth'));

        return $guard;
    }

    protected function currentSession(): ?AuthSession
    {
        return $this->guard()->session();
    }

    protected function user(Request $request): Authenticatable
    {
        $user = $request->user();
        abort_if($user === null, 401);

        return $user;
    }
}
