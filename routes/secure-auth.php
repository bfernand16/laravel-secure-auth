<?php

use Illuminate\Support\Facades\Route;
use SecureAuth\Http\Controllers\AuthController;
use SecureAuth\Http\Controllers\MeController;
use SecureAuth\Http\Controllers\SecurityEventsController;
use SecureAuth\Http\Controllers\SessionsController;
use SecureAuth\Http\Controllers\TwoFactorController;

Route::prefix((string) config('secure-auth.routes.prefix', 'api'))
    ->middleware((array) config('secure-auth.routes.middleware', ['api']))
    ->name('secure-auth.')
    ->group(function () {
        Route::prefix('auth')->middleware('secure-auth.same-origin')->group(function () {
            Route::post('/login', [AuthController::class, 'login'])->middleware('throttle:secure-auth.login')->name('login');
            Route::post('/two-factor', [AuthController::class, 'verifyTwoFactor'])->middleware('throttle:secure-auth.two-factor')->name('login.two-factor');
            Route::post('/refresh', [AuthController::class, 'refresh'])->middleware('throttle:secure-auth.refresh')->name('refresh');
            Route::post('/logout', [AuthController::class, 'logout'])->middleware('throttle:secure-auth.refresh')->name('logout');
        });

        Route::middleware(['secure-auth', 'throttle:secure-auth.account'])->group(function () {
            Route::get('/me', [MeController::class, 'show'])->name('me');
            Route::post('/me/step-up', [MeController::class, 'stepUp'])->middleware('throttle:secure-auth.step-up')->name('step-up');

            if (config('secure-auth.routes.password_change', true)) {
                Route::put('/me/password', [MeController::class, 'password'])->middleware('secure-auth.recent-mfa')->name('password');
            }

            Route::get('/me/sessions', [SessionsController::class, 'index'])->name('sessions.index');
            Route::delete('/me/sessions', [SessionsController::class, 'destroyOthers'])->name('sessions.destroy-others');
            Route::delete('/me/sessions/{session}', [SessionsController::class, 'destroy'])->whereNumber('session')->name('sessions.destroy');

            Route::get('/me/security-events', [SecurityEventsController::class, 'index'])->name('security-events');

            Route::get('/me/two-factor', [TwoFactorController::class, 'show'])->name('two-factor.show');
            Route::post('/me/two-factor/totp', [TwoFactorController::class, 'start'])->middleware('secure-auth.recent-mfa')->name('two-factor.start');
            Route::post('/me/two-factor/totp/confirm', [TwoFactorController::class, 'confirm'])->middleware('throttle:secure-auth.step-up')->name('two-factor.confirm');
            Route::post('/me/two-factor/recovery-codes', [TwoFactorController::class, 'regenerateRecoveryCodes'])->middleware('secure-auth.recent-mfa')->name('two-factor.recovery-codes');
            Route::delete('/me/two-factor/totp', [TwoFactorController::class, 'disable'])->middleware('secure-auth.recent-mfa')->name('two-factor.disable');
        });
    });
