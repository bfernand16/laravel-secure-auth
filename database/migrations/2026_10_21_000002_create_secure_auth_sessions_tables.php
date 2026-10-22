<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SecureAuth\Support\Tables;

/**
 * Refresh sessions (only hashes of the cookie secret are stored) and the single-use challenges of the login second step.
 */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create(Tables::name('auth_sessions'), function (Blueprint $table) {
            $table->id();
            Tables::userForeign($table);
            $table->string('selector', 32)->unique();
            $table->char('secret_hash', 64);
            $table->char('previous_secret_hash', 64)->nullable();
            $table->char('family_id', 36)->index();
            $table->string('device_label')->nullable();
            $table->char('device_hash', 64)->nullable();
            $table->string('ip', 45)->nullable();
            $table->boolean('remember')->default(false);
            $table->json('amr')->nullable();
            $table->timestamp('authenticated_at')->nullable();
            $table->timestamp('last_mfa_at')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamp('expires_at');
            $table->timestamp('absolute_expires_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'revoked_at']);
            $table->index(['user_id', 'last_used_at']);
        });

        Schema::create(Tables::name('login_challenges'), function (Blueprint $table) {
            $table->id();
            Tables::userForeign($table);
            $table->char('token_hash', 64)->unique();
            $table->boolean('remember')->default(false);
            $table->unsignedTinyInteger('attempts')->default(0);
            $table->timestamp('expires_at');
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(Tables::name('login_challenges'));
        Schema::dropIfExists(Tables::name('auth_sessions'));
    }
};
