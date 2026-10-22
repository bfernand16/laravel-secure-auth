<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SecureAuth\Support\Tables;

/** Second-factor methods (TOTP today; the secret is encrypted at rest) and the hashed single-use recovery codes. */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create(Tables::name('two_factor_methods'), function (Blueprint $table) {
            $table->id();
            Tables::userForeign($table);
            $table->string('type', 30);
            $table->text('secret')->nullable();
            $table->timestamp('confirmed_at')->nullable();
            $table->unsignedBigInteger('last_used_timestep')->nullable();
            $table->timestamp('last_used_at')->nullable();
            $table->timestamps();

            $table->unique(['user_id', 'type']);
        });

        Schema::create(Tables::name('recovery_codes'), function (Blueprint $table) {
            $table->id();
            Tables::userForeign($table);
            $table->char('code_hash', 64);
            $table->timestamp('used_at')->nullable();
            $table->timestamps();

            $table->index(['user_id', 'code_hash']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(Tables::name('recovery_codes'));
        Schema::dropIfExists(Tables::name('two_factor_methods'));
    }
};
