<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SecureAuth\Support\Tables;

/** Security history of each account. Written only through `SecureAuth\Audit\SecurityEvents`. */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create(Tables::name('security_events'), function (Blueprint $table) {
            $table->id();
            Tables::userForeign($table);
            $table->string('type', 50);
            Tables::userForeign($table, 'actor_id', nullable: true);
            $table->string('ip', 45)->nullable();
            $table->string('device')->nullable();
            $table->json('meta')->nullable();
            $table->timestamp('created_at')->useCurrent();

            $table->index(['user_id', 'created_at']);
            $table->index('created_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(Tables::name('security_events'));
    }
};
