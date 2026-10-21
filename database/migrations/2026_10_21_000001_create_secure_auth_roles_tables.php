<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use SecureAuth\Support\Tables;

/** Roles, permissions (`<type>_<entity>`, entity already flattened with its parents) and their assignments. */
return new class extends Migration
{
    public function up(): void
    {
        Schema::create(Tables::name('roles'), function (Blueprint $table) {
            $table->id();
            $table->string('name', 100)->unique();
            $table->string('label')->nullable();
            $table->timestamps();
        });

        Schema::create(Tables::name('permissions'), function (Blueprint $table) {
            $table->id();
            $table->string('name', 191)->unique();
            $table->string('type', 50);
            $table->string('entity', 150);
            $table->string('label')->nullable();
            $table->timestamps();

            $table->index(['entity', 'type']);
        });

        Schema::create(Tables::name('role_permission'), function (Blueprint $table) {
            $table->foreignId('role_id')->constrained(Tables::name('roles'))->cascadeOnDelete();
            $table->foreignId('permission_id')->constrained(Tables::name('permissions'))->cascadeOnDelete();
            $table->timestamps();

            $table->primary(['role_id', 'permission_id']);
        });

        Schema::create(Tables::name('user_role'), function (Blueprint $table) {
            Tables::userForeign($table);
            $table->foreignId('role_id')->constrained(Tables::name('roles'))->cascadeOnDelete();
            $table->timestamps();

            $table->primary(['user_id', 'role_id']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists(Tables::name('user_role'));
        Schema::dropIfExists(Tables::name('role_permission'));
        Schema::dropIfExists(Tables::name('permissions'));
        Schema::dropIfExists(Tables::name('roles'));
    }
};
