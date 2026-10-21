<?php

namespace SecureAuth\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Database\Schema\ColumnDefinition;

/** Table names and the host's user key, read from the `secure-auth` config so migrations and models agree. */
final class Tables
{
    public static function name(string $key): string
    {
        return (string) config('secure-auth.tables.'.$key, $key);
    }

    public static function users(): string
    {
        return self::userModel()->getTable();
    }

    /** Adds a foreign key column to the host's users table, matching its key type (`int`, `uuid` or `ulid`). */
    public static function userForeign(Blueprint $table, string $column = 'user_id', bool $nullable = false): ColumnDefinition
    {
        $definition = match (config('secure-auth.user_key_type', 'int')) {
            'uuid' => $table->foreignUuid($column),
            'ulid' => $table->foreignUlid($column),
            default => $table->foreignId($column),
        };

        if ($nullable) {
            $definition->nullable();
        }

        $definition->constrained(self::users(), self::userModel()->getKeyName());

        return $nullable ? $definition->nullOnDelete() : $definition->cascadeOnDelete();
    }

    private static function userModel(): Model
    {
        $class = (string) config('secure-auth.user_model');

        return new $class;
    }
}
