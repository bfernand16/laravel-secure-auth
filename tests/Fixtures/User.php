<?php

namespace SecureAuth\Tests\Fixtures;

use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Foundation\Auth\User as Authenticatable;
use SecureAuth\Concerns\HasSecureAuth;

class User extends Authenticatable implements MustVerifyEmail
{
    use HasSecureAuth;
    use \Illuminate\Auth\MustVerifyEmail;

    protected $guarded = [];

    protected $hidden = ['password'];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'two_factor_required_at' => 'datetime',
            'blocked_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    public function secureAuthIsBlocked(): bool
    {
        return $this->blocked_at !== null;
    }

    public function secureAuthProfile(): array
    {
        return ['id' => $this->id, 'email' => $this->email, 'name' => $this->name];
    }
}
