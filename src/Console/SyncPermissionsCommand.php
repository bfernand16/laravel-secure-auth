<?php

namespace SecureAuth\Console;

use Illuminate\Console\Command;
use SecureAuth\Permissions\PermissionCatalogSync;

class SyncPermissionsCommand extends Command
{
    protected $signature = 'secure-auth:permissions-sync';

    protected $description = 'Apply the permission catalog (config/secure-auth-permissions.php) idempotently, never removing permissions or grants';

    public function handle(PermissionCatalogSync $sync): int
    {
        $stats = $sync->run();

        $this->info(sprintf(
            'Permissions synced: %d new permissions, %d new roles, %d grants added.',
            $stats['permissions_created'],
            $stats['roles_created'],
            $stats['grants_added'],
        ));

        return self::SUCCESS;
    }
}
