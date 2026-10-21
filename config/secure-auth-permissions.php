<?php

/*
|--------------------------------------------------------------------------
| Permission catalog
|--------------------------------------------------------------------------
|
| Single source of the application's permissions. `php artisan secure-auth:permissions-sync` applies it idempotently: it
| creates what is missing and only ever adds grants. It never deletes permissions nor removes permissions already given to a
| role, so changes made from an admin screen survive.
|
| Naming:
|  - A permission is `<type>_<entity>`, e.g. `edit_admin-users`.
|  - Entities are kebab-case and may nest; a child's full name is `<parent>-<child>` (`admin` > `users` = `admin-users`).
|  - Each entity lists in `types` only the types that make sense (default: `default_types`).
|  - Labels are plain keys (`label`): the host application translates them.
*/

return [

    'types' => ['create', 'view', 'edit', 'delete', 'execute'],

    'default_types' => ['create', 'view', 'edit', 'delete'],

    'entities' => [
        'admin' => [
            'label' => 'permissions.entities.admin',
            'types' => ['view'],
            'children' => [
                'users' => ['label' => 'permissions.entities.admin_users', 'types' => ['create', 'view', 'edit', 'delete']],
                'roles' => ['label' => 'permissions.entities.admin_roles', 'types' => ['create', 'view', 'edit', 'delete']],
                'security-events' => ['label' => 'permissions.entities.admin_security_events', 'types' => ['view']],
            ],
        ],
    ],

    /*
    | Roles created by the sync. Values are label keys for the host to translate.
    */
    'roles' => [
        'admin' => 'roles.admin',
        'user' => 'roles.user',
    ],

    /*
    | The role that receives every permission, including the `admin_only` ones.
    */
    'admin_role' => 'admin',

    /*
    | Permissions no role receives through `*` except the admin role (for example the ones that touch money).
    */
    'admin_only' => [],

    /*
    | A role inherits (always additively) the permissions of other roles.
    */
    'inherits' => [],

    /*
    | Permissions each role receives on sync. Only added, never removed. `*` = every permission of the catalog.
    */
    'grants' => [
        'admin' => ['*'],
        'user' => [],
    ],

];
