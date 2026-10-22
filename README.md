# laravel-secure-auth

Autenticación para APIs Laravel con un frontend React en el mismo dominio, extraída de Liga Fantasy:

- **Access token JWT de vida corta** (10 minutos) que el navegador guarda solo en memoria.
- **Cookie de renovación** opaca, HttpOnly y rotatoria, con detección de robo por reutilización.
- **Verificación en dos pasos (TOTP)** con códigos de recuperación y periodo de gracia para hacerla obligatoria.
- **Step-up** (volver a confirmar la identidad) para acciones sensibles.
- **Sesiones** visibles y revocables, **historial de seguridad** y **roles y permisos** con reglas CASL para la interfaz.

El repositorio contiene dos paquetes con la misma versión:

| Paquete | Gestor | Código |
| --- | --- | --- |
| `bfernand16/laravel-secure-auth` | Composer | `src/` (namespace `SecureAuth\`) |
| `@bfernand16/secure-auth` | pnpm | `js/src` (compilado en `js/dist`, incluido en git) |

Requisitos: PHP 8.3 o superior, Laravel 13, React 18 o 19 y `@casl/ability` 6 o 7.

Licencia: propietaria (ver `LICENSE`). El repositorio es privado.

---

## Instalación en una aplicación

### 1. Backend (Composer)

El repositorio es privado, así que Composer lo lee como repositorio `vcs` con un token de GitHub.

En el `composer.json` de la aplicación:

```json
{
    "repositories": [
        { "type": "vcs", "url": "https://github.com/bfernand16/laravel-secure-auth" }
    ],
    "require": {
        "bfernand16/laravel-secure-auth": "^0.1"
    }
}
```

Token: crea en GitHub un **fine-grained personal access token** con acceso **solo a este repositorio** y el permiso
**Contents: Read-only** (nada más). Dáselo a Composer por variable de entorno, nunca en el `composer.json`:

```bash
export COMPOSER_AUTH='{"github-oauth": {"github.com": "github_pat_..."}}'
composer update bfernand16/laravel-secure-auth
```

En CI o en el servidor, guarda `COMPOSER_AUTH` como secreto del entorno. El paquete se registra solo
(auto-discovery de `SecureAuth\SecureAuthServiceProvider`).

### 2. Publicar configuración y migraciones

```bash
php artisan vendor:publish --tag=secure-auth-config          # config/secure-auth.php
php artisan vendor:publish --tag=secure-auth-permissions     # config/secure-auth-permissions.php (catálogo)
php artisan vendor:publish --tag=secure-auth-migrations      # tablas nuevas
php artisan vendor:publish --tag=secure-auth-users-migration # columna two_factor_required_at en users
php artisan migrate
php artisan secure-auth:permissions-sync
```

Tablas que crea el paquete (todas nuevas; el nombre de cada una se puede cambiar en `secure-auth.tables`): `roles`,
`permissions`, `role_permission`, `user_role`, `auth_sessions`, `login_challenges`, `two_factor_methods`,
`recovery_codes` y `security_events`.

Si la tabla `users` usa UUID o ULID como clave, pon `'user_key_type' => 'uuid'` (o `'ulid'`) en `config/secure-auth.php`
**antes** de migrar.

### 3. Columnas de `users`

El paquete solo da por hecho que `users` tiene `id`, `email` (o el campo de `login_field`) y `password`. Necesita
**una** columna más, que añade la migración publicada con `secure-auth-users-migration`:

| Columna | Tipo | Para qué |
| --- | --- | --- |
| `two_factor_required_at` | `timestamp`, nullable | Desde ese momento, una cuenta sin TOTP solo puede usar las rutas de configurar el 2FA. `null` = 2FA opcional. |

Añade también el cast `'two_factor_required_at' => 'datetime'` en el modelo.

### 4. Modelo de usuario

```php
use Illuminate\Foundation\Auth\User as Authenticatable;
use SecureAuth\Concerns\HasSecureAuth;

class User extends Authenticatable
{
    use HasSecureAuth;

    protected function casts(): array
    {
        return ['two_factor_required_at' => 'datetime', 'password' => 'hashed'];
    }

    // Opcional: impide iniciar sesión, renovar y usar tokens (cuenta suspendida, etc.).
    public function secureAuthIsBlocked(): bool
    {
        return $this->suspended_at !== null;
    }

    // Opcional: lo que devuelve GET /me en `user`. Por defecto, id y email. Nunca va en el token.
    public function secureAuthProfile(): array
    {
        return ['id' => $this->id, 'email' => $this->email, 'name' => $this->name];
    }
}
```

`HasSecureAuth` incluye `HasRoles`: `roles()`, `assignRole()`, `removeRole()`, `syncRoles()`, `hasRole()`,
`hasPermission()` y `permissionNames()`, además de las relaciones `authSessions()`, `twoFactorMethods()` y
`securityEvents()`. Si el modelo implementa `MustVerifyEmail`, una cuenta sin verificar no puede iniciar sesión
(`require_verified_email`).

### 5. Frontend (pnpm)

```bash
pnpm add github:bfernand16/laravel-secure-auth#v0.1.0
pnpm add @casl/ability react   # dependencias peer, si no las tienes
```

pnpm usa las credenciales de git de la máquina para el repositorio privado (en CI, un token de solo lectura como el de
Composer). El paquete no se compila al instalar: `js/dist` ya va en la etiqueta.

---

## Configuración (`config/secure-auth.php`)

| Clave | Por defecto | Qué hace |
| --- | --- | --- |
| `user_model` | `App\Models\User` | Modelo de usuario (con `HasSecureAuth`). |
| `user_key_type` | `int` | Tipo de `users.id` para las claves foráneas: `int`, `uuid`, `ulid`. |
| `guard` / `user_provider` | `secure-auth` / `users` | Guard que registra el paquete y provider de `config/auth.php` que usa. |
| `login_field` | `email` | Campo con el que se inicia sesión. |
| `routes.enabled` | `true` | Registrar las rutas del paquete. Con `false`, la aplicación usa los controladores en sus rutas. |
| `routes.prefix` | `api` | Prefijo de las rutas. La cookie queda en `/<prefijo>/auth`. |
| `routes.middleware` | `['api']` | Grupo de middleware de las rutas. |
| `routes.password_change` | `true` | Registrar `PUT /me/password`. |
| `access_token.ttl_minutes` | `10` | Vida del access token. |
| `access_token.secret` | `SECURE_AUTH_JWT_SECRET` | Clave HMAC (32 bytes como mínimo). Vacía: se deriva de `APP_KEY`. |
| `access_token.issuer` | `APP_URL` | Claim `iss`; un token de otro emisor no vale. |
| `session.cookie` | `secure_auth_session` | Nombre de la cookie de renovación. |
| `session.cookie_secure` | `true` | Atributo `Secure`. Ponlo a `false` solo en local con HTTP (`SECURE_AUTH_COOKIE_SECURE=false`). |
| `session.absolute_days` | 30 con «recordarme», 7 sin | Límite absoluto de la sesión. |
| `session.sliding_hours` | 168 / 24 | Caducidad por inactividad. |
| `session.reuse_grace_seconds` | `10` | Margen en el que el secreto anterior aún vale (recargas y pestañas simultáneas). |
| `allowed_origins` | `[]` | Orígenes que pueden llamar a las rutas con cookie. Vacío: `cors.allowed_origins` (nunca `*`). El propio host siempre vale. |
| `rate_limits.*` | | Peticiones por minuto: login por cuenta e IP y por IP, segundo paso por reto e IP, fallos de código por cuenta (15 min), refresh por sesión e IP, step-up. |
| `two_factor.issuer` | `APP_NAME` | Nombre que muestra la app de autenticación. |
| `two_factor.challenge_ttl_minutes` | `5` | Vida del reto del segundo paso. |
| `two_factor.recovery_codes` | `10` | Códigos de recuperación por usuario. |
| `two_factor.setup_routes` | `me`, `step-up`, `two-factor.*` | Rutas (por nombre) accesibles con el 2FA obligatorio pendiente. |
| `two_factor.allow_code_reuse` | `false` | Permite repetir un código TOTP. Solo vale en `local` y `testing` (E2E). |
| `recent_mfa_minutes` | `10` | Ventana por defecto de `secure-auth.recent-mfa`. |
| `security_events.retention_days` | `180` | Lo que conserva `secure-auth:prune`. |
| `security_events.meta_keys` | `[]` | Claves de `meta` extra que la aplicación puede guardar. Nunca secretos. |
| `permissions.cache_ttl_seconds` | `600` | Caché de permisos por usuario. |
| `permissions.short_middleware_alias` | `true` | Registrar el alias `permission` (además de `secure-auth.permission`). |
| `tables.*` | | Nombre de cada tabla. |

## Rutas

Con el prefijo por defecto `api`. Las de `/auth/*` usan la cookie y exigen `X-Requested-With: XMLHttpRequest` y un
`Origin` (o `Referer`) permitido. Las demás usan `Authorization: Bearer <token>` y el middleware `secure-auth`.

| Método y ruta | Nombre | Qué hace |
| --- | --- | --- |
| `POST /api/auth/login` | `secure-auth.login` | `email`, `password`, `remember`. Abre la sesión o devuelve `{two_factor: true, challenge}`. |
| `POST /api/auth/two-factor` | `secure-auth.login.two-factor` | `challenge`, `method` (`totp` o `recovery`), `code`. |
| `POST /api/auth/refresh` | `secure-auth.refresh` | Rota la cookie y devuelve un access token nuevo. 204 sin cookie. |
| `POST /api/auth/logout` | `secure-auth.logout` | Cierra la sesión de la cookie (o la del bearer) y borra la cookie. |
| `GET /api/me` | `secure-auth.me` | Perfil, reglas CASL (`permissions.can` / `cannot`), estado del 2FA y de la sesión. |
| `POST /api/me/step-up` | `secure-auth.step-up` | `current_password` y, con TOTP, `method` + `code`. Renueva `last_mfa_at`. |
| `PUT /api/me/password` | `secure-auth.password` | Cambia la contraseña, cierra todas las sesiones y abre una nueva aquí. Pide step-up reciente. |
| `GET /api/me/sessions` | `secure-auth.sessions.index` | Sesiones abiertas, con la actual marcada. |
| `DELETE /api/me/sessions` | `secure-auth.sessions.destroy-others` | Cierra todas las demás. |
| `DELETE /api/me/sessions/{id}` | `secure-auth.sessions.destroy` | Cierra una. |
| `GET /api/me/security-events` | `secure-auth.security-events` | Historial de seguridad propio, paginado. |
| `GET /api/me/two-factor` | `secure-auth.two-factor.show` | Estado del TOTP. |
| `POST /api/me/two-factor/totp` | `secure-auth.two-factor.start` | Empieza el alta: `secret`, `otpauth_url` y `qr_svg`. Pide step-up reciente. |
| `POST /api/me/two-factor/totp/confirm` | `secure-auth.two-factor.confirm` | `code`. Activa el TOTP y devuelve los 10 códigos de recuperación. |
| `POST /api/me/two-factor/recovery-codes` | `secure-auth.two-factor.recovery-codes` | Regenera los códigos (los anteriores dejan de valer). Pide step-up reciente. |
| `DELETE /api/me/two-factor/totp` | `secure-auth.two-factor.disable` | Desactiva el TOTP (no si la cuenta lo tiene obligatorio). Pide step-up reciente. |

Los errores llevan `message` (traducido, `secure-auth::messages`) y `reason`, un código estable para el cliente:
`invalid_credentials`, `account_blocked`, `email_unverified`, `token_missing`, `token_invalid`, `session_revoked`,
`permissions_stale`, `session_invalid`, `csrf_rejected`, `forbidden`, `mfa_required`, `two_factor_required`,
`two_factor_code_invalid` (con `attempts_remaining`), `two_factor_attempts_exhausted`, `two_factor_challenge_invalid`,
`two_factor_throttled`, `two_factor_already_enabled`, `two_factor_not_enabled` y `two_factor_mandatory`.

### Middleware para las rutas de la aplicación

```php
Route::middleware('secure-auth')->group(function () {
    Route::get('/reports', ReportController::class)->middleware('permission:view_reports');
    Route::post('/payouts', PayoutController::class)->middleware(['permission:execute_payouts', 'secure-auth.recent-mfa:5']);
});
```

- `secure-auth`: exige un access token válido, de una sesión viva y con los permisos al día, y fija el guard del paquete
  para la petición (`$request->user()`). Con el 2FA obligatorio vencido, solo deja pasar `two_factor.setup_routes`.
- `permission:<nombre>` (o `secure-auth.permission:<nombre>`): exige el permiso; `a|b` acepta cualquiera de los dos.
- `secure-auth.recent-mfa:<minutos>`: exige un login o step-up en los últimos minutos; si no, 403 `mfa_required` y el
  cliente pide la contraseña (y el código) con `POST /me/step-up` y reintenta.

## Roles y permisos

El catálogo vive en `config/secure-auth-permissions.php`. Un permiso es `<tipo>_<entidad>`; las entidades van en
kebab-case y se anidan (`admin` > `users` da `admin-users`, y los permisos `view_admin-users`, `edit_admin-users`...).
Cada entidad declara solo los tipos que tienen sentido. Las etiquetas son claves (`label`) que traduce la aplicación:
el paquete no tiene tablas de traducciones.

```php
'entities' => [
    'admin' => ['label' => 'permissions.admin', 'types' => ['view'], 'children' => [
        'users' => ['label' => 'permissions.admin_users', 'types' => ['create', 'view', 'edit', 'delete']],
        'billing' => ['types' => ['view', 'edit']],
    ]],
],
'roles' => ['admin' => 'roles.admin', 'staff' => 'roles.staff', 'user' => 'roles.user'],
'admin_role' => 'admin',                 // recibe todo, también lo de admin_only
'admin_only' => ['edit_admin-billing'],  // permisos de dinero: ningún otro rol los recibe con '*'
'inherits' => ['staff' => ['user']],     // staff suma siempre lo que tenga user
'grants' => ['admin' => ['*'], 'staff' => ['*'], 'user' => ['view_admin']],
```

`php artisan secure-auth:permissions-sync` aplica el catálogo de forma idempotente: crea lo que falta y solo **añade**
asignaciones. Nunca borra permisos ni quita los que un administrador haya dado a mano.

Cada token lleva `pv`, la versión de permisos del usuario. Cambiar sus roles (`assignRole`, `syncRoles`...) o los permisos
de un rol (`$role->grant()`, `$role->revoke()`, la sincronización) invalida sus tokens vivos: el siguiente uso responde
401 `permissions_stale`, el cliente renueva y recarga `/me`. Si modificas las tablas pivote directamente, llama a
`app(SecureAuth\Permissions\PermissionCache::class)->flush()`.

### Permisos de otra fuente

Los permisos salen del contrato `SecureAuth\Contracts\PermissionResolver` (`permissionsOf($user)` y `catalog()`). Por
defecto se usan las tablas del paquete; para usar otra fuente, enlaza tu implementación en un service provider:

```php
$this->app->singleton(PermissionResolver::class, MyPermissionResolver::class);
```

## Historial de seguridad

`SecureAuth\Audit\SecurityEvents::record($user, $type, $request, $meta, $actor)` es el único punto de escritura. Guarda
IP y navegador legible solo cuando el titular actúa sobre su cuenta (si actúa un administrador, `$actor`, no se copian sus
datos) y solo las claves de `meta` permitidas: nunca contraseñas, códigos, tokens ni correos. El paquete registra login,
fallos de login, logout, cambios de contraseña, alta y baja del 2FA, regeneración de códigos, step-up, cierres de
sesión y reutilización de cookie. La aplicación puede registrar sus propios tipos.

Programa la purga en `routes/console.php`:

```php
Schedule::command('secure-auth:prune')->daily();
```

El evento `SecureAuth\Events\SessionRevoked` (id de sesión, usuario y motivo) permite, por ejemplo, avisar en tiempo real.

---

## Frontend

### Comprobar la sesión antes de pintar nada

`bootstrap()` renueva con la cookie y carga `/me`. Espera a que termine antes de montar la aplicación y no habrá un
destello de la interfaz antes de redirigir al login.

```tsx
import { createRoot } from 'react-dom/client';
import { createAuthClient } from '@bfernand16/secure-auth';
import { AuthProvider } from '@bfernand16/secure-auth/react';

export const auth = createAuthClient({
  baseUrl: '/api',
  onSessionExpired: () => router.navigate({ to: '/login' }),
  onTwoFactorRequired: () => router.navigate({ to: '/account/security' }),
});

const root = createRoot(document.getElementById('root')!);

auth.bootstrap()
  .then(() => root.render(<AuthProvider client={auth}><App /></AuthProvider>))
  .catch(() => root.render(<ServerUnavailable />)); // sin red: no se muestra el login por error
```

Con TanStack Router, el estado ya está resuelto cuando corre el primer `beforeLoad`:

```ts
beforeLoad: ({ location }) => {
  if (auth.getState().status !== 'authenticated') {
    throw redirect({ to: '/login', search: { redirectTo: location.href } });
  }
},
```

### Login, segundo paso y logout

```ts
const result = await auth.login({ email, password, remember });

if (result.status === 'two_factor') {
  await auth.verifyTwoFactor({ challenge: result.challenge, method: 'totp', code });
}

const { revoked } = await auth.logout(); // revoked=false: sin conexión, la cookie vive hasta caducar

const token = await auth.getFreshAccessToken(); // renovado si está a punto de caducar; null sin sesión
```

Los fallos lanzan `AuthError` con `status`, `reason` y, en un código incorrecto, `attemptsRemaining`.

### Peticiones autenticadas

`auth.fetch(path, init)` añade el bearer, renueva antes de que caduque, comparte una sola renovación entre peticiones
simultáneas y reintenta una vez tras un 401. Si la cookie ya no vale, cierra la sesión y llama a `onSessionExpired`.
Para axios u otro cliente, usa `auth.getAccessToken()` en un interceptor y `auth.refresh()` al recibir un 401.

```ts
const response = await auth.fetch('reports');

if (response.status === 403 && (await response.clone().json()).reason === 'mfa_required') {
  await auth.stepUp({ password, method: 'totp', code });
}
```

### Permisos en la interfaz

```tsx
import { Can, RequirePermission, useAbility, useAuth } from '@bfernand16/secure-auth/react';

<Can I="edit" a="admin-users"><EditButton /></Can>

<RequirePermission I="view" a="admin" fallback={<Forbidden />} onDenied={() => navigate({ to: '/' })}>
  <AdminPanel />
</RequirePermission>

const ability = useAbility();     // ability.can('view', 'reports')
const { state, client } = useAuth();
```

`Can` acepta las props de `@casl/react` (`I`/`a`, `I`/`an`, `do`/`on`, `not`, `passThrough`, hijo función) pero lee la
ability del contexto de este paquete, así que no depende de la versión de `@casl/react` (ni de tenerla). Fuera de React,
`defineRulesFor(me.permissions)` construye la ability. Ocultar algo en la interfaz no protege nada: la comprobación de
verdad es el middleware `permission:` del servidor.

### Varias pestañas

Con `BroadcastChannel`, las pestañas comparten el access token en memoria: un login, una renovación o un logout en una
llega a las demás sin otra petición. Con Web Locks, solo una pestaña rota la cookie a la vez. Sin esas APIs todo sigue
funcionando, cada pestaña por su cuenta.

---

## Notas de seguridad

- **Por qué el token vive en memoria.** Un script inyectado (XSS) lee `localStorage` y `sessionStorage` sin esfuerzo y
  se lleva un token que sigue valiendo en otra máquina. En memoria, el token desaparece al cerrar la pestaña, vive 10
  minutos y no se puede leer desde otra página. La renovación va por una cookie que JavaScript no puede leer.
- **La cookie de renovación** es `HttpOnly` (no la lee JavaScript), `Secure` (solo HTTPS), `SameSite=Strict` (no viaja en
  peticiones desde otros sitios) y con `Path=/<prefijo>/auth` (no se envía al resto de la API). Guarda `selector.secreto`;
  en la base de datos solo está la huella SHA-256 del secreto. Cada renovación rota el secreto; si llega uno ya rotado
  fuera del margen, se revoca la sesión entera (alguien tenía una copia).
- **CSRF.** Las rutas con cookie exigen `X-Requested-With: XMLHttpRequest` (un formulario de otro sitio no puede enviarla)
  y un `Origin` permitido. Detrás de un proxy, configura `TrustProxies` para que el esquema y el host sean los reales.
- **Cookies cifradas.** Laravel cifra las cookies del grupo `web`. Las rutas del paquete van en `api`; si las mueves a
  `web`, excluye la cookie: `$middleware->encryptCookies(except: ['secure_auth_session'])`.
- **Revocación inmediata.** El guard comprueba en cada petición que la sesión del token (`sid`) sigue viva y que `pv`
  está al día: cerrar una sesión, cambiar la contraseña o los roles corta los tokens al momento.
- **Secretos.** El secreto TOTP se guarda cifrado con `APP_KEY`; los códigos de recuperación y los retos, solo como
  huella. El QR se genera en el servidor (SVG); el secreto nunca sale hacia un servicio externo. Si rotas `APP_KEY`, deja la
  anterior en `APP_PREVIOUS_KEYS`: así siguen valiendo los secretos TOTP y los códigos de recuperación. Sin
  `SECURE_AUTH_JWT_SECRET`, los access tokens vigentes dejan de valer y el cliente los renueva con la cookie.
- **Respuestas sin caché.** Las que llevan tokens, secretos o códigos van con `Cache-Control: no-store`.
- **Fotos, vídeos y otros medios.** Un `<img>` o `<video>` no envía el bearer. Servirlos con URLs firmadas y de vida
  corta (`URL::temporarySignedRoute`) es tarea de la aplicación; no pongas el access token en la URL.
- **Lo que no hace el paquete.** Registro de usuarios, verificación de email y recuperación de contraseña siguen siendo de
  la aplicación. Para que un reseteo cierre las sesiones, dispara el evento `PasswordReset` de Laravel (el broker de
  contraseñas lo hace) o llama a `SessionTokens::revokeAll($user)`.

---

## Desarrollo

```bash
composer install && pnpm install
vendor/bin/phpunit            # tests PHP (Testbench, SQLite en memoria)
vendor/bin/pint --test        # formato PHP
pnpm run check                # ESLint, TypeScript, Vitest y compilación de js/dist
```

Antes de etiquetar una versión: `pnpm run build`, confirmar que `js/dist` está en el commit, subir la versión de
`package.json`, anotar el `CHANGELOG.md` y crear la etiqueta `vX.Y.Z`.
