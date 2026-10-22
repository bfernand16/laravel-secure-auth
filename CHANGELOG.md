# Changelog

Todas las versiones siguen [SemVer](https://semver.org/lang/es/). Los dos paquetes del repositorio (Composer y pnpm)
comparten número de versión y etiqueta git (`vX.Y.Z`).

## [0.2.0] - Sin publicar

### Cliente (`@bfernand16/secure-auth`)

- `logout()` devuelve `{ revoked }`: `false` cuando el servidor no pudo enterarse (sin conexión) y la cookie sigue viva
  hasta caducar. La sesión local se cierra siempre.
- `getFreshAccessToken()` devuelve el access token renovado antes si está a punto de caducar, para URLs y sockets que no
  pasan por `fetch`. Sin sesión devuelve `null`.

## [0.1.1] - Sin publicar

- El inicio de sesión vuelve a calcular el hash de la contraseña cuando los parámetros del algoritmo han cambiado
  (por ejemplo, de bcrypt a Argon2id), solo tras una contraseña correcta y una cuenta que puede entrar.

## [0.1.0] - Sin publicar

Primera versión, extraída de la autenticación de Liga Fantasy.

### Backend (`bfernand16/laravel-secure-auth`)

- Access token JWT HS256 de vida corta (10 minutos por defecto) con `sub`, `sid`, `pv`, `amr` y `auth_time`; sin email
  ni nombre. Guard `secure-auth` que rechaza tokens de sesiones revocadas o con la versión de permisos obsoleta.
- Sesión renovable con cookie `selector.secreto` HttpOnly, Secure, SameSite=Strict y ruta `/<prefijo>/auth`; solo se
  guardan huellas; rotación en cada renovación con margen de reutilización y revocación de la familia si se reutiliza;
  caducidad deslizante y absoluta con «recordarme»; comprobación de `Origin` y `X-Requested-With`.
- Login con límites por cuenta e IP, mensaje genérico y segundo paso TOTP con reto de un solo uso de 5 minutos.
- TOTP: alta con secreto cifrado, QR SVG generado en el servidor y clave manual; confirmación con el primer código;
  protección contra repetición y ventana de ±1 intervalo; 10 códigos de recuperación con huella; desactivar.
  Periodo de gracia con `users.two_factor_required_at`.
- Step-up para acciones sensibles: middleware `secure-auth.recent-mfa:<minutos>` y `POST /me/step-up`.
- Sesiones: listar, cerrar una, cerrar las demás; cambiar la contraseña (o el evento `PasswordReset`) las cierra todas.
- Historial de seguridad con meta en lista blanca y comando `secure-auth:prune`.
- Roles y permisos: catálogo publicable `<tipo>_<entidad>` con entidades anidadas, `admin_only` y herencia;
  `secure-auth:permissions-sync` idempotente; caché con versión por usuario; middleware `permission:<nombre>`;
  trait `HasSecureAuth`; `GET /me` con reglas CASL; contrato `PermissionResolver`.

### Frontend (`@bfernand16/secure-auth`)

- `createAuthClient`: token solo en memoria, renovación única compartida, reintento tras 401, login con segundo paso,
  logout, step-up, sincronización entre pestañas y `bootstrap()` para comprobar la sesión antes de pintar la interfaz.
- `defineRulesFor`, `AuthProvider`, `AbilityProvider`, `useAbility`, `useAuth`, `Can` y `RequirePermission`.
