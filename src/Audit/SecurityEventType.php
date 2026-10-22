<?php

namespace SecureAuth\Audit;

/** Types the package records. Hosts may record their own types (any string up to 50 characters). */
final class SecurityEventType
{
    public const LOGIN = 'login';

    public const LOGIN_FAILED = 'login_failed';

    public const LOGOUT = 'logout';

    public const PASSWORD_CHANGED = 'password_changed';

    public const TWO_FACTOR_ENABLED = 'two_factor_enabled';

    public const TWO_FACTOR_DISABLED = 'two_factor_disabled';

    public const RECOVERY_CODES_REGENERATED = 'recovery_codes_regenerated';

    public const STEP_UP = 'step_up';

    public const STEP_UP_FAILED = 'step_up_failed';

    public const SESSION_REVOKED = 'session_revoked';

    public const SESSIONS_REVOKED_ALL = 'sessions_revoked_all';

    public const SESSION_REUSE_DETECTED = 'session_reuse_detected';
}
