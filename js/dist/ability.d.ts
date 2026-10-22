import type { AppAbility, PermissionRules } from './types.js';
/**
 * Builds the CASL ability from the `can` / `cannot` lists of `GET /me`. Without rules, everything is denied.
 * Uses `createMongoAbility`, available in @casl/ability 6 and 7.
 */
export declare function defineRulesFor(permissions: PermissionRules | null | undefined): AppAbility;
