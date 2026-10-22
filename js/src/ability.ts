import { createMongoAbility, type RawRuleOf } from '@casl/ability';
import type { AppAbility, PermissionRules } from './types.js';

/**
 * Builds the CASL ability from the `can` / `cannot` lists of `GET /me`. Without rules, everything is denied.
 * Uses `createMongoAbility`, available in @casl/ability 6 and 7.
 */
export function defineRulesFor(permissions: PermissionRules | null | undefined): AppAbility {
  const rules: RawRuleOf<AppAbility>[] = [
    ...(permissions?.can ?? []).map(({ type, entity }) => ({ action: type, subject: entity })),
    ...(permissions?.cannot ?? []).map(({ type, entity }) => ({ action: type, subject: entity, inverted: true })),
  ];

  return createMongoAbility<AppAbility>(rules);
}
