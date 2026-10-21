import { describe, expect, it } from 'vitest';
import { defineRulesFor } from '../src/ability';
import { decodeAccessToken } from '../src/jwt';
import { fakeJwt } from './kit';

describe('defineRulesFor', () => {
  it('allows what the server lists in can', () => {
    const ability = defineRulesFor({ can: [{ type: 'edit', entity: 'admin-users' }], cannot: [] });

    expect([ability.can('edit', 'admin-users'), ability.can('delete', 'admin-users')]).toEqual([true, false]);
  });

  it('denies what the server lists in cannot', () => {
    const ability = defineRulesFor({ can: [], cannot: [{ type: 'view', entity: 'admin' }] });

    expect(ability.cannot('view', 'admin')).toBe(true);
  });

  it('denies everything without rules', () => {
    expect(defineRulesFor(null).can('view', 'anything')).toBe(false);
  });
});

describe('decodeAccessToken', () => {
  it('reads the claims of the token', () => {
    expect(decodeAccessToken(fakeJwt('9', 10, 4))).toMatchObject({ sub: '9', sid: 4, amr: ['pwd'] });
  });

  it('returns null for something that is not a JWT', () => {
    expect([decodeAccessToken('nope'), decodeAccessToken('a.%%%.c')]).toEqual([null, null]);
  });
});
