import { describe, expect, it } from 'vitest';

import { isEmailDomainAllowed } from '../src/utils/utils';

describe('isEmailDomainAllowed', () => {
	it('allows any email when no allowlist is configured', () => {
		expect(isEmailDomainAllowed('user@anything.com', undefined)).toBe(true);
		expect(isEmailDomainAllowed('user@anything.com', '')).toBe(true);
	});

	it('allows an email whose domain is in the allowlist', () => {
		expect(isEmailDomainAllowed('user@allowed.com', 'allowed.com')).toBe(true);
	});

	it('rejects an email whose domain is not in the allowlist', () => {
		expect(isEmailDomainAllowed('user@blocked.com', 'allowed.com')).toBe(false);
	});

	it('matches case-insensitively', () => {
		expect(isEmailDomainAllowed('User@Allowed.COM', 'allowed.com')).toBe(true);
		expect(isEmailDomainAllowed('user@allowed.com', 'ALLOWED.COM')).toBe(true);
	});

	it('supports multiple comma-separated domains', () => {
		expect(isEmailDomainAllowed('user@second.com', 'first.com,second.com,third.com')).toBe(true);
		expect(isEmailDomainAllowed('user@fourth.com', 'first.com,second.com,third.com')).toBe(false);
	});

	it('tolerates whitespace around comma-separated entries', () => {
		expect(isEmailDomainAllowed('user@second.com', ' first.com , second.com , third.com ')).toBe(true);
	});

	it('rejects malformed emails with no domain part', () => {
		expect(isEmailDomainAllowed('not-an-email', 'allowed.com')).toBe(false);
	});

	it('does not perform substring or wildcard matching', () => {
		// Defense against an attacker registering a similar-looking domain.
		expect(isEmailDomainAllowed('user@allowed.com.evil.tld', 'allowed.com')).toBe(false);
		expect(isEmailDomainAllowed('user@notallowed.com', 'allowed.com')).toBe(false);
	});
});
