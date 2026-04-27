import { APIError } from 'better-auth';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../src/queries/organization.queries', () => ({
	initializePersonalOrganization: vi.fn(),
	initializeDefaultOrganizationForFirstUser: vi.fn(),
	addUserToDefaultProjectIfExists: vi.fn(),
}));

vi.mock('../src/utils/logger', () => ({
	logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import {
	buildAfterCreateHook,
	buildBeforeCreateHook,
	enforceDomainAllowlist,
	isSocialProvider,
} from '../src/auth-hooks';
import * as orgQueries from '../src/queries/organization.queries';

const user = { id: 'user-123', email: 'someone@allowed.com' };

describe('isSocialProvider', () => {
	it.each([['google'], ['github'], ['microsoft']])('recognizes %s as a social provider', (id) => {
		expect(isSocialProvider(id)).toBe(true);
	});

	it('rejects email-password and unknown providers', () => {
		expect(isSocialProvider('credential')).toBe(false);
		expect(isSocialProvider(undefined)).toBe(false);
		expect(isSocialProvider('made-up')).toBe(false);
	});
});

describe('enforceDomainAllowlist', () => {
	it('allows Microsoft sign-up when the email domain is in the allowlist', () => {
		expect(() =>
			enforceDomainAllowlist(user, { params: { id: 'microsoft' } }, {
				googleAuthDomains: undefined,
				microsoftAuthDomains: 'allowed.com',
			}),
		).not.toThrow();
	});

	it('blocks Microsoft sign-up when the email domain is not in the allowlist', () => {
		expect(() =>
			enforceDomainAllowlist(
				{ id: 'u', email: 'attacker@evil.com' },
				{ params: { id: 'microsoft' } },
				{ googleAuthDomains: undefined, microsoftAuthDomains: 'allowed.com' },
			),
		).toThrow(APIError);
	});

	it('blocks Google sign-up when the email domain is not in the allowlist', () => {
		expect(() =>
			enforceDomainAllowlist(
				{ id: 'u', email: 'attacker@evil.com' },
				{ params: { id: 'google' } },
				{ googleAuthDomains: 'allowed.com', microsoftAuthDomains: undefined },
			),
		).toThrow(APIError);
	});

	it('does not apply the Microsoft allowlist to Google sign-ups (regression)', () => {
		expect(() =>
			enforceDomainAllowlist(
				{ id: 'u', email: 'someone@google-domain.com' },
				{ params: { id: 'google' } },
				{ googleAuthDomains: undefined, microsoftAuthDomains: 'only-microsoft.com' },
			),
		).not.toThrow();
	});

	it('does not apply allowlists to GitHub sign-ups', () => {
		expect(() =>
			enforceDomainAllowlist(user, { params: { id: 'github' } }, {
				googleAuthDomains: 'other.com',
				microsoftAuthDomains: 'other.com',
			}),
		).not.toThrow();
	});

	it('does not apply allowlists to email-password sign-ups', () => {
		expect(() =>
			enforceDomainAllowlist(user, undefined, {
				googleAuthDomains: 'other.com',
				microsoftAuthDomains: 'other.com',
			}),
		).not.toThrow();
	});
});

describe('buildBeforeCreateHook', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it('returns true on allowed domain', async () => {
		const before = buildBeforeCreateHook({
			googleAuthDomains: undefined,
			microsoftAuthDomains: 'allowed.com',
		});
		await expect(before(user, { params: { id: 'microsoft' } })).resolves.toBe(true);
	});

	it('throws on blocked domain', async () => {
		const before = buildBeforeCreateHook({
			googleAuthDomains: undefined,
			microsoftAuthDomains: 'allowed.com',
		});
		await expect(
			before({ id: 'u', email: 'someone@blocked.com' }, { params: { id: 'microsoft' } }),
		).rejects.toThrow(APIError);
	});
});

describe('buildAfterCreateHook', () => {
	beforeEach(() => {
		vi.clearAllMocks();
	});

	it('in self-hosted mode with a social provider, seeds the default org and project', async () => {
		const after = buildAfterCreateHook({ isCloud: false });
		await after(user, { params: { id: 'microsoft' } });

		expect(orgQueries.initializeDefaultOrganizationForFirstUser).toHaveBeenCalledWith('user-123');
		expect(orgQueries.addUserToDefaultProjectIfExists).toHaveBeenCalledWith('user-123');
		expect(orgQueries.initializePersonalOrganization).not.toHaveBeenCalled();
	});

	it('in self-hosted mode with email-password, seeds the default org but not the project', async () => {
		const after = buildAfterCreateHook({ isCloud: false });
		await after(user, undefined);

		expect(orgQueries.initializeDefaultOrganizationForFirstUser).toHaveBeenCalledWith('user-123');
		expect(orgQueries.addUserToDefaultProjectIfExists).not.toHaveBeenCalled();
		expect(orgQueries.initializePersonalOrganization).not.toHaveBeenCalled();
	});

	it('in cloud mode, initializes a personal organization and skips the default-org path', async () => {
		const after = buildAfterCreateHook({ isCloud: true });
		await after(user, { params: { id: 'microsoft' } });

		expect(orgQueries.initializePersonalOrganization).toHaveBeenCalledWith('user-123');
		expect(orgQueries.initializeDefaultOrganizationForFirstUser).not.toHaveBeenCalled();
		expect(orgQueries.addUserToDefaultProjectIfExists).not.toHaveBeenCalled();
	});

	it('handles a null context (better-auth may pass null) without throwing', async () => {
		const after = buildAfterCreateHook({ isCloud: false });
		await expect(after(user, null)).resolves.not.toThrow();
	});
});
