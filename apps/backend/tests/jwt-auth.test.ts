import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { __reloadEnvForTesting } from '../src/env';
import { extractIdentity } from '../src/services/jwt-auth.service';
import { hasAnyRole, parseGroup, resolveGroupMemberships } from '../src/services/jwt-group.service';

// ─── extractIdentity ────────────────────────────────────────────────

describe('extractIdentity', () => {
	beforeEach(() => {
		delete process.env.JWT_CLAIM_EMAIL;
		delete process.env.JWT_CLAIM_NAME;
		delete process.env.JWT_GROUP_CLAIM;
		__reloadEnvForTesting();
	});

	afterEach(() => {
		delete process.env.JWT_CLAIM_EMAIL;
		delete process.env.JWT_CLAIM_NAME;
		delete process.env.JWT_GROUP_CLAIM;
		__reloadEnvForTesting();
	});

	it('extracts email from default "sub" claim', () => {
		const identity = extractIdentity({ sub: 'alice@example.com', displayName: 'Alice' });
		expect(identity.email).toBe('alice@example.com');
		expect(identity.name).toBe('Alice');
	});

	it('extracts groups from default "groups" claim', () => {
		const identity = extractIdentity({
			sub: 'alice@example.com',
			groups: ['GROUP-A', 'GROUP-B'],
		});
		expect(identity.groups).toEqual(['GROUP-A', 'GROUP-B']);
	});

	it('uses email prefix as name when displayName is missing', () => {
		const identity = extractIdentity({ sub: 'bob@example.com' });
		expect(identity.name).toBe('bob');
	});

	it('returns empty groups when claim is missing', () => {
		const identity = extractIdentity({ sub: 'alice@example.com' });
		expect(identity.groups).toEqual([]);
	});

	it('filters non-string values from groups array', () => {
		const identity = extractIdentity({
			sub: 'alice@example.com',
			groups: ['VALID', 123, null, 'ALSO-VALID'],
		});
		expect(identity.groups).toEqual(['VALID', 'ALSO-VALID']);
	});

	it('throws when email claim is missing', () => {
		expect(() => extractIdentity({})).toThrow("JWT claim 'sub' is missing or not a valid email");
	});

	it('throws when email claim is not a valid email', () => {
		expect(() => extractIdentity({ sub: 'not-an-email' })).toThrow(
			"JWT claim 'sub' is missing or not a valid email",
		);
	});

	it('lowercases the email', () => {
		const identity = extractIdentity({ sub: 'Alice@Example.COM' });
		expect(identity.email).toBe('alice@example.com');
	});

	it('respects custom claim names', () => {
		process.env.JWT_CLAIM_EMAIL = 'email';
		process.env.JWT_CLAIM_NAME = 'name';
		process.env.JWT_GROUP_CLAIM = 'roles';
		__reloadEnvForTesting();

		const identity = extractIdentity({
			email: 'custom@example.com',
			name: 'Custom User',
			roles: ['ROLE-A'],
		});
		expect(identity.email).toBe('custom@example.com');
		expect(identity.name).toBe('Custom User');
		expect(identity.groups).toEqual(['ROLE-A']);
	});
});

// ─── parseGroup ─────────────────────────────────────────────────────

describe('parseGroup', () => {
	beforeEach(() => {
		process.env.JWT_GROUP_PREFIX = 'ACME-CORP';
		process.env.JWT_GROUP_SUFFIX = 'PROD';
		delete process.env.JWT_GROUP_ROLE_ADMIN;
		delete process.env.JWT_GROUP_ROLE_USER;
		delete process.env.JWT_GROUP_ROLE_VIEWER;
		__reloadEnvForTesting();
	});

	afterEach(() => {
		delete process.env.JWT_GROUP_PREFIX;
		delete process.env.JWT_GROUP_SUFFIX;
		delete process.env.JWT_GROUP_ROLE_ADMIN;
		delete process.env.JWT_GROUP_ROLE_USER;
		delete process.env.JWT_GROUP_ROLE_VIEWER;
		__reloadEnvForTesting();
	});

	it('parses a project admin group', () => {
		const result = parseGroup('ACME-CORP-PROJECT-1-ADMINS-PROD');
		expect(result).toEqual({ projectSlug: 'PROJECT-1', role: 'admin' });
	});

	it('parses a project user group', () => {
		const result = parseGroup('ACME-CORP-PROJECT-1-USERS-PROD');
		expect(result).toEqual({ projectSlug: 'PROJECT-1', role: 'user' });
	});

	it('parses a project viewer group', () => {
		const result = parseGroup('ACME-CORP-PROJECT-2-VIEWERS-PROD');
		expect(result).toEqual({ projectSlug: 'PROJECT-2', role: 'viewer' });
	});

	it('parses an org-level admin group', () => {
		const result = parseGroup('ACME-CORP-ADMINS-PROD');
		expect(result).toEqual({ projectSlug: null, role: 'admin' });
	});

	it('parses an org-level user group', () => {
		const result = parseGroup('ACME-CORP-USERS-PROD');
		expect(result).toEqual({ projectSlug: null, role: 'user' });
	});

	it('parses an org-level viewer group', () => {
		const result = parseGroup('ACME-CORP-VIEWERS-PROD');
		expect(result).toEqual({ projectSlug: null, role: 'viewer' });
	});

	it('is case-insensitive', () => {
		const result = parseGroup('acme-corp-my-project-admins-prod');
		expect(result).toEqual({ projectSlug: 'MY-PROJECT', role: 'admin' });
	});

	it('returns null for unrecognized prefix', () => {
		const result = parseGroup('WRONG-PREFIX-PROJECT-1-ADMINS-PROD');
		expect(result).toBeNull();
	});

	it('returns null for unrecognized suffix', () => {
		const result = parseGroup('ACME-CORP-PROJECT-1-ADMINS-WRONG');
		expect(result).toBeNull();
	});

	it('returns null when no role keyword matches', () => {
		const result = parseGroup('ACME-CORP-PROJECT-1-UNKNOWN-PROD');
		expect(result).toBeNull();
	});

	it('returns null for empty middle segment', () => {
		const result = parseGroup('ACME-CORP-PROD');
		expect(result).toBeNull();
	});

	it('handles multi-segment project slugs', () => {
		const result = parseGroup('ACME-CORP-MY-LONG-PROJECT-NAME-ADMINS-PROD');
		expect(result).toEqual({ projectSlug: 'MY-LONG-PROJECT-NAME', role: 'admin' });
	});

	it('works with custom role keywords', () => {
		process.env.JWT_GROUP_ROLE_ADMIN = 'SUPERUSERS';
		process.env.JWT_GROUP_ROLE_USER = 'EDITORS';
		__reloadEnvForTesting();

		expect(parseGroup('ACME-CORP-PROJECT-1-SUPERUSERS-PROD')).toEqual({
			projectSlug: 'PROJECT-1',
			role: 'admin',
		});
		expect(parseGroup('ACME-CORP-EDITORS-PROD')).toEqual({
			projectSlug: null,
			role: 'user',
		});
	});

	it('works without prefix and suffix', () => {
		delete process.env.JWT_GROUP_PREFIX;
		delete process.env.JWT_GROUP_SUFFIX;
		__reloadEnvForTesting();

		expect(parseGroup('MY-PROJECT-ADMINS')).toEqual({ projectSlug: 'MY-PROJECT', role: 'admin' });
		expect(parseGroup('ADMINS')).toEqual({ projectSlug: null, role: 'admin' });
	});
});

// ─── resolveGroupMemberships ────────────────────────────────────────

describe('resolveGroupMemberships', () => {
	beforeEach(() => {
		process.env.JWT_GROUP_PREFIX = 'ACME-CORP';
		process.env.JWT_GROUP_SUFFIX = 'PROD';
		delete process.env.JWT_GROUP_ROLE_ADMIN;
		delete process.env.JWT_GROUP_ROLE_USER;
		delete process.env.JWT_GROUP_ROLE_VIEWER;
		__reloadEnvForTesting();
	});

	afterEach(() => {
		delete process.env.JWT_GROUP_PREFIX;
		delete process.env.JWT_GROUP_SUFFIX;
		delete process.env.JWT_GROUP_ROLE_ADMIN;
		delete process.env.JWT_GROUP_ROLE_USER;
		delete process.env.JWT_GROUP_ROLE_VIEWER;
		__reloadEnvForTesting();
	});

	it('resolves org-level and project-level roles', () => {
		const result = resolveGroupMemberships(['ACME-CORP-ADMINS-PROD', 'ACME-CORP-PROJECT-1-USERS-PROD']);
		expect(result.orgRole).toBe('admin');
		expect(result.projectRoles.get('PROJECT-1')).toBe('user');
	});

	it('picks the highest-privilege org role', () => {
		const result = resolveGroupMemberships(['ACME-CORP-VIEWERS-PROD', 'ACME-CORP-ADMINS-PROD']);
		expect(result.orgRole).toBe('admin');
	});

	it('picks the highest-privilege project role', () => {
		const result = resolveGroupMemberships(['ACME-CORP-PROJECT-1-VIEWERS-PROD', 'ACME-CORP-PROJECT-1-ADMINS-PROD']);
		expect(result.projectRoles.get('PROJECT-1')).toBe('admin');
	});

	it('skips unrecognized groups', () => {
		const result = resolveGroupMemberships(['UNRELATED-GROUP', 'ACME-CORP-PROJECT-1-ADMINS-PROD']);
		expect(result.orgRole).toBeNull();
		expect(result.projectRoles.size).toBe(1);
	});

	it('returns empty when no groups match', () => {
		const result = resolveGroupMemberships(['RANDOM-GROUP', 'ANOTHER-GROUP']);
		expect(result.orgRole).toBeNull();
		expect(result.projectRoles.size).toBe(0);
	});
});

// ─── hasAnyRole ─────────────────────────────────────────────────────

describe('hasAnyRole', () => {
	it('returns true when org role is set', () => {
		expect(hasAnyRole({ orgRole: 'admin', projectRoles: new Map() })).toBe(true);
	});

	it('returns true when project roles exist', () => {
		const projectRoles = new Map([['PROJECT-1', 'user' as const]]);
		expect(hasAnyRole({ orgRole: null, projectRoles })).toBe(true);
	});

	it('returns false when no roles', () => {
		expect(hasAnyRole({ orgRole: null, projectRoles: new Map() })).toBe(false);
	});
});
