import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { __reloadEnvForTesting } from '../src/env';

// ─── Mocks ──────────────────────────────────────────────────────────

const mockGetSession = vi.fn();
vi.mock('../src/auth', () => ({
	getAuth: vi.fn().mockResolvedValue({
		api: { getSession: (...args: unknown[]) => mockGetSession(...args) },
	}),
}));

const mockGetUser = vi.fn();
vi.mock('../src/queries/user.queries', () => ({
	getUser: (...args: unknown[]) => mockGetUser(...args),
}));

const mockGetFirstOrganization = vi.fn();
vi.mock('../src/queries/organization.queries', () => ({
	getFirstOrganization: () => mockGetFirstOrganization(),
}));

const mockVerifyAndDecode = vi.fn();
const mockExtractIdentity = vi.fn();
const mockIsJwtAuthEnabled = vi.fn();
vi.mock('../src/services/jwt-auth.service', () => ({
	verifyAndDecode: (...args: unknown[]) => mockVerifyAndDecode(...args),
	extractIdentity: (...args: unknown[]) => mockExtractIdentity(...args),
	isJwtAuthEnabled: () => mockIsJwtAuthEnabled(),
}));

const mockResolveGroupMemberships = vi.fn();
const mockHasAnyRole = vi.fn();
vi.mock('../src/services/jwt-group.service', () => ({
	resolveGroupMemberships: (...args: unknown[]) => mockResolveGroupMemberships(...args),
	hasAnyRole: (...args: unknown[]) => mockHasAnyRole(...args),
}));

const mockInsertExecute = vi.fn().mockResolvedValue([{ id: 'new-user-id', email: 'test@example.com', name: 'Test' }]);
const mockInsertReturning = vi.fn().mockReturnValue({ execute: mockInsertExecute });
const mockInsertValues = vi.fn().mockReturnValue({ returning: mockInsertReturning, execute: vi.fn() });
const mockInsert = vi.fn().mockReturnValue({ values: mockInsertValues });

const mockTxOrgMemberFindFirst = vi.fn();
const mockTxUpdateExecute = vi.fn();
const mockTxUpdateWhere = vi.fn().mockReturnValue({ execute: mockTxUpdateExecute });
const mockTxUpdateSet = vi.fn().mockReturnValue({ where: mockTxUpdateWhere });
const mockTxUpdate = vi.fn().mockReturnValue({ set: mockTxUpdateSet });
const mockTxInsertExecute = vi.fn();
const mockTxInsertValues = vi
	.fn()
	.mockReturnValue({ execute: mockTxInsertExecute, returning: vi.fn().mockReturnValue({ execute: vi.fn() }) });
const mockTxInsert = vi.fn().mockReturnValue({ values: mockTxInsertValues });
const mockTxDeleteExecute = vi.fn();
const mockTxDeleteWhere = vi.fn().mockReturnValue({ execute: mockTxDeleteExecute });
const mockTxDelete = vi.fn().mockReturnValue({ where: mockTxDeleteWhere });
const mockTxSelectExecute = vi.fn().mockResolvedValue([]);
const mockTxSelectWhere = vi.fn().mockReturnValue({ execute: mockTxSelectExecute });
const mockTxSelectFrom = vi.fn().mockReturnValue({ where: mockTxSelectWhere });
const mockTxSelect = vi.fn().mockReturnValue({ from: mockTxSelectFrom });

const mockTransaction = vi.fn().mockImplementation(async (fn: (tx: unknown) => Promise<void>) => {
	const tx = {
		query: {
			orgMember: { findFirst: mockTxOrgMemberFindFirst },
		},
		update: mockTxUpdate,
		insert: mockTxInsert,
		delete: mockTxDelete,
		select: mockTxSelect,
	};
	await fn(tx);
});

vi.mock('../src/db/db', () => ({
	db: {
		insert: (...args: unknown[]) => mockInsert(...args),
		transaction: (...args: unknown[]) => mockTransaction(...args),
	},
}));

vi.mock('../src/db/abstractSchema', () => ({
	default: {
		user: { id: 'user.id', email: 'user.email' },
		account: { id: 'account.id' },
		session: { id: 'session.id' },
		orgMember: { orgId: 'orgMember.orgId', userId: 'orgMember.userId' },
		project: { orgId: 'project.orgId' },
		projectMember: { userId: 'projectMember.userId', projectId: 'projectMember.projectId' },
	},
}));

vi.mock('drizzle-orm', () => ({
	and: (...args: unknown[]) => args,
	eq: (...args: unknown[]) => args,
}));

// ─── Import after mocks ─────────────────────────────────────────────

import { jwtAuthPreHandler } from '../src/middleware/jwt-auth';

// ─── Helpers ────────────────────────────────────────────────────────

function makeRequest(overrides: Partial<FastifyRequestLike> = {}): FastifyRequestLike {
	return {
		headers: { authorization: 'Bearer valid-jwt-token' },
		ip: '127.0.0.1',
		...overrides,
	};
}

interface FastifyRequestLike {
	headers: Record<string, string | undefined>;
	ip: string;
}

function makeReply() {
	const reply = {
		statusCode: 200,
		body: null as unknown,
		headers: {} as Record<string, string>,
		status: vi.fn().mockImplementation((code: number) => {
			reply.statusCode = code;
			return reply;
		}),
		send: vi.fn().mockImplementation((body: unknown) => {
			reply.body = body;
			return reply;
		}),
		header: vi.fn().mockImplementation((name: string, value: string) => {
			reply.headers[name] = value;
			return reply;
		}),
	};
	return reply;
}

function setupValidJwtFlow(overrides?: {
	email?: string;
	name?: string;
	groups?: string[];
	orgRole?: string | null;
	projectRoles?: Map<string, string>;
}) {
	const email = overrides?.email ?? 'alice@example.com';
	const name = overrides?.name ?? 'Alice';
	const groups = overrides?.groups ?? ['ACME-ADMINS'];

	mockIsJwtAuthEnabled.mockReturnValue(true);
	mockGetSession.mockResolvedValue(null);
	mockVerifyAndDecode.mockResolvedValue({ sub: email, displayName: name, groups });
	mockExtractIdentity.mockReturnValue({ email, name, groups });
	mockResolveGroupMemberships.mockReturnValue({
		orgRole: overrides && 'orgRole' in overrides ? overrides.orgRole : 'admin',
		projectRoles: overrides?.projectRoles ?? new Map(),
	});
	mockHasAnyRole.mockReturnValue(true);
	mockGetUser.mockResolvedValue({ id: 'user-123', email, name });
	mockGetFirstOrganization.mockResolvedValue({ id: 'org-1', name: 'Default Org', slug: 'default' });
	mockTxOrgMemberFindFirst.mockResolvedValue(null);
	mockTxSelectExecute.mockResolvedValue([]);
}

// ─── Tests ──────────────────────────────────────────────────────────

describe('jwtAuthPreHandler', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		delete process.env.JWT_AUTH_DOMAINS;
		delete process.env.MODE;
		__reloadEnvForTesting();
	});

	afterEach(() => {
		delete process.env.JWT_AUTH_DOMAINS;
		delete process.env.MODE;
		__reloadEnvForTesting();
	});

	it('skips when JWT auth is disabled', async () => {
		mockIsJwtAuthEnabled.mockReturnValue(false);
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(reply.status).not.toHaveBeenCalled();
		expect(mockVerifyAndDecode).not.toHaveBeenCalled();
	});

	it('skips when an existing session is present', async () => {
		mockIsJwtAuthEnabled.mockReturnValue(true);
		mockGetSession.mockResolvedValue({ user: { id: 'existing-user' } });
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(reply.status).not.toHaveBeenCalled();
		expect(mockVerifyAndDecode).not.toHaveBeenCalled();
	});

	it('returns 401 when Authorization header is missing', async () => {
		mockIsJwtAuthEnabled.mockReturnValue(true);
		mockGetSession.mockResolvedValue(null);
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest({ headers: {} }) as never, reply as never);

		expect(reply.status).toHaveBeenCalledWith(401);
		expect(reply.body).toEqual({ error: 'Missing authorization token' });
	});

	it('returns 401 when Authorization header is not Bearer', async () => {
		mockIsJwtAuthEnabled.mockReturnValue(true);
		mockGetSession.mockResolvedValue(null);
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest({ headers: { authorization: 'Basic abc' } }) as never, reply as never);

		expect(reply.status).toHaveBeenCalledWith(401);
		expect(reply.body).toEqual({ error: 'Missing authorization token' });
	});

	it('returns 403 when email domain is not allowed', async () => {
		process.env.JWT_AUTH_DOMAINS = 'allowed.com';
		__reloadEnvForTesting();
		setupValidJwtFlow({ email: 'alice@forbidden.com' });
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(reply.status).toHaveBeenCalledWith(403);
		expect(reply.body).toEqual({ error: 'Email domain not authorized' });
	});

	it('returns 403 when user has no recognized groups', async () => {
		setupValidJwtFlow();
		mockHasAnyRole.mockReturnValue(false);
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(reply.status).toHaveBeenCalledWith(403);
		expect(reply.body).toEqual({ error: 'No authorized group membership' });
	});

	it('returns 500 when no organization exists', async () => {
		setupValidJwtFlow();
		mockGetFirstOrganization.mockResolvedValue(null);
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(reply.status).toHaveBeenCalledWith(500);
		expect(reply.body).toEqual({ error: 'No organization configured' });
	});

	it('returns 401 when JWT verification fails', async () => {
		mockIsJwtAuthEnabled.mockReturnValue(true);
		mockGetSession.mockResolvedValue(null);
		mockVerifyAndDecode.mockRejectedValue(new Error('signature verification failed'));
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(reply.status).toHaveBeenCalledWith(401);
		expect(reply.body).toEqual({ error: 'signature verification failed' });
	});

	it('sets session cookie on successful authentication', async () => {
		setupValidJwtFlow();
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(reply.header).toHaveBeenCalledWith('Set-Cookie', expect.stringContaining('better-auth.session_token='));
		expect(reply.header).toHaveBeenCalledWith('Set-Cookie', expect.stringContaining('HttpOnly'));
		expect(reply.header).toHaveBeenCalledWith('Set-Cookie', expect.stringContaining('Path=/'));
	});

	it('includes Secure flag in cookie when MODE is prod', async () => {
		process.env.MODE = 'prod';
		__reloadEnvForTesting();
		setupValidJwtFlow();
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(reply.header).toHaveBeenCalledWith('Set-Cookie', expect.stringContaining('Secure'));
	});

	it('omits Secure flag in cookie when MODE is dev', async () => {
		process.env.MODE = 'dev';
		__reloadEnvForTesting();
		setupValidJwtFlow();
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		const cookie = reply.headers['Set-Cookie'];
		expect(cookie).not.toContain('Secure');
	});

	it('creates a new user when not found in DB', async () => {
		setupValidJwtFlow({ email: 'newuser@example.com', name: 'New User' });
		mockGetUser.mockResolvedValue(null);
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(mockInsert).toHaveBeenCalled();
		expect(reply.header).toHaveBeenCalledWith('Set-Cookie', expect.stringContaining('better-auth.session_token='));
	});

	it('reuses existing user when found in DB', async () => {
		setupValidJwtFlow();
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		// insert is called for session only (not user+account)
		// getUser returned a user, so no user insert should happen
		expect(mockGetUser).toHaveBeenCalledWith({ email: 'alice@example.com' });
	});

	it('calls syncMemberships with resolved roles', async () => {
		const projectRoles = new Map([['PROJECT-1', 'admin' as const]]);
		setupValidJwtFlow({ orgRole: 'user', projectRoles });
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(mockTransaction).toHaveBeenCalled();
	});

	it('inserts new org member when not existing', async () => {
		setupValidJwtFlow({ orgRole: 'admin' });
		mockTxOrgMemberFindFirst.mockResolvedValue(null);
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(mockTxInsert).toHaveBeenCalled();
	});

	it('updates org member role when different', async () => {
		setupValidJwtFlow({ orgRole: 'admin' });
		mockTxOrgMemberFindFirst.mockResolvedValue({ orgId: 'org-1', userId: 'user-123', role: 'viewer' });
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(mockTxUpdate).toHaveBeenCalled();
	});

	it('skips org member update when role is unchanged', async () => {
		setupValidJwtFlow({ orgRole: 'admin' });
		mockTxOrgMemberFindFirst.mockResolvedValue({ orgId: 'org-1', userId: 'user-123', role: 'admin' });
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		// update should not be called for org member since role matches
		// (it may still be called for project sync, but orgMember update is skipped)
		expect(mockTxUpdateSet).not.toHaveBeenCalledWith({ role: 'admin' });
	});

	it('assigns viewer org role when user only has project-level groups', async () => {
		const projectRoles = new Map([['PROJECT-1', 'user' as const]]);
		setupValidJwtFlow({ orgRole: null, projectRoles });
		mockTxOrgMemberFindFirst.mockResolvedValue(null);
		mockTxSelectExecute.mockResolvedValue([]);
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		const orgMemberInsert = mockTxInsertValues.mock.calls.find((args: unknown[]) => {
			const arg = args[0] as Record<string, unknown> | undefined;
			return arg && 'orgId' in arg && 'role' in arg;
		});
		expect(orgMemberInsert).toBeDefined();
		expect((orgMemberInsert![0] as Record<string, unknown>).role).toBe('viewer');
	});

	it('deletes stale project membership not in target groups', async () => {
		setupValidJwtFlow({ orgRole: 'admin', projectRoles: new Map() });
		mockTxOrgMemberFindFirst.mockResolvedValue({ orgId: 'org-1', userId: 'user-123', role: 'admin' });
		// Org has one project
		mockTxSelectExecute
			.mockResolvedValueOnce([{ id: 'proj-1', name: 'Old Project', orgId: 'org-1' }])
			// User has membership in that project
			.mockResolvedValueOnce([{ projectId: 'proj-1', userId: 'user-123', role: 'admin' }]);
		const reply = makeReply();

		await jwtAuthPreHandler(makeRequest() as never, reply as never);

		expect(mockTxDelete).toHaveBeenCalled();
	});
});
