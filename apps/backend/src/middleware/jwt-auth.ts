import crypto from 'node:crypto';

import { and, eq } from 'drizzle-orm';
import type { FastifyReply, FastifyRequest } from 'fastify';

import { getAuth } from '../auth';
import s from '../db/abstractSchema';
import { db } from '../db/db';
import { env } from '../env';
import * as orgQueries from '../queries/organization.queries';
import { getUser } from '../queries/user.queries';
import { extractIdentity, isJwtAuthEnabled, verifyAndDecode } from '../services/jwt-auth.service';
import { hasAnyRole, resolveGroupMemberships, type ResolvedMemberships } from '../services/jwt-group.service';
import type { OrgRole } from '../types/organization';
import { convertHeaders, isEmailDomainAllowed } from '../utils/utils';

const SESSION_EXPIRY_SECONDS = 7 * 24 * 3600;

export async function jwtAuthPreHandler(request: FastifyRequest, reply: FastifyReply) {
	if (!isJwtAuthEnabled()) return;

	const headers = convertHeaders(request.headers);
	const auth = await getAuth();
	const existingSession = await auth.api.getSession({ headers });
	if (existingSession?.user) return;

	const authHeader = request.headers.authorization;
	if (!authHeader?.startsWith('Bearer ')) {
		return reply.status(401).send({ error: 'Missing authorization token' });
	}

	try {
		const token = authHeader.slice(7);
		const payload = await verifyAndDecode(token);
		const identity = extractIdentity(payload);

		if (!isEmailDomainAllowed(identity.email, env.JWT_AUTH_DOMAINS)) {
			return reply.status(403).send({ error: 'Email domain not authorized' });
		}

		const memberships = resolveGroupMemberships(identity.groups);
		if (!hasAnyRole(memberships)) {
			return reply.status(403).send({ error: 'No authorized group membership' });
		}

		const user = await findOrCreateUser(identity.email, identity.name);
		const org = await orgQueries.getFirstOrganization();
		if (!org) {
			return reply.status(500).send({ error: 'No organization configured' });
		}

		await syncMemberships(user.id, org.id, memberships);

		const sessionToken = await createSession(user.id, request);
		const secure = env.MODE === 'prod';
		const parts = [
			`better-auth.session_token=${sessionToken}`,
			'Path=/',
			'HttpOnly',
			'SameSite=Lax',
			`Max-Age=${SESSION_EXPIRY_SECONDS}`,
		];
		if (secure) parts.push('Secure');
		reply.header('Set-Cookie', parts.join('; '));
	} catch (error) {
		const message = error instanceof Error ? error.message : 'JWT authentication failed';
		return reply.status(401).send({ error: message });
	}
}

async function findOrCreateUser(email: string, name: string) {
	const existing = await getUser({ email });
	if (existing) return existing;

	const userId = crypto.randomUUID();
	const now = new Date();

	const [user] = await db
		.insert(s.user)
		.values({
			id: userId,
			email,
			name,
			emailVerified: true,
			createdAt: now,
			updatedAt: now,
		})
		.returning()
		.execute();

	await db
		.insert(s.account)
		.values({
			id: crypto.randomUUID(),
			accountId: userId,
			providerId: 'jwt',
			userId,
			createdAt: now,
			updatedAt: now,
		})
		.execute();

	return user;
}

async function createSession(userId: string, request: FastifyRequest): Promise<string> {
	const sessionId = crypto.randomUUID();
	const token = crypto.randomBytes(32).toString('hex');
	const now = new Date();
	const expiresAt = new Date(now.getTime() + SESSION_EXPIRY_SECONDS * 1000);

	await db
		.insert(s.session)
		.values({
			id: sessionId,
			token,
			userId,
			expiresAt,
			createdAt: now,
			updatedAt: now,
			ipAddress: request.ip ?? null,
			userAgent: request.headers['user-agent'] ?? null,
		})
		.execute();

	return token;
}

async function syncMemberships(userId: string, orgId: string, memberships: ResolvedMemberships) {
	const effectiveOrgRole = memberships.orgRole ?? (memberships.projectRoles.size > 0 ? 'viewer' : null);
	if (!effectiveOrgRole) return;

	await db.transaction(async (tx) => {
		const existingOrgMember = await tx.query.orgMember.findFirst({
			where: and(eq(s.orgMember.orgId, orgId), eq(s.orgMember.userId, userId)),
		});

		if (existingOrgMember) {
			if (existingOrgMember.role !== effectiveOrgRole) {
				await tx
					.update(s.orgMember)
					.set({ role: effectiveOrgRole })
					.where(and(eq(s.orgMember.orgId, orgId), eq(s.orgMember.userId, userId)))
					.execute();
			}
		} else {
			await tx.insert(s.orgMember).values({ orgId, userId, role: effectiveOrgRole }).execute();
		}

		// Sync project memberships
		const orgProjects = await tx.select().from(s.project).where(eq(s.project.orgId, orgId)).execute();

		const resolvedTargets = new Map<string, OrgRole>();
		for (const [slug, role] of memberships.projectRoles) {
			const project = orgProjects.find((p) => normalizeSlug(p.name) === slug);
			if (project) {
				resolvedTargets.set(project.id, role);
			}
		}

		const existingMemberships = await tx
			.select()
			.from(s.projectMember)
			.where(eq(s.projectMember.userId, userId))
			.execute();

		const orgProjectIds = new Set(orgProjects.map((p) => p.id));
		const existingInOrg = existingMemberships.filter((m) => orgProjectIds.has(m.projectId));

		for (const existing of existingInOrg) {
			const targetRole = resolvedTargets.get(existing.projectId);
			if (!targetRole) {
				await tx
					.delete(s.projectMember)
					.where(and(eq(s.projectMember.projectId, existing.projectId), eq(s.projectMember.userId, userId)))
					.execute();
			} else if (existing.role !== targetRole) {
				await tx
					.update(s.projectMember)
					.set({ role: targetRole })
					.where(and(eq(s.projectMember.projectId, existing.projectId), eq(s.projectMember.userId, userId)))
					.execute();
			}
		}

		const existingProjectIds = new Set(existingInOrg.map((m) => m.projectId));
		for (const [projectId, role] of resolvedTargets) {
			if (!existingProjectIds.has(projectId)) {
				await tx.insert(s.projectMember).values({ projectId, userId, role }).execute();
			}
		}
	});
}

function normalizeSlug(name: string): string {
	return name.toUpperCase().replace(/[\s_]+/g, '-');
}
