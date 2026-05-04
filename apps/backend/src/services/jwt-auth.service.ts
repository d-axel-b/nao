import { createRemoteJWKSet, jwtVerify } from 'jose';

import { env } from '../env';

export interface JwtIdentity {
	email: string;
	name: string;
	groups: string[];
}

let jwks: ReturnType<typeof createRemoteJWKSet> | null = null;

function getJwks(): ReturnType<typeof createRemoteJWKSet> {
	if (!jwks && env.JWT_JWKS_URL) {
		jwks = createRemoteJWKSet(new URL(env.JWT_JWKS_URL));
	}
	if (!jwks) {
		throw new Error('JWT_JWKS_URL is not configured');
	}
	return jwks;
}

export function resetJwksCache(): void {
	jwks = null;
}

export function isJwtAuthEnabled(): boolean {
	return env.JWT_AUTH_ENABLED === true;
}

export async function verifyAndDecode(token: string): Promise<Record<string, unknown>> {
	const { payload } = await jwtVerify(token, getJwks(), {
		issuer: env.JWT_ISSUER || undefined,
	});
	return payload as Record<string, unknown>;
}

export function extractIdentity(payload: Record<string, unknown>): JwtIdentity {
	const emailClaim = env.JWT_CLAIM_EMAIL ?? 'sub';
	const nameClaim = env.JWT_CLAIM_NAME ?? 'displayName';
	const groupClaim = env.JWT_GROUP_CLAIM ?? 'groups';

	const email = payload[emailClaim];
	if (typeof email !== 'string' || !email.includes('@')) {
		throw new Error(`JWT claim '${emailClaim}' is missing or not a valid email`);
	}

	const name = typeof payload[nameClaim] === 'string' ? payload[nameClaim] : email.split('@')[0];

	const rawGroups = payload[groupClaim];
	const groups = Array.isArray(rawGroups) ? rawGroups.filter((g): g is string => typeof g === 'string') : [];

	return { email: email.toLowerCase(), name, groups };
}
