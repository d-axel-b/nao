import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { __reloadEnvForTesting } from '../src/env';
import { isJwtAuthEnabled, resetJwksCache, verifyAndDecode } from '../src/services/jwt-auth.service';

// ─── Test keypair & mock JWKS server ────────────────────────────────

let privateKey: CryptoKey;
let publicJwk: Record<string, unknown>;

beforeAll(async () => {
	const pair = await generateKeyPair('RS256');
	privateKey = pair.privateKey as CryptoKey;
	const exported = await exportJWK(pair.publicKey);
	publicJwk = { ...exported, kid: 'test-key-1', alg: 'RS256', use: 'sig' };
});

function mockJwksServer() {
	const jwksResponse = JSON.stringify({ keys: [publicJwk] });
	vi.stubGlobal(
		'fetch',
		vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: () => Promise.resolve(JSON.parse(jwksResponse)),
		}),
	);
}

async function signToken(
	claims: Record<string, unknown>,
	opts?: { expiresIn?: string; issuer?: string; kid?: string },
): Promise<string> {
	let builder = new SignJWT(claims)
		.setProtectedHeader({ alg: 'RS256', kid: opts?.kid ?? 'test-key-1' })
		.setIssuedAt();

	if (opts?.expiresIn) {
		builder = builder.setExpirationTime(opts.expiresIn);
	} else {
		builder = builder.setExpirationTime('1h');
	}

	if (opts?.issuer) {
		builder = builder.setIssuer(opts.issuer);
	}

	return builder.sign(privateKey);
}

// ─── isJwtAuthEnabled ───────────────────────────────────────────────

describe('isJwtAuthEnabled', () => {
	afterEach(() => {
		delete process.env.JWT_AUTH_ENABLED;
		__reloadEnvForTesting();
	});

	it('returns false when not set', () => {
		delete process.env.JWT_AUTH_ENABLED;
		__reloadEnvForTesting();
		expect(isJwtAuthEnabled()).toBe(false);
	});

	it('returns true when set to "true"', () => {
		process.env.JWT_AUTH_ENABLED = 'true';
		__reloadEnvForTesting();
		expect(isJwtAuthEnabled()).toBe(true);
	});

	it('returns false when set to "false"', () => {
		process.env.JWT_AUTH_ENABLED = 'false';
		__reloadEnvForTesting();
		expect(isJwtAuthEnabled()).toBe(false);
	});
});

// ─── verifyAndDecode ────────────────────────────────────────────────

describe('verifyAndDecode', () => {
	beforeEach(() => {
		resetJwksCache();
		process.env.JWT_JWKS_URL = 'https://idp.example.com/.well-known/jwks.json';
		delete process.env.JWT_ISSUER;
		__reloadEnvForTesting();
		mockJwksServer();
	});

	afterEach(() => {
		delete process.env.JWT_JWKS_URL;
		delete process.env.JWT_ISSUER;
		__reloadEnvForTesting();
		resetJwksCache();
		vi.restoreAllMocks();
	});

	it('decodes a valid JWT and returns the payload', async () => {
		const token = await signToken({ sub: 'alice@example.com', displayName: 'Alice' });
		const payload = await verifyAndDecode(token);
		expect(payload.sub).toBe('alice@example.com');
		expect(payload.displayName).toBe('Alice');
	});

	it('rejects an expired token', async () => {
		const token = await signToken({ sub: 'alice@example.com' }, { expiresIn: '-1h' });
		await expect(verifyAndDecode(token)).rejects.toThrow();
	});

	it('rejects a token with wrong issuer when JWT_ISSUER is set', async () => {
		process.env.JWT_ISSUER = 'https://expected-issuer.example.com';
		__reloadEnvForTesting();
		resetJwksCache();

		const token = await signToken({ sub: 'alice@example.com' }, { issuer: 'https://wrong-issuer.example.com' });
		await expect(verifyAndDecode(token)).rejects.toThrow();
	});

	it('accepts a token with matching issuer when JWT_ISSUER is set', async () => {
		process.env.JWT_ISSUER = 'https://expected-issuer.example.com';
		__reloadEnvForTesting();
		resetJwksCache();

		const token = await signToken({ sub: 'alice@example.com' }, { issuer: 'https://expected-issuer.example.com' });
		const payload = await verifyAndDecode(token);
		expect(payload.sub).toBe('alice@example.com');
	});

	it('accepts a token with any issuer when JWT_ISSUER is not set', async () => {
		const token = await signToken({ sub: 'alice@example.com' }, { issuer: 'https://any-issuer.example.com' });
		const payload = await verifyAndDecode(token);
		expect(payload.sub).toBe('alice@example.com');
	});

	it('throws when JWT_JWKS_URL is not configured', async () => {
		delete process.env.JWT_JWKS_URL;
		__reloadEnvForTesting();
		resetJwksCache();

		const token = await signToken({ sub: 'alice@example.com' });
		await expect(verifyAndDecode(token)).rejects.toThrow('JWT_JWKS_URL is not configured');
	});

	it('rejects a tampered token', async () => {
		const token = await signToken({ sub: 'alice@example.com' });
		const tampered = token.slice(0, -5) + 'XXXXX';
		await expect(verifyAndDecode(tampered)).rejects.toThrow();
	});
});

// ─── resetJwksCache ─────────────────────────────────────────────────

describe('resetJwksCache', () => {
	beforeEach(() => {
		process.env.JWT_JWKS_URL = 'https://idp.example.com/.well-known/jwks.json';
		__reloadEnvForTesting();
		mockJwksServer();
	});

	afterEach(() => {
		delete process.env.JWT_JWKS_URL;
		__reloadEnvForTesting();
		resetJwksCache();
		vi.restoreAllMocks();
	});

	it('forces JWKS to be re-fetched on next verify', async () => {
		const token = await signToken({ sub: 'alice@example.com' });

		await verifyAndDecode(token);
		resetJwksCache();
		await verifyAndDecode(token);

		// createRemoteJWKSet is recreated after reset, so fetch is called again for JWKS
		expect(vi.mocked(fetch).mock.calls.length).toBeGreaterThanOrEqual(2);
	});
});
