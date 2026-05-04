import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('JWT env validation', () => {
	const originalEnv = { ...process.env };
	const mockExit = vi.spyOn(process, 'exit').mockImplementation(() => undefined as never);
	const mockConsoleError = vi.spyOn(console, 'error').mockImplementation(() => {});

	beforeEach(() => {
		mockExit.mockClear();
		mockConsoleError.mockClear();
	});

	afterEach(() => {
		process.env = { ...originalEnv };
	});

	it('exits when JWT_AUTH_ENABLED=true but JWT_JWKS_URL is missing', async () => {
		process.env.JWT_AUTH_ENABLED = 'true';
		delete process.env.JWT_JWKS_URL;

		await import('../src/env?t=' + Date.now());

		expect(mockExit).toHaveBeenCalledWith(1);
		expect(mockConsoleError).toHaveBeenCalledWith('JWT_JWKS_URL is required when JWT_AUTH_ENABLED=true.');
	});

	it('does not exit when JWT_AUTH_ENABLED=true and JWT_JWKS_URL is set', async () => {
		process.env.JWT_AUTH_ENABLED = 'true';
		process.env.JWT_JWKS_URL = 'https://idp.example.com/.well-known/jwks.json';

		mockExit.mockClear();
		await import('../src/env?t=' + (Date.now() + 1));

		const jwtRelatedCalls = mockExit.mock.calls.filter(() => {
			return mockConsoleError.mock.calls.some(
				(call) => typeof call[0] === 'string' && call[0].includes('JWT_JWKS_URL'),
			);
		});
		expect(jwtRelatedCalls).toHaveLength(0);
	});

	it('does not validate JWT_JWKS_URL when JWT_AUTH_ENABLED is not set', async () => {
		delete process.env.JWT_AUTH_ENABLED;
		delete process.env.JWT_JWKS_URL;

		mockExit.mockClear();
		mockConsoleError.mockClear();
		await import('../src/env?t=' + (Date.now() + 2));

		const jwtCalls = mockConsoleError.mock.calls.filter(
			(call) => typeof call[0] === 'string' && call[0].includes('JWT_JWKS_URL'),
		);
		expect(jwtCalls).toHaveLength(0);
	});
});
