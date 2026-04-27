import { APIError, betterAuth } from 'better-auth';
import { drizzleAdapter } from 'better-auth/adapters/drizzle';

import { buildAfterCreateHook, buildBeforeCreateHook } from './auth-hooks';
import { db } from './db/db';
import dbConfig, { Dialect } from './db/dbConfig';
import { env, isCloud } from './env';
import * as orgQueries from './queries/organization.queries';
import { emailService } from './services/email';
import { buildForgotPasswordEmail } from './utils/email-builders';
import { buildGithubAllowlist } from './utils/utils';

type GoogleConfig = Awaited<ReturnType<typeof orgQueries.getGoogleConfig>>;

function createAuthInstance(googleConfig: GoogleConfig) {
	const githubAllowlist = buildGithubAllowlist(env.GITHUB_ALLOWED_USERS);

	const socialProviders: Parameters<typeof betterAuth>[0]['socialProviders'] = {
		google: {
			prompt: 'select_account',
			clientId: googleConfig.clientId,
			clientSecret: googleConfig.clientSecret,
		},
	};

	if (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) {
		socialProviders.github = {
			clientId: env.GITHUB_CLIENT_ID,
			clientSecret: env.GITHUB_CLIENT_SECRET,
			getUserInfo: async (token) => {
				const res = await fetch('https://api.github.com/user', {
					headers: { Authorization: `Bearer ${token.accessToken}`, Accept: 'application/json' },
				});
				const profile = await res.json();

				if (githubAllowlist.size > 0 && !githubAllowlist.has(profile.login)) {
					throw new APIError('FORBIDDEN', {
						message: 'Your GitHub account is not authorized to access this application.',
					});
				}

				return {
					user: {
						id: String(profile.id),
						name: profile.login as string,
						email: (profile.email ?? `${profile.login}@users.noreply.github.com`) as string,
						image: profile.avatar_url as string,
						emailVerified: true,
					},
					data: profile,
				};
			},
		};
	}

	if (env.MICROSOFT_CLIENT_ID && env.MICROSOFT_CLIENT_SECRET) {
		// `tenantId` is forwarded into the Microsoft authorize URL, so a UUID restricts the OAuth flow
		// to that single tenant at the IdP layer. `organizations` (default) accepts any work/school
		// account but blocks personal Microsoft accounts. See apps/backend/docs/auth-microsoft.md.
		socialProviders.microsoft = {
			clientId: env.MICROSOFT_CLIENT_ID,
			clientSecret: env.MICROSOFT_CLIENT_SECRET,
			tenantId: env.MICROSOFT_TENANT_ID ?? 'organizations',
			prompt: 'select_account',
		};
	}

	const beforeCreate = buildBeforeCreateHook({
		googleAuthDomains: googleConfig.authDomains,
		microsoftAuthDomains: env.MICROSOFT_AUTH_DOMAINS,
	});
	const afterCreate = buildAfterCreateHook({ isCloud });

	return betterAuth({
		secret: env.BETTER_AUTH_SECRET,
		database: drizzleAdapter(db, {
			provider: dbConfig.dialect === Dialect.Postgres ? 'pg' : 'sqlite',
			schema: dbConfig.schema,
		}),
		trustedOrigins: env.BETTER_AUTH_URL ? [env.BETTER_AUTH_URL] : undefined,
		emailAndPassword: {
			enabled: true,
			sendResetPassword: async ({ user, url }) => {
				if (!emailService.isEnabled()) {
					return;
				}
				emailService.sendEmail(user.email, buildForgotPasswordEmail(user, url));
			},
		},
		socialProviders,
		// Restrict cross-provider account linking to providers that always return a verified email.
		// Prevents an attacker controlling provider B from taking over an existing account on provider A
		// just by claiming the same email. Better-auth defaults `allowDifferentEmails` to false.
		account: {
			accountLinking: {
				enabled: true,
				trustedProviders: ['google', 'github', 'microsoft'],
			},
		},
		databaseHooks: {
			user: {
				create: {
					before: beforeCreate,
					after: afterCreate,
				},
			},
		},
		user: {
			additionalFields: {
				requiresPasswordReset: { type: 'boolean', default: false, input: false },
				messagingProviderCode: { type: 'string', default: '', input: false },
			},
		},
	});
}

let authPromise: Promise<ReturnType<typeof createAuthInstance>> | null = null;

export const getAuth = () => {
	if (!authPromise) {
		authPromise = orgQueries.getGoogleConfig().then(createAuthInstance);
	}
	return authPromise;
};

export function updateAuth() {
	authPromise = orgQueries.getGoogleConfig().then(createAuthInstance);
}
