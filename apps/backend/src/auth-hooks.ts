import { APIError } from 'better-auth';

import * as orgQueries from './queries/organization.queries';
import { isEmailDomainAllowed } from './utils/utils';
import { logger } from './utils/logger';

export type AuthHookContext = { params?: { id?: string } } | null | undefined;

export type AuthHookUser = { id: string; email: string };

export type AuthHookConfig = {
	googleAuthDomains: string | undefined;
	microsoftAuthDomains: string | undefined;
};

const SOCIAL_PROVIDER_IDS = ['google', 'github', 'microsoft'] as const;

export const isSocialProvider = (providerId: string | undefined): boolean => {
	return SOCIAL_PROVIDER_IDS.includes(providerId as (typeof SOCIAL_PROVIDER_IDS)[number]);
};

/** Validate the email domain for providers that have a configured allowlist. Throws FORBIDDEN if blocked. */
export const enforceDomainAllowlist = (
	user: AuthHookUser,
	ctx: AuthHookContext,
	config: AuthHookConfig,
): void => {
	const providerId = ctx?.params?.id;

	if (providerId === 'google' && !isEmailDomainAllowed(user.email, config.googleAuthDomains)) {
		throw new APIError('FORBIDDEN', {
			message: 'This email domain is not authorized to access this application.',
		});
	}

	if (providerId === 'microsoft' && !isEmailDomainAllowed(user.email, config.microsoftAuthDomains)) {
		throw new APIError('FORBIDDEN', {
			message: 'This email domain is not authorized to access this application.',
		});
	}
};

/** Build the `before` user-create hook. Runs before the user row is inserted. */
export const buildBeforeCreateHook = (config: AuthHookConfig) => {
	return async (user: AuthHookUser, ctx: AuthHookContext) => {
		enforceDomainAllowlist(user, ctx, config);
		return true;
	};
};

/** Build the `after` user-create hook. Seeds organization / project membership for the new user. */
export const buildAfterCreateHook = (opts: { isCloud: boolean }) => {
	return async (user: AuthHookUser, ctx: AuthHookContext) => {
		const providerId = ctx?.params?.id;
		const isSocial = isSocialProvider(providerId);

		if (opts.isCloud) {
			await orgQueries.initializePersonalOrganization(user.id);
		} else {
			await orgQueries.initializeDefaultOrganizationForFirstUser(user.id);
			if (isSocial) {
				await orgQueries.addUserToDefaultProjectIfExists(user.id);
			}
		}

		logger.info('user signed up', {
			source: 'http',
			context: { userId: user.id, provider: providerId ?? 'email-password' },
		});
	};
};
