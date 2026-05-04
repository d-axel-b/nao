import { env } from '../env';
import type { OrgRole } from '../types/organization';

export interface ParsedGroupRole {
	projectSlug: string | null;
	role: OrgRole;
}

export interface ResolvedMemberships {
	orgRole: OrgRole | null;
	projectRoles: Map<string, OrgRole>;
}

const ROLE_PRIORITY: Record<OrgRole, number> = { admin: 3, user: 2, viewer: 1 };

function higherRole(a: OrgRole, b: OrgRole): OrgRole {
	return ROLE_PRIORITY[a] >= ROLE_PRIORITY[b] ? a : b;
}

function escapeRegex(str: string): string {
	return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function buildGroupRegex(): { regex: RegExp; roleMap: Map<string, OrgRole> } {
	const roleKeywords = [
		{ keyword: (env.JWT_GROUP_ROLE_ADMIN ?? 'ADMINS').toUpperCase(), role: 'admin' as OrgRole },
		{ keyword: (env.JWT_GROUP_ROLE_USER ?? 'USERS').toUpperCase(), role: 'user' as OrgRole },
		{ keyword: (env.JWT_GROUP_ROLE_VIEWER ?? 'VIEWERS').toUpperCase(), role: 'viewer' as OrgRole },
	];

	const roleMap = new Map<string, OrgRole>();
	for (const { keyword, role } of roleKeywords) {
		roleMap.set(keyword, role);
	}

	const prefix = env.JWT_GROUP_PREFIX ? escapeRegex(env.JWT_GROUP_PREFIX.toUpperCase()) + '-' : '';
	const suffix = env.JWT_GROUP_SUFFIX ? '-' + escapeRegex(env.JWT_GROUP_SUFFIX.toUpperCase()) : '';
	const roleAlternation = roleKeywords.map((r) => escapeRegex(r.keyword)).join('|');

	const pattern = `^${prefix}(?:(?<slug>.+)-)?(?<role>${roleAlternation})${suffix}$`;
	return { regex: new RegExp(pattern, 'i'), roleMap };
}

export function parseGroup(groupName: string): ParsedGroupRole | null {
	const { regex, roleMap } = buildGroupRegex();
	const match = regex.exec(groupName);
	if (!match?.groups) return null;

	const role = roleMap.get(match.groups.role.toUpperCase());
	if (!role) return null;

	const slug = match.groups.slug?.toUpperCase() ?? null;
	return { projectSlug: slug, role };
}

export function resolveGroupMemberships(groups: string[]): ResolvedMemberships {
	let orgRole: OrgRole | null = null;
	const projectRoles = new Map<string, OrgRole>();

	for (const group of groups) {
		const parsed = parseGroup(group);
		if (!parsed) continue;

		if (parsed.projectSlug === null) {
			orgRole = orgRole ? higherRole(orgRole, parsed.role) : parsed.role;
		} else {
			const existing = projectRoles.get(parsed.projectSlug);
			projectRoles.set(parsed.projectSlug, existing ? higherRole(existing, parsed.role) : parsed.role);
		}
	}

	return { orgRole, projectRoles };
}

export function hasAnyRole(memberships: ResolvedMemberships): boolean {
	return memberships.orgRole !== null || memberships.projectRoles.size > 0;
}
