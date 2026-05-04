# JWT Pre-Authentication

JWT pre-authentication lets nao run behind an identity-aware proxy (ISTIO, Envoy, API gateway) that handles login and token issuance. nao receives every request with a pre-validated JWT in the `Authorization` header, verifies the token independently, and creates a local session.

This mode is designed for enterprise deployments where authentication is centralized at the infrastructure layer and AD group memberships drive project access.

## How it works

```
Browser ─► ISTIO / API gateway ─► nao backend
              │                        │
              │ validates JWT           │ verifies JWT signature (JWKS)
              │ sets Authorization      │ extracts email + name + groups
              │ header                  │ finds or creates user
              │                        │ syncs org & project memberships
              │                        │ creates session cookie
              │                        │
              │                        ▼
              │                   standard better-auth
              │                   session flow from here
```

1. The proxy authenticates the user (e.g., OIDC login flow) and forwards every request with `Authorization: Bearer <jwt>`.
2. nao's pre-handler verifies the JWT signature using the JWKS endpoint and validates `exp` / `iss` claims.
3. If the user already has a valid session cookie, the JWT is ignored and the request proceeds normally.
4. On first request (or after session expiry), nao extracts the user identity and AD groups from the JWT, syncs memberships to the database, and sets a session cookie.
5. Subsequent requests use the session cookie — no JWT processing until the session expires.

## Prerequisites

- An identity provider (Entra ID, Okta, Keycloak, etc.) that issues JWTs with user identity and group claims.
- A reverse proxy (ISTIO `RequestAuthentication`, Envoy, or any API gateway) that validates tokens before they reach nao.
- A JWKS endpoint published by your identity provider for signature verification.

## Environment variables

### Core settings

| Variable           | Required | Default       | Description                                                                                                 |
| ------------------ | -------- | ------------- | ----------------------------------------------------------------------------------------------------------- |
| `JWT_AUTH_ENABLED` | No       | `false`       | Set to `true` to enable JWT pre-authentication                                                              |
| `JWT_JWKS_URL`     | **Yes**  | —             | JWKS endpoint URL for signature verification. Required when JWT auth is enabled.                            |
| `JWT_ISSUER`       | No       | —             | Expected `iss` claim value. When set, tokens from other issuers are rejected.                               |
| `JWT_CLAIM_EMAIL`  | No       | `sub`         | Name of the JWT claim containing the user's email address.                                                  |
| `JWT_CLAIM_NAME`   | No       | `displayName` | Name of the JWT claim containing the user's display name.                                                   |
| `JWT_AUTH_DOMAINS` | No       | —             | Comma-separated list of allowed email domains. When set, users outside these domains are rejected with 403. |

### Group-to-role mapping

| Variable                | Required | Default   | Description                                                         |
| ----------------------- | -------- | --------- | ------------------------------------------------------------------- |
| `JWT_GROUP_CLAIM`       | No       | `groups`  | Name of the JWT claim containing the group list (array of strings). |
| `JWT_GROUP_PREFIX`      | No       | —         | Prefix to strip from group names before parsing.                    |
| `JWT_GROUP_SUFFIX`      | No       | —         | Suffix to strip from group names before parsing.                    |
| `JWT_GROUP_ROLE_ADMIN`  | No       | `ADMINS`  | Role keyword that maps to nao `admin` role.                         |
| `JWT_GROUP_ROLE_USER`   | No       | `USERS`   | Role keyword that maps to nao `user` role.                          |
| `JWT_GROUP_ROLE_VIEWER` | No       | `VIEWERS` | Role keyword that maps to nao `viewer` role.                        |

## Minimal setup

```env
JWT_AUTH_ENABLED=true
JWT_JWKS_URL=https://login.microsoftonline.com/{tenant-id}/discovery/v2.0/keys
JWT_ISSUER=https://sts.windows.net/{tenant-id}/
JWT_CLAIM_EMAIL=preferred_username
JWT_GROUP_CLAIM=groups
JWT_GROUP_PREFIX=ACME-NAO
JWT_GROUP_SUFFIX=PROD
```

With this configuration, a user whose JWT contains the group `ACME-NAO-SALES-DASHBOARD-ADMINS-PROD` will be granted admin access to the nao project named `SALES-DASHBOARD`.

## Group naming convention

Group names follow the pattern:

```
{PREFIX}-{PROJECT_SLUG}-{ROLE_KEYWORD}-{SUFFIX}
```

nao strips the configured prefix and suffix, then uses a regex to extract the **project slug** and **role keyword** in a single pass. The match is case-insensitive.

### Anatomy of a group name

```
ACME-NAO  -  SALES-DASHBOARD  -  ADMINS  -  PROD
────────     ───────────────     ──────     ────
 prefix       project slug       role      suffix
 (stripped)   (matched to DB)    keyword   (stripped)
                                 (→ admin)
```

### Role keywords

| Keyword (default) | nao role | Permissions                                                 |
| ----------------- | -------- | ----------------------------------------------------------- |
| `ADMINS`          | `admin`  | Full access: manage members, settings, and all project data |
| `USERS`           | `user`   | Can use the chat, run queries, and view project data        |
| `VIEWERS`         | `viewer` | Read-only access to the project                             |

You can override these keywords with `JWT_GROUP_ROLE_ADMIN`, `JWT_GROUP_ROLE_USER`, and `JWT_GROUP_ROLE_VIEWER`.

### Org-level vs project-level groups

Groups **without a project slug** (i.e., just the role keyword between prefix and suffix) assign an organization-level role:

| Group name              | Role   | Scope             |
| ----------------------- | ------ | ----------------- |
| `ACME-NAO-ADMINS-PROD`  | admin  | Organization-wide |
| `ACME-NAO-USERS-PROD`   | user   | Organization-wide |
| `ACME-NAO-VIEWERS-PROD` | viewer | Organization-wide |

Groups **with a project slug** assign a per-project role:

| Group name                             | Role   | Project         |
| -------------------------------------- | ------ | --------------- |
| `ACME-NAO-SALES-DASHBOARD-ADMINS-PROD` | admin  | SALES-DASHBOARD |
| `ACME-NAO-FINANCE-REPORTS-USERS-PROD`  | user   | FINANCE-REPORTS |
| `ACME-NAO-HR-ANALYTICS-VIEWERS-PROD`   | viewer | HR-ANALYTICS    |

### Project slug matching

The project slug extracted from the group name is matched against existing nao project names. The comparison is case-insensitive and normalizes spaces/underscores to dashes. For example:

- Group slug `SALES-DASHBOARD` matches a project named `Sales Dashboard` or `sales-dashboard`
- Group slug `HR-ANALYTICS` matches a project named `HR Analytics`

If no project with a matching name exists, the group is silently skipped. When the project is created later and the user logs in again, the membership is created automatically.

### Role priority

When a user is in multiple groups that map to the same scope (same project or both org-level), the **highest privilege wins**:

```
admin > user > viewer
```

For example, if a user is in both `ACME-NAO-SALES-DASHBOARD-USERS-PROD` and `ACME-NAO-SALES-DASHBOARD-ADMINS-PROD`, they get `admin` on that project.

## How to create AD groups

### Step 1: Choose your prefix and suffix

Pick a prefix that identifies your organization and nao deployment, and a suffix that identifies the environment:

|        | Example    | Purpose                                   |
| ------ | ---------- | ----------------------------------------- |
| Prefix | `ACME-NAO` | Isolates nao groups from other AD groups  |
| Suffix | `PROD`     | Distinguishes production from staging/dev |

### Step 2: Create org-level groups (optional)

Create groups for users who need organization-wide access:

```
ACME-NAO-ADMINS-PROD       → org admins (can manage all projects and members)
ACME-NAO-USERS-PROD        → org users (default access to all projects)
ACME-NAO-VIEWERS-PROD      → org viewers (read-only across all projects)
```

### Step 3: Create per-project groups

For each nao project, create groups matching the project name. Use dashes instead of spaces:

```
# Project "Sales Dashboard"
ACME-NAO-SALES-DASHBOARD-ADMINS-PROD
ACME-NAO-SALES-DASHBOARD-USERS-PROD
ACME-NAO-SALES-DASHBOARD-VIEWERS-PROD

# Project "Finance Reports"
ACME-NAO-FINANCE-REPORTS-ADMINS-PROD
ACME-NAO-FINANCE-REPORTS-USERS-PROD
```

You don't need to create all three role groups — only the ones you need.

### Step 4: Assign users

Add users to the appropriate AD groups. A user can be in multiple groups (e.g., admin on one project, viewer on another).

### Step 5: Configure the identity provider

Ensure that the JWT issued to users includes the group memberships in the configured claim (default: `groups`). In Entra ID, this is configured under **App registrations > Token configuration > Add groups claim**.

## Access rules

- **Users must have at least one recognized group** to access nao. Users without any group matching the prefix/suffix/role pattern are rejected with 403.
- There is **no fallback to `DEFAULT_USER_ROLE`** — AD group membership is the sole authority for JWT-authenticated users.
- **Org-level admins are admin everywhere** — project-level groups refine access for non-admin org members.
- **Org members without explicit project membership** get implicit `viewer` access to all projects in the org (existing nao behavior).
- **Memberships are re-synced on every JWT login** (whenever the session expires and a new JWT is presented). Between syncs, the DB state from the last login is used.

## Session lifecycle

1. **First request**: JWT is verified, user is provisioned, memberships are synced, session cookie is set.
2. **Subsequent requests**: Session cookie is used. JWT is ignored. No re-sync.
3. **Session expires**: Next request with a valid JWT triggers a new sync. Group changes take effect at this point.
4. **No JWT and no session**: Request is rejected with 401.

The session duration follows better-auth's default (7 days). This means group changes in AD can take up to 7 days to take effect. If faster propagation is needed, reduce the session expiry or have users clear their cookies.

## Coexistence with other auth methods

JWT pre-authentication coexists with existing auth methods (email/password, Google OAuth, GitHub OAuth, Microsoft SSO):

- When `JWT_AUTH_ENABLED=true`, the JWT pre-handler runs on every request **before** route handlers.
- If the request already has a valid session cookie (from any auth method), the JWT pre-handler is skipped.
- If no session exists and no `Authorization: Bearer` header is present, the pre-handler returns 401.
- Users created via JWT auth get a `jwt` provider account. They cannot log in via email/password unless a password is set separately.

## Troubleshooting

### 401 "Missing authorization token"

The request reached nao without an `Authorization: Bearer <token>` header and without a valid session cookie. Check that your proxy is forwarding the JWT correctly.

### 401 "JWT authentication failed"

The JWT signature verification failed. Common causes:

- `JWT_JWKS_URL` is incorrect or unreachable from the nao backend
- The JWT was signed by a different key than what the JWKS endpoint publishes
- The token has expired (`exp` claim is in the past)
- `JWT_ISSUER` is set but doesn't match the `iss` claim in the token

### 403 "Email domain not authorized"

`JWT_AUTH_DOMAINS` is set and the user's email domain is not in the allowlist. Either add the domain or remove the restriction.

### 403 "No authorized group membership"

The user's JWT contains no groups that match the configured prefix/suffix/role pattern. Check:

- The `groups` claim (or your configured `JWT_GROUP_CLAIM`) is present in the JWT
- The group names follow the expected convention
- `JWT_GROUP_PREFIX` and `JWT_GROUP_SUFFIX` match what's in the group names (case-insensitive)
- At least one group contains a valid role keyword (`ADMINS`, `USERS`, or `VIEWERS` by default)

### User can see the app but has no projects in the sidebar

The user has an org-level group but no project-level groups, and no nao projects match any of their group slugs. Either:

- Create the matching projects in nao
- Add the user to project-level AD groups that match existing project names
- Ensure project names in nao match the slug portion of the AD group names (dashes = spaces)

### Group changes not reflected in the UI

Membership sync only runs when a new JWT login occurs (session expired or first visit). The user's current session still uses the old memberships. Ask the user to clear cookies or wait for the session to expire.
