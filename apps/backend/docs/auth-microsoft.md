# Microsoft (Entra ID) Authentication

Sign in to nao with a Microsoft work/school or personal account via OAuth 2.0 (OIDC).

## Prerequisites

- Admin access to an Azure / Entra ID tenant (or a personal Azure account for testing).
- nao backend running and reachable at a known URL (e.g. `http://localhost:5005` or your production host).

## Azure Portal Setup

1. Go to **Azure Portal > Microsoft Entra ID > App registrations > New registration**.
2. Name: e.g. `nao`.
3. Supported account types: choose the option that matches your tenant configuration (see Tenant ID table below).
4. Redirect URI: select **Web**, enter:
   ```
   https://<your-nao-host>/auth/callback/microsoft
   ```
   For local development: `http://localhost:5005/auth/callback/microsoft`.
5. Click **Register**.
6. On the app overview page, copy the **Application (client) ID**.
7. Go to **Certificates & secrets > New client secret**, create one, and copy the **Value** (not the Secret ID).
8. Go to **API permissions**, confirm these are present (they are added by default):
   - `openid`
   - `profile`
   - `email`
   - `User.Read`

## Environment Variables

Add these to your `.env` file at the repository root:

| Variable | Required | Description |
|---|---|---|
| `MICROSOFT_CLIENT_ID` | Yes | Application (client) ID from Azure |
| `MICROSOFT_CLIENT_SECRET` | Yes | Client secret value |
| `MICROSOFT_TENANT_ID` | No | See table below. Defaults to `organizations`. |
| `MICROSOFT_AUTH_DOMAINS` | No | Comma-separated email domain allowlist. Empty = allow all. |

When both `MICROSOFT_CLIENT_ID` and `MICROSOFT_CLIENT_SECRET` are set, a "Continue with Microsoft" button appears on the login page.

## Tenant ID Selection

| Value | Who can sign in | Use case |
|---|---|---|
| `<your-tenant-uuid>` | Only users from your specific Entra ID tenant | Production single-tenant deployments. **Recommended for enterprise.** The tenant UUID restricts the OAuth flow at the IdP layer, so tokens from other tenants are rejected before they reach nao. |
| `organizations` (default) | Any work/school Microsoft account | Multi-tenant SaaS deployments. Combine with `MICROSOFT_AUTH_DOMAINS` to restrict by email domain. |
| `common` | Any Microsoft account (work/school + personal) | Open access. Use with caution. |
| `consumers` | Personal Microsoft accounts only (Outlook, Xbox, etc.) | Uncommon for enterprise use. |

## Domain Allowlist

Set `MICROSOFT_AUTH_DOMAINS` to restrict which email domains are accepted:

```env
MICROSOFT_AUTH_DOMAINS=mycompany.com,subsidiary.org
```

- Comparison is case-insensitive.
- An empty or unset value allows all domains.
- This is applied **in addition to** the tenant restriction, not instead of it.

## IdP Federation

If your Entra ID tenant federates authentication to an IdP (ADFS, Okta, Ping, OneLogin, ...), users who click "Continue with Microsoft" will be redirected through the IdP transparently. This is handled entirely by Microsoft's authorization flow — no nao-side configuration is needed.

## Account Linking

If a user signs in via Microsoft with the same email as an existing Google or email/password account, better-auth will link the accounts (same user row, new account row) provided the email is verified by both providers. This is the default behavior configured in `apps/backend/src/auth.ts` via `account.accountLinking`.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "Continue with Microsoft" button not visible | `MICROSOFT_CLIENT_ID` or `MICROSOFT_CLIENT_SECRET` not set | Check `.env` and restart the backend |
| `redirect_uri mismatch` error from Microsoft | Redirect URI in Azure doesn't match | Ensure the URI in Azure App Registration exactly matches `<BETTER_AUTH_URL>/auth/callback/microsoft` |
| `AADSTS50011` or `unauthorized_client` | App registration not configured for the chosen tenant type | Re-check "Supported account types" in Azure matches your `MICROSOFT_TENANT_ID` value |
| `This email domain is not authorized` | Email domain blocked by `MICROSOFT_AUTH_DOMAINS` | Add the domain to the allowlist or clear the variable |
| Sign-in works but user can't see any projects | User was created but not added to a project | In self-hosted mode, social sign-ups are automatically added to the default project. Check that `NAO_DEFAULT_PROJECT_PATH` is set. |
