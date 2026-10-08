# `@secure-publish/edge`

Cloudflare Worker: panel HTML (`GET /:id`) + **console API** matching Cameron’s contract.

Contract (source of truth): [`docs/API-CONTRACT.md`](../../docs/API-CONTRACT.md)  
(in-repo copy / pointer: see root README). Console client: `secure-publish-app/api.js`.

## Endpoints

| Method | Path | Notes |
|--------|------|--------|
| GET | `/api/me` | `{ email, idp, domain, host, customHostname, customVerified }` (+ `verify` when pending) — SSO required |
| GET | `/api/panels?scope=mine\|company` | `{ host, panels: [{ id, title, … }] }` — SSO; `title` fallback `"untitled"`; `viewers[]` only after auth |
| PATCH | `/api/panels/:id/access` | `{ mode, allowlist[], sendInvite? }` — **publisher only** |
| PUT | `/api/hosting/subdomain` | `{ slug }` → `{ host }`. `400 reserved_slug` for product/infra names |
| PUT | `/api/hosting/custom` | `{ hostname }` → claim; TXT `sp-verify=<opaque-token>`; **not served until verified** |
| DELETE | `/api/hosting/custom` | clear **unverified** pending claim only (`404` / `409` if none / verified) |
| POST | `/api/hosting/custom/verify` | DoH TXT `_secure-publish.<host>` = stored opaque token → `customVerified` + switch `host` |
| GET | `/auth/providers` | `{ providers }` — configured IdPs (client id+secret); public, CORS+credentials |
| GET | `/auth/{google\|microsoft\|github}` | OAuth start (`?next=` → return); callback pinned to `app.securepublish.work` |
| GET\|POST | `/auth/logout` | Clear `secure_publish_session` with **same** Path/SameSite/Secure/Domain as login → 302 first `CONSOLE_ORIGIN` + `/signup/` (idempotent; ignores `?next=`; `cache-control: no-store`) |
| GET | `/:panelId` | HTML after SSO + ACL (Lock A). Session cookie `Domain=.securepublish.work` from console login is accepted on panel hosts. |

### Marcus checklist

1. Every `/api/*` requires SSO session (401 without cookie / Access JWT).
2. `PATCH …/access` = publisher only (403 otherwise).
3. CORS = exact `CONSOLE_ORIGIN` (comma-separated) + `credentials`.
4. `viewers[]` is PII — only returned on authenticated `/api/panels`.
5. Custom domain: reserved via API; Host gate blocks serving until `customVerified`.

Lock A: `mode=company` = email **domain** after SSO (not Workspace/Entra/GitHub Org).

`sendInvite?` logs a stub — does **not** claim email sent.

## KV shape (`PANELS`)

| Key | Value |
|-----|--------|
| `{24-hex-id}` | `{ v, title, publishedAt, publisherEmail, access, html }` |
| `idx:pub:{email}` | `string[]` panel ids |
| `idx:domain:{domain}` | `string[]` panel ids |
| `view:{id}` | `{ count, byEmail: { email: { first, last } } }` |
| `tenant:user:{email}` | hosting prefs |
| `host:sub:{slug}` / `host:custom:{hostname}` | owner email lock |

CLI publish should set `publisherEmail` + indexes (see `packages/cli`). Legacy bare records still serve HTML; console list falls back to KV scan.

## Local run

```bash
cd packages/edge
npm install
npm test

# Dev Worker (local only — opt-in bypass, never default):
# Create .dev.vars (gitignored) with e.g.:
#   SSO_DEV_BYPASS=1
#   CONSOLE_ORIGIN=http://127.0.0.1:5500
#   OAUTH_ALLOWED_DOMAINS=localhost
npx wrangler dev
```

Production: set secrets with `wrangler secret put` (no secrets in repo). Do **not** set `SSO_DEV_BYPASS`.

```bash
npx wrangler secret put SESSION_SECRET
npx wrangler secret put GOOGLE_CLIENT_ID
# …
# vars: CONSOLE_ORIGIN, OAUTH_ALLOWED_DOMAINS
npx wrangler deploy
```

## Gaps (John / ops)

- OAuth client IDs/secrets + redirect URIs (`/_auth/callback/{provider}`).
- DNS: `*.securepublish.work` → Worker; custom domain: TXT `_secure-publish.{host}=sp-verify=<opaque-token>` then `POST /api/hosting/custom/verify`; CNAME de tráfego (`cname.securepublish.work`) TBD (John/CF). Legacy email-in-TXT claims need re-claim.
- Email provider for `sendInvite`.
- Cloudflare Access (`TEAM_DOMAIN` + `POLICY_AUD`) if preferred over Worker OAuth.
