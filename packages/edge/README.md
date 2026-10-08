# `@secure-publish/edge`

Cloudflare Worker: panel HTML (`GET /:id`) + **console API** matching Cameron’s contract. `/api/*` is served only on the app host.

Contract (source of truth): [`docs/API-CONTRACT.md`](../../docs/API-CONTRACT.md)  
(in-repo copy / pointer: see root README). Console client: `secure-publish-app/api.js`.

## Endpoints

| Method | Path | Notes |
|--------|------|--------|
| GET | `/api/me` | `{ email, idp, domain, host, customHostname, customVerified, customDomainsEnabled }` (+ `customStatus` / `customRecords` when a claim exists and the flag is on) — SSO required |
| GET | `/api/panels?scope=mine\|company` | `{ host, panels: [{ id, title, … }] }` — SSO; `title` fallback `"untitled"`; `views` for every listed panel; **`viewers[]` publisher-only** (omitted unless session email === `publisherEmail`) |
| PATCH | `/api/panels/:id/access` | `{ mode, allowlist[], sendInvite? }` — **publisher only** |
| PUT | `/api/hosting/subdomain` | `{ slug }` → `{ host }`. `400 reserved_slug` for product/infra names |
| PUT | `/api/hosting/custom` | `{ hostname }` → pending claim (per-account TXT token, **no** exclusive lock, no Cloudflare call). Flag off → `403 custom_domains_disabled`. Relative DNS `records`. Host already `active`/`records_missing` for another account → `409 hostname_taken`. |
| DELETE | `/api/hosting/custom` | owner only: delete CF custom hostname (if any) + KV lock + claim fields |
| POST | `/api/hosting/custom/verify` | DoH TXT then Cloudflare for SaaS create/status. `200 { status, records, customHostname }`. Same TXT-recheck as the daily cron. |
| GET | `/auth/handoff` | `app.securepublish.work` only: mint one-time host-bound code (stores SHA-256 of `__Host-sp_handoff` nonce). Elsewhere → identical panel 404. |
| GET | `/_auth/handoff` | Verified customer host only: cookie hash + Host must match; set `__Host-sp_session`, clear handoff cookie, 302. Failure → 403 (HTML if `Accept` includes `text/html`). Elsewhere → identical panel 404. |
| GET | `/auth/providers` | `{ providers }` — configured IdPs (client id+secret); public, CORS+credentials |
| GET | `/auth/{google\|microsoft\|github}` | OAuth start (`?next=` → return); callback pinned to `app.securepublish.work` |
| GET\|POST | `/auth/logout` | Custom host: clear `__Host-sp_session` then app `/auth/logout`. Zone hosts: clear `secure_publish_session` → 302 first `CONSOLE_ORIGIN` + `/signup/` |
| GET | `/:panelId` | HTML after SSO + ACL (Lock A). Custom host needs `__Host-sp_session` (handoff). Subdomain cookie `Domain=.securepublish.work`. |

### Marcus checklist

1. Every `/api/*` requires SSO session (401 without cookie / Access JWT).
2. `PATCH …/access` = publisher only (403 otherwise).
3. CORS = exact `CONSOLE_ORIGIN` (comma-separated, `new URL().origin`) + `credentials`.
4. `viewers[]` is PII — publisher-only (session email equals `publisherEmail`). Colleagues still get `views` + `path`.
5. Custom domain: reserved via API; Host gate serves only when `customVerified` **and** `customStatus === "active"` (never trust Cloudflare status alone). Unknown/unverified hosts return the same 404 body as an unknown panel id.
6. `/api/*` only when `Host` is the app host (`APP_HOST` or `OAUTH_CALLBACK_ORIGIN`). Other hosts: same 404 as an unknown path.
7. Cookie mutations (`POST`/`PATCH`/`PUT`/`DELETE`): exact console `Origin` + `Content-Type: application/json`. Else `403 csrf_origin` / `csrf_content_type`. Bearer and `/api/device/code|token` exempt; `/api/device/bind` is not.

Lock A: `mode=company` = email **domain** after SSO (not Workspace/Entra/GitHub Org).

### SSO

GitHub OAuth uses `/user/emails` (`user:email` scope) only — never the public `/user` email. Only `verified: true` addresses; the first whose domain is an exact (case-insensitive) member of `OAUTH_ALLOWED_DOMAINS` is chosen; otherwise the primary verified email. If `/user/emails` errors or has no verified entry, login is denied (403, no session). `users.noreply.github.com` (and subdomains) never count as an allowed match. Session emails are stored lowercase for every IdP.

**Known risk:** GitHub does not re-verify emails, so someone who left the company but keeps a verified @company email on GitHub can still sign in via GitHub even after their Google account is disabled. Accepted for now given the small audience; mitigation if needed later is requiring Google for company mode.

`sendInvite?` logs a stub — does **not** claim email sent.

## KV shape (`PANELS`)

| Key | Value |
|-----|--------|
| `{24-hex-id}` | `{ v, title, publishedAt, publisherEmail, access, html }` |
| `idx:pub:{email}` | `string[]` panel ids |
| `idx:domain:{domain}` | `string[]` panel ids |
| `view:{id}` | `{ count, byEmail: { email: { first, last } } }` |
| `tenant:user:{email}` | hosting prefs (`customHostname`, `customVerified`, `customStatus`, `customVerifyToken`, `customCfId`) |
| `host:sub:{slug}` / `host:custom:{hostname}` | owner email lock (`host:custom` written only at `active`, kept through `records_missing`, no TTL) |
| `handoff:{code}` | one-time custom-host session code (TTL 60s, hostname + nonce hash) |

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
npx wrangler secret put CF_SAAS_TOKEN   # zone-scoped; SSL and Certificates: Edit
# …
# vars in wrangler.toml:
#   CONSOLE_ORIGIN, OAUTH_ALLOWED_DOMAINS
#   CF_ZONE_ID = "397f24981bc11c467ae86b5ee71a43e1"   (zone securepublish.work)
#   CUSTOM_DOMAINS_ENABLED = "false"                  # set "true" to launch
# Cron trigger (daily TXT recheck): wrangler.toml [triggers] crons
npx wrangler deploy
```

`CF_SAAS_TOKEN` must never be logged or returned. Fallback origin `cname.securepublish.work` is the Custom Hostnames target. Zone route `*/*` sends every host (including customer CNAMEs) to this Worker; apex `securepublish.work` and `www` stay on Pages.

KV `handoff:{code}` is read then deleted; that is **not strictly atomic** (60s TTL, hostname-bound, CSRF-bound to a SHA-256 of `__Host-sp_handoff`). Pages never set session cookies — only this Worker. `/api/*` is not served on customer hosts; `__Host-sp_session` is never accepted for `api: true` SSO.

Customer DNS (names relative to their registrable domain):

- CNAME `share` → `cname.securepublish.work`
- TXT `_secure-publish.share` → `sp-verify=<opaque per-account token>`

## Gaps (John / ops)

- OAuth client IDs/secrets + redirect URIs (`/_auth/callback/{provider}`).
- Flip `CUSTOM_DOMAINS_ENABLED` to `"true"` after security review. Daily cron plus `POST /api/hosting/custom/verify` share one TXT-recheck (QA can re-run verify; no admin endpoint).
- Email provider for `sendInvite`.
- Cloudflare Access (`TEAM_DOMAIN` + `POLICY_AUD`) if preferred over Worker OAuth.
