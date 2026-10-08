# Console ↔ Worker API contract (V1)

Cameron console (`/workspace/secure-publish-app/`) calls these when `window.SP_API_BASE` is set (or `?api=`). Default = **stub** (no backend).

Auth: session cookie from OAuth (same-site / CORS credentials).

| Method | Path | Notes |
|--------|------|--------|
| GET | `/api/me` | `{ email, idp, domain, publicDomain, host, customHostname, customVerified }` — `publicDomain` is `true` when the session email domain is on the Worker public-mailbox list (exact match, case-insensitive). `host` is the serving host only (verified custom or subdomain), never `""`. When a custom hostname is claimed but not verified (`customHostname` set and `customVerified` false), also includes `verify: { type:"txt", name, value }` with the opaque TXT challenge so Hosting can re-show Name/Value without re-claiming. |
| POST | `/api/panels` | SSO cookie **or** `Authorization: Bearer` publish credential (not a browser cookie). Body `{ html, title?, to? }`. Default access = company (session email domain). `201 { ok, id, url, host, mode, allowlist, title, publishedAt }` with `url` = `https://{host}/{id}`. `400 company_requires_work_domain` if the publisher's email domain is public and the body has no email allowlist (`to` / company mode) — nothing written to KV. Allowlist (`to`) still works for public-domain accounts. `409 no_host` if the account has no host. `413 html_too_large` over 1.5MB. `401` with no session. Publisher is always the signed-in account. |
| POST | `/api/device/code` | No session. Starts a one-time login. `{ device_code, verification_url, expires_in, interval }` |
| POST | `/api/device/token` | No session. Poll with `{ device_code }`. Pending: `authorization_pending`. Once: `{ access_token, token_type: Bearer, email, host, expires_in }` (12h, publish-only). Replay: `expired_token`. |
| POST | `/api/device/bind` | SSO only. Account owner links the one-time code. Single-use. |
| POST | `/api/session/revoke` | `Authorization: Bearer` drops that publish credential. |
| GET | `/api/panels?scope=mine\|company` | `{ host, panels: [{ id, title, publisherEmail, mode: company\|allowlist, allowlist[], publishedAt, publishedLabel?, views, viewers: [{email,first,last,firstAt,lastAt}] }] }` — `title` from panel record, fallback `"untitled"`. `firstAt`/`lastAt` are ISO 8601 UTC (`2026-10-07T00:47:12.000Z` or `null` if empty/invalid); the console formats them. `first`/`last` are legacy time-only labels (`HH:mm` pt-BR). `scope=company` does **not** list `mode: company` panels whose company domain is a public mailbox domain. |
| PATCH | `/api/panels/:id/access` | body `{ mode, allowlist[], sendInvite? }` — publisher only. `400 company_requires_work_domain` when `mode: company` and the publisher's email domain is public — nothing written. |
| PUT | `/api/hosting/subdomain` | `{ slug }` → `{ host }`. `400 reserved_slug` for product/infra names (case-insensitive; nothing written). `400 invalid_slug`. `409 subdomain_taken` |
| PUT | `/api/hosting/custom` | `{ hostname }` → `{ host, customHostname, customVerified:false, verify:{ type:"txt", name, value } }` — claim only; TXT `_secure-publish.<host>` = `sp-verify=<opaque-token>` (not owner email); serving host unchanged until verified |
| DELETE | `/api/hosting/custom` | SSO required; session owner only. Clears an **unverified** pending claim (`host:custom:*` lock + `customHostname` / `customVerified` / `customVerifyToken` on tenant). Does **not** change serving subdomain `host`/`slug`. `{ ok: true }`. `404 no_pending_custom_hostname` if none pending; `409 custom_already_verified` if already verified (use host-switch flow). |
| POST | `/api/hosting/custom/verify` | no body required → DoH TXT lookup against stored opaque token; success `{ ok, host, customHostname, customVerified:true, verify }` (sets `host` to custom hostname); errors `no_custom_hostname` 400, `reclaim_required` 409 (legacy email-TXT claims), `txt_not_found`/`txt_mismatch` 422, `dns_lookup_failed` 502 — never fakes success |
| GET | `/auth/providers` | `{ providers: ["google", ...] }` — public; only IdPs with both CLIENT_ID and CLIENT_SECRET. CORS + credentials like `/api/*`. Console `/signup/` and `/login/` call this to choose SSO buttons. |
| GET | `/auth/{google\|microsoft\|github}` | OAuth start (Miles/John); callback pinned to `app.securepublish.work` so session cookie is `Domain=.securepublish.work` |
| GET\|POST | `/auth/logout` | Clear `secure_publish_session` (same Path/SameSite/Secure/Domain as login) → 302 first `CONSOLE_ORIGIN` + `/signup/` (ignores `?next=`; `Cache-Control: no-store`) |

Lock A: `mode=company` = same email domain after SSO. Not Workspace/Entra/GitHub Org membership.

Public mailbox domains (Worker `PUBLIC_EMAIL_DOMAINS`, exact match): company publish and `PATCH` `mode: company` return `400 {"error":"company_requires_work_domain"}`. Existing `mode: company` panels whose company domain is public return **403** to everyone except the panel's `publisherEmail`. Same-domain viewers are not exempt.
