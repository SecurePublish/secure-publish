# Console ↔ Worker API contract (V1)

Cameron console (`/workspace/secure-publish-app/`) calls these when `window.SP_API_BASE` is set (or `?api=`). Default = **stub** (no backend).

Auth: session cookie from OAuth (same-site / CORS credentials).

| Method | Path | Notes |
|--------|------|--------|
| GET | `/api/me` | `{ email, idp, domain, host }` |
| POST | `/api/panels` | SSO cookie **or** `Authorization: Bearer` publish credential (not a browser cookie). Body `{ html, title?, to? }`. Default access = company (session email domain). `201 { ok, id, url, host, mode, allowlist, title, publishedAt }` with `url` = `https://{host}/{id}`. `409 no_host` if the account has no host. `413 html_too_large` over 1.5MB. `401` with no session. Publisher is always the signed-in account. |
| POST | `/api/device/code` | No session. Starts a one-time login. `{ device_code, verification_url, expires_in, interval }` |
| POST | `/api/device/token` | No session. Poll with `{ device_code }`. Pending: `authorization_pending`. Once: `{ access_token, token_type: Bearer, email, host, expires_in }` (12h, publish-only). Replay: `expired_token`. |
| POST | `/api/device/bind` | SSO only. Account owner links the one-time code. Single-use. |
| POST | `/api/session/revoke` | `Authorization: Bearer` drops that publish credential. |
| GET | `/api/panels?scope=mine\|company` | `{ host, panels: [{ id, publisherEmail, mode: company\|allowlist, allowlist[], publishedAt, publishedLabel?, views, viewers: [{email,first,last}] }] }` |
| PATCH | `/api/panels/:id/access` | body `{ mode, allowlist[], sendInvite? }` — publisher only |
| PUT | `/api/hosting/subdomain` | `{ slug }` → `{ host }` |
| PUT | `/api/hosting/custom` | `{ hostname }` → `{ host, customHostname, customVerified:false, verify:{ type:"txt", name, value } }` — claim only; TXT `_secure-publish.<host>` = `sp-verify=<email>`; serving host unchanged until verified |
| POST | `/api/hosting/custom/verify` | no body required → DoH TXT lookup; success `{ ok, host, customHostname, customVerified:true, verify }` (sets `host` to custom hostname); errors `no_custom_hostname` 400, `txt_not_found`/`txt_mismatch` 422, `dns_lookup_failed` 502 — never fakes success |
| GET | `/auth/{google\|microsoft\|github}` | OAuth start (Miles/John) |
| GET\|POST | `/auth/logout` | Clear `secure_publish_session` (same Path/SameSite/Secure/Domain as login) → 302 first `CONSOLE_ORIGIN` + `/signup/` (ignores `?next=`; `Cache-Control: no-store`) |

Lock A: `mode=company` = same email domain after SSO. Not Workspace/Entra/GitHub Org membership.
