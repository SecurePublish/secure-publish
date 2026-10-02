# Console ↔ Worker API contract (V1)

Cameron console (`/workspace/secure-publish-app/`) calls these when `window.SP_API_BASE` is set (or `?api=`). Default = **stub** (no backend).

Auth: session cookie from OAuth (same-site / CORS credentials).

| Method | Path | Notes |
|--------|------|--------|
| GET | `/api/me` | `{ email, idp, domain, host }` |
| GET | `/api/panels?scope=mine\|company` | `{ host, panels: [{ id, publisherEmail, mode: company\|allowlist, allowlist[], publishedAt, publishedLabel?, views, viewers: [{email,first,last}] }] }` |
| PATCH | `/api/panels/:id/access` | body `{ mode, allowlist[], sendInvite? }` — publisher only |
| PUT | `/api/hosting/subdomain` | `{ slug }` → `{ host }` |
| PUT | `/api/hosting/custom` | `{ hostname }` → `{ host }` |
| GET | `/auth/{google\|microsoft\|github}` | OAuth start (Miles/John) |
| GET\|POST | `/auth/logout` | Clear `secure_publish_session` → 302 to first `CONSOLE_ORIGIN` + `/signup/` (or allowlisted `?next=`) |

Lock A: `mode=company` = same email domain after SSO. Not Workspace/Entra/GitHub Org membership.
