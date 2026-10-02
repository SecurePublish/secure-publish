# Deploy wildcard `*.securepublish.work`

After GoDaddy NS for `securepublish.work` show **Active** in Cloudflare DNS.

## 1. Attach the Worker to the zone

**Dashboard (preferred)**

1. [Workers & Pages](https://dash.cloudflare.com) → worker **`secure-publish`**.
2. **Settings → Domains & Routes → Add**  
   - Custom Domain: `*.securepublish.work` (wildcard)  
   - Optional apex: `securepublish.work` if you want apex to hit the Worker too  
   (Usually apex/`www` stay on **Pages** for the landing; panel hosts use the wildcard.)
3. Confirm CF created the proxy records in DNS.

**Or wrangler**

Uncomment the `[[routes]]` blocks in `packages/edge/wrangler.toml`, then:

```bash
cd packages/edge
npx wrangler deploy
```

Interim host stays up: `https://secure-publish.clovist.workers.dev` (`workers_dev = true`).

## 2. Console origin + CORS

Set Worker var `CONSOLE_ORIGIN` (comma-separated, exact origins):

```text
https://app.securepublish.work,https://secure-publish-app.pages.dev,http://127.0.0.1:8765
```

```bash
cd packages/edge
npx wrangler deploy   # picks up [vars] from wrangler.toml
# or: npx wrangler versions secret / dashboard → Variables
```

Point Pages custom domain `app.securepublish.work` at the console project. Update OAuth redirect URIs if the Worker host changes (Google/MS/GitHub still call back on the **Worker** host: `/_auth/callback/{provider}`).

## 3. CLI base URL

| Phase | `SECURE_PUBLISH_BASE_URL` | Example panel URL |
|-------|---------------------------|-------------------|
| Interim (now) | `https://secure-publish.clovist.workers.dev` | `https://secure-publish.clovist.workers.dev/{id}` |
| After wildcard | `https://{slug}.securepublish.work` (tenant host) or keep workers.dev | `https://{slug}.securepublish.work/{id}` |

```bash
export SECURE_PUBLISH_BASE_URL=https://secure-publish.clovist.workers.dev
# later:
# export SECURE_PUBLISH_BASE_URL=https://acme.securepublish.work
```

## 4. Publish E2E checklist (needs `CLOUDFLARE_API_TOKEN`)

Token is issued by John/ops — **never invent or commit secrets**.

```bash
export CLOUDFLARE_API_TOKEN=…          # from John — not in git
export CLOUDFLARE_ACCOUNT_ID=…
export SECURE_PUBLISH_KV_NAMESPACE_ID=46d61ee3d1f7410fa081e383b776934a
export SECURE_PUBLISH_BASE_URL=https://secure-publish.clovist.workers.dev
export SECURE_PUBLISH_COMPANY_DOMAINS=wises.com.br

node packages/cli/bin/secure-publish.js doctor
# expect: token verify OK

node packages/cli/bin/secure-publish.js publish examples/panel-vendas.html \
  --title "E2E wildcard"
# note the printed URL → PANEL_URL

# No session → must NOT serve panel HTML
curl -sI "$PANEL_URL" | head -5
# OAuth mode (current): HTTP/2 302 → /_auth/login?return_to=…
# Access / none mode:   HTTP 403
# /api/me without cookie → 401 {"error":"unauthorized"}
# Body of GET /$PANEL_ID must be empty (0 bytes) before login.

# With SSO session cookie (browser after Google login) → 200 + HTML
# Or Access JWT header if using Cloudflare Access.
```

Without a token, use mock only:

```bash
SECURE_PUBLISH_MOCK=1 node packages/cli/bin/secure-publish.js doctor
npm run e2e:mock
```

## 5. Still blocked without

- `CLOUDFLARE_API_TOKEN` (KV PUT from CLI)
- Active NS / custom domain attach (pretty `*.securepublish.work` URLs)
- GitHub / Microsoft OAuth apps (Google already live)
