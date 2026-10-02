---
name: secure-publish
description: >-
  Publish an AI HTML dashboard with Secure Publish so only people on the
  company email domain (after SSO) — or an explicit --to email list — can open
  it. Use when the user asks to publish, share, or host an HTML dashboard/panel
  for their company, or to restrict it to specific emails. V1 is email-domain
  ACL, not Workspace/Entra/GitHub Org membership.
---

# Secure Publish

Agent-first path: link an account, pick hosting, publish HTML. There is no web “publish” button. The console only tracks URLs and views.

Install (already used by the landing):

```text
npx skills add https://github.com/clovistx/secure-publish --skill "secure-publish"
```

User prompts this skill handles:

- PT: *Publique este dashboard HTML com Secure Publish.*
- EN: *Publish this HTML dashboard with Secure Publish.*
- PT: *Publique este HTML pra toda a empresa.*
- PT: *Publique só para clovis@wises.com.br e ana@wises.com.br.*
- EN: *Publish this HTML for the whole company.*
- EN: *Publish only to jane@acme.com.*

## What you do

1. **Account.** If the user has no linked Secure Publish account, say (PT):

   > Você ainda não tem conta Secure Publish. Vou abrir o cadastro — entre com Google, Microsoft ou GitHub (e-mail da empresa).

   EN: *You don’t have a Secure Publish account yet. I’ll open signup — use Google, Microsoft, or GitHub (company email).*

   Open signup (product URL when live). After they start, say:

   > Depois de criar a conta, volto aqui. Código de vínculo: {code}

   EN: *After you create the account, I’ll continue here. Link code: {code}*

   When linked: **Conta vinculada.** / *Account linked.*

2. **Hosting.** If no host is set:

   > Onde publicar? Posso reservar {slug}.securepublish.work ou você usa um domínio próprio.

   EN: *Where should we host? I can reserve {slug}.securepublish.work or you can use a custom domain.*

3. **Publish** with the CLI (from the repo or global bin):

   ```bash
   # whole company = same email domain as the tenant (V1 default)
   secure-publish publish ./dashboard.html --title "Painel"

   # restrict to specific people (flag name is --to)
   secure-publish publish ./dashboard.html --to clovis@wises.com.br,ana@wises.com.br
   ```

   Before publishing, if they didn’t say who can see it, ask:

   > Quer restringir a alguém? Passe os e-mails (senão fica aberto pra empresa — mesmo domínio de e-mail).

   EN: *Want to restrict access? Pass emails (otherwise it’s open to the company — same email domain).*

4. **Tell them the result** (do not invent a URL):

   - Company default: `Publicado pra **toda a empresa**: {url}` / *Published for the **whole company**: {url}*
   - Allowlist: `Publicado só para {emails}: {url}` / *Published only for {emails}: {url}*

## ACL (V1 Lock A) — do not claim org membership

| UI label | CLI | What it actually checks |
|----------|-----|-------------------------|
| Toda a empresa / Whole company | default (no `--to`); metadata mode `company` or `org` | Email **domain** allowlist after SSO (`OAUTH_ALLOWED_DOMAINS` / tenant domain). Example: `@wises.com.br`. |
| Só estas pessoas / Only these people | `--to a@x,b@y` | Explicit email allowlist. Still requires sign-in. |

- Same domain as the tenant is the default when `--to` is omitted.
- This is **not** Google Workspace, Microsoft Entra, or GitHub Org membership. That is a later phase.
- A personal account on the same domain can pass a domain-only policy. Say so if asked.
- `--to` stays the flag name. Do not rename it to `--allow` or `--org`.

## Errors (user-facing)

| Situation | PT | EN |
|-----------|----|----|
| Email not on company domain | Seu e-mail não é do domínio desta empresa. Peça acesso ou use a conta corporativa. | Your email isn’t on this company’s domain. Ask for access or use your work account. |
| Signed in, no permission (other dashboard / allowlist) | Você está logado, mas não tem permissão neste dashboard. | You’re signed in, but you don’t have access to this dashboard. |
| Missing `--to` emails when they asked for a list | Inclua pelo menos um e-mail | Add at least one email |

## Security checklist (mock ≠ product)

1. **Mock ≠ SSO.** A “Continuar como …” screen on the landing/demo proves the *flow*; it authenticates nobody. Never say “real Google/Microsoft/GitHub login” about that page.
2. **Do not imitate IdP UI.** No logos, brand colors, or a fake Google window. Use a generic “Continuar como …” plus a visible label: *Demo do fluxo · não é login de verdade*.
3. **The panel URL is not a credential.** `/{panel-id}` only identifies HTML in KV. Without an SSO session (Access JWT or OAuth cookie), the Worker returns 403 — even with the URL.
4. **Domain allowlist ≠ org membership.** `OAUTH_ALLOWED_DOMAINS` (email `@empresa.com`) or an Access “emails ending in” policy is a **domain allowlist**. It does **not** check Google Workspace / Entra / GitHub Org membership. A personal account on the same domain can pass if the policy is only “authenticated” plus domain.
5. **Do not claim:** E2E encryption, compliance/SOC2, “nobody ever leaks”, “compatible with IdP X” before that IdP’s OAuth/Access is actually connected, a waitlist that “already saved the email” without real storage, or `SSO_DEV_BYPASS` / mock auth in production.

## Ban list (copy)

Do not use: gate, gated, waitlist, early access, “SSO coming soon”, “copie e rode agora” as if production install were already live, compliance, E2E, zero trust, “org member”, “Workspace membership”, “Entra member”, “GitHub Org member” as a V1 guarantee.

## Local mock (no Cloudflare)

```bash
export SECURE_PUBLISH_MOCK=1
export SECURE_PUBLISH_COMPANY_DOMAINS=empresa.com
node packages/cli/bin/secure-publish.js publish examples/panel-vendas.html --title "Painel Vendas Q3"
node packages/cli/bin/secure-publish.js mock-serve --port 8787
# another shell:
curl -D- -H 'X-Mock-User: ana@empresa.com' http://127.0.0.1:8787/<key>
```

`X-Mock-User` simulates a signed-in session. It is not SSO. Never enable mock auth in production.
