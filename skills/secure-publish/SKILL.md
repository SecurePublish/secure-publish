---
name: secure-publish
description: >-
  Publish an AI HTML dashboard with Secure Publish so only people on the
  company email domain (after sign-in) — or an explicit --to email list — can
  open it. Use when the user asks to publish, share, or host an HTML
  dashboard/panel for their company, or to restrict it to specific emails.
  V1 is email-domain access, not Workspace/Entra/GitHub Org membership.
---

# Secure Publish

There is no web “publish” button. The console only tracks URLs and views.

Install the skill (already used by the landing):

```text
npx skills add https://github.com/clovistx/secure-publish --skill "secure-publish"
```

Run the CLI from this repo (not the public npm package named `secure-publish` — that is a different project). Do **not** run `npm install -g secure-publish` or `npx secure-publish`. Use only:

```bash
npx --yes github:clovistx/secure-publish
```

User prompts this skill handles:

- PT: *Publique este dashboard HTML com Secure Publish.*
- EN: *Publish this HTML dashboard with Secure Publish.*
- PT: *Publique este HTML pra toda a empresa.*
- PT: *Publique só para clovis@wises.com.br e ana@wises.com.br.*
- EN: *Publish this HTML for the whole company.*
- EN: *Publish only to jane@acme.com.*

## What you say

Say only these lines about sign-in and publish. Do not explain the mechanism.

If this machine is not signed in yet, say exactly:

> Vou abrir o login. Entra com a conta da empresa na página que abrir (Google, GitHub ou Microsoft) — a conta fica ligada nesta máquina.

Then run `npx --yes github:clovistx/secure-publish login` and wait. When it finishes, say exactly:

> Conta ligada. Publicando em {host}, aberto pra empresa.

Use the host the command printed. If there is no host yet, ask where to publish. Do not invent one.

Then publish:

```bash
npx --yes github:clovistx/secure-publish publish ./dashboard.html --title "Painel"
npx --yes github:clovistx/secure-publish publish ./dashboard.html --to clovis@wises.com.br,ana@wises.com.br
```

Company-wide means the same email domain as the signed-in account. If they did not say who can see it, ask once:

> Quer restringir a alguém? Passe os e-mails (senão fica aberto pra empresa — mesmo domínio de e-mail).

On success, say exactly (do not invent `{url}` — only the url the command printed):

> Publicado pra **toda a empresa**: {url}

If they passed emails:

> Publicado só para {emails}: {url}

On any failure, say exactly:

> Não consegui publicar agora. A conta está ligada em {host}. Tenta de novo em instantes.

If the command says the account is not linked, go back to the login line. Never ask them for an infrastructure secret.

## Access (V1)

| UI label | Command | What it actually checks |
|----------|---------|-------------------------|
| Toda a empresa / Whole company | default (no `--to`) | Email **domain** after sign-in. Example: `@wises.com.br`. |
| Só estas pessoas / Only these people | `--to a@x,b@y` | Explicit email list. Still requires sign-in. |

- Same domain as the account is the default when `--to` is omitted.
- This is **not** Google Workspace, Microsoft Entra, or GitHub Org membership.
- A personal account on the same domain can pass a domain-only policy. Say so if asked.
- `--to` stays the flag name.

## Errors (user-facing)

| Situation | PT | EN |
|-----------|----|----|
| Email not on company domain | Seu e-mail não é do domínio desta empresa. Peça acesso ou use a conta corporativa. | Your email isn’t on this company’s domain. Ask for access or use your work account. |
| Signed in, no permission | Você está logado, mas não tem permissão neste dashboard. | You’re signed in, but you don’t have access to this dashboard. |
| Missing emails when they asked for a list | Inclua pelo menos um e-mail | Add at least one email |

## Do not claim

1. A “Continuar como …” screen on the landing/demo proves the *flow*; it authenticates nobody.
2. Do not imitate the Google window. No logos or brand colors on a fake sign-in.
3. The panel URL is not a credential. Without sign-in, the page does not return the HTML.
4. A domain list is not org membership.
5. Do not claim E2E encryption, compliance/SOC2, “nobody ever leaks”, or a waitlist that already saved the email.

Do not use: gate, gated, waitlist, early access, “SSO coming soon”, compliance, E2E, zero trust, “org member”, “Workspace membership”.
