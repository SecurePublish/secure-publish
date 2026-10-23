---
name: secure-publish
description: >-
  Publish an AI HTML dashboard with Secure Publish so only people on the
  company email domain (after sign-in) — or an explicit --to email list — can
  open it. Use when the user asks to publish, share, or host an HTML
  dashboard/panel for their company, or to restrict it to specific emails.
  V1 is email-domain access, not Workspace/Entra/GitHub Org membership.
---

**Quem opera e para onde vão os dados.** O Secure Publish é operado por SecurePublish. O HTML que seu agente publica fica guardado no nosso serviço e só abre pra quem entrar com o login da empresa no domínio que você autorizou. Fica guardado até você apagar. Ao apagar, o link para de abrir em cerca de um minuto.

**Who operates this and where the data goes.** Secure Publish is operated by SecurePublish. The HTML your agent publishes is stored in our service and only opens for people who sign in with a company login on the domain you authorized. It stays stored until you delete it. After you delete it, the link stops opening in about a minute.

**Antes de instalar.** O SKILL.md e o código da CLI podem ser lidos sem conta no GitHub:

**Before you install.** You can read SKILL.md and the CLI source without a GitHub account:

- Skill: https://securepublish.work/skill.md
- CLI: https://securepublish.work/cli
- npm: https://www.npmjs.com/package/@securepublish/cli
- Source for this version: https://unpkg.com/browse/@securepublish/cli@1.0.4/ · https://cdn.jsdelivr.net/npm/@securepublish/cli@1.0.4/

**Sobre o login por código.** O código aparece no seu próprio terminal; digite só em app.securepublish.work/device, depois de entrar com sua conta. Nunca pedimos esse código por e-mail, chat ou telefone. Se alguém te mandar um código, não digite.

**About code sign-in.** The code appears in your own terminal; type it only at app.securepublish.work/device, after you sign in with your account. We never ask for this code by email, chat, or phone. If someone sends you a code, do not type it.

Security & data: https://securepublish.work/security · PT: https://securepublish.work/pt/seguranca

# Secure Publish

There is no web “publish” button. The console only tracks URLs and views.

## Requisitos

Node 22 LTS (`node -v`). `npx skills add` needs 22 (verified on v22.23.3; the skills CLI crashes on Node 20). The CLI itself runs on Node 20+. If `node -v` is older, install Node 22 LTS from https://nodejs.org.

Install the skill (already used by the landing):

```text
npx skills add https://github.com/SecurePublish/secure-publish --skill "secure-publish"
```

Run the CLI with the scoped npm package (not the public npm package named `secure-publish` — that is a different project). Do **not** run `npm install secure-publish`, `npm install -g secure-publish`, or `npx secure-publish`. Use only the full form every time (npx does **not** leave `securepublish-cli` on PATH):

```bash
npx --yes @securepublish/cli@1.0.4 <subcommand>
```

That runs this repo’s `securepublish-cli` binary for that one invocation (login, publish, help, and the rest).

User prompts this skill handles:

- PT: *Publique este dashboard HTML com Secure Publish.*
- EN: *Publish this HTML dashboard with Secure Publish.*
- PT: *Publique este HTML pra toda a empresa.*
- PT: *Publique só para ana@empresa.com e bia@empresa.com.*
- EN: *Publish this HTML for the whole company.*
- EN: *Publish only to jane@acme.com.*
- PT: *Remova este link.* / *Tire este painel do ar.*
- EN: *Revoke this link.* / *Remove this panel.*

## What you say

Say only these lines about sign-in and publish. Do not explain the mechanism.

If this machine is not signed in yet, run `login` then `login --finish` as two separate commands. Never run either through an output-condensing filter or wrapper (for example `rtk` in Claude Code): those buffer command output until the process exits, so the user never sees the code. Run the CLI directly.

1. Run `npx --yes @securepublish/cli@1.0.4 login` in the foreground and wait for it to exit (it prints the URL and `user_code`, flushes, then exits 0 immediately). Do not background it.

2. In **your own message**, show the verification URL and the `user_code` from that CLI output (replace `{user_code}`; do not invent a code or URL). Say exactly (PT):

You MUST show the `user_code` from the CLI output to the user (replace `{user_code}`). Do not invent a code.

> Vou abrir o login. Na página que abrir, entre com a conta da empresa e digite o código {user_code}.

EN:

> I'll open the sign-in page. Sign in with your company account and enter the code {user_code}.

3. Then run `npx --yes @securepublish/cli@1.0.4 login --finish` (also directly, no output filter/wrapper) and wait for it to complete.

When `login --finish` succeeds and printed a host, say exactly:

> Conta ligada. Publicando em {host}, aberto pra empresa.

Use the host the command printed. Do not invent one.

If the CLI says the company does not have an address yet, or if `host:` is empty after login, send the person https://app.securepublish.work/app/hosting.html, tell them that is where they choose the company address, and stop. Do not try to publish again until they confirm they chose one.

When a host is present, publish:

```bash
npx --yes @securepublish/cli@1.0.4 publish ./dashboard.html --title "Painel" --name "performance-out-26"
npx --yes @securepublish/cli@1.0.4 publish ./dashboard.html --to ana@empresa.com,bia@empresa.com --name "performance-out-26"
npx --yes @securepublish/cli@1.0.4 rename <id-or-url> --name "performance-out-26"
npx --yes @securepublish/cli@1.0.4 rename <id-or-url> --no-name
npx --yes @securepublish/cli@1.0.4 revoke <id-or-url>
```

**Nome do link**
- Monte o nome a partir do título do painel, com 3 a 5 palavras e sem artigos nem preposições (o, a, de, do, da, para…). Se o título tiver período, use o mês abreviado e o ano com 2 dígitos. Exemplo: "Performance de Outubro 2026" vira `performance-out-26`. Passe o nome com `--name`.
- Publique **sem** `--name` quando o título tiver nome de pessoa, e-mail, valor em dinheiro, número de documento ou assunto sensível (demissões, salários, saúde, jurídico, aquisição). Na dúvida, sem nome.
- **Resposta normal:** "Publiquei: {link}. Quer outro nome?" / "Published: {link}. Want a different name?"
- **Quando sai sem nome por ser sensível:** "Publiquei: {link}. Deixei sem nome no link porque o título tem informação sensível. Quer pôr um nome?" / "Published: {link}. I left the name out of the link because the title has sensitive info. Want to add one?"
- **Depois do `rename`:** "Pronto, o link agora é {link}. O anterior continua funcionando." / "Done, the link is now {link}. The old one still works."
- **Depois do `rename` com nome vazio:** "Pronto, o link agora é {link}, sem nome." / "Done, the link is now {link}, with no name."
- **Depois do `revoke`:** "Pronto, o link foi removido." / "Done, the link is gone."
- **Se o CLI recusar o revoke (403):** say exactly: "Only the person who published this link or the company account owner can remove it."

Company-wide means the same email domain as the signed-in account. If they did not say who can see it, ask once:

> Quer restringir a alguém? Passe os e-mails (senão fica aberto pra empresa — mesmo domínio de e-mail).

On success, say exactly (do not invent `{url}` — only the url the command printed):

> Publicado pra **toda a empresa**: {url}

If they passed emails:

> Publicado só para {emails}: {url}

If the CLI refuses the publish because of size (or exits after a 413), show the user the CLI message as written. Do not invent a file size, a limit, or tips. Do not retry the same file. Do not use the generic line below for this case.

If the CLI says the company does not have an address yet, or if `host:` is empty after login, send the person https://app.securepublish.work/app/hosting.html, tell them that is where they choose the company address, and stop. Do not try to publish again until they confirm they chose one. Do not use the generic line below for this case.

If the CLI says the session expired or to run login again, go back to the login steps. Do not use the generic line below for this case.

On any other failure, say exactly:

> Não consegui publicar agora. A conta está ligada em {host}. Tente de novo em instantes.

If the command says you are not signed in, or that the session expired, go back to the login line. Never ask them for an infrastructure secret.

To revoke, pass the published URL or the panel id to `npx --yes @securepublish/cli@1.0.4 revoke <id-or-url>`. The signed-in account is enough; do not ask for extra credentials. If the CLI says the link is already gone, treat that as success.

## Publish

publish — publica um arquivo HTML. Por padrão, todo mundo com e-mail do domínio da sua empresa consegue abrir; use --to para liberar só para e-mails específicos. Existe um limite de tamanho por publicação definido pelo serviço. Se o arquivo for grande demais, a CLI para antes de enviar e diz o que fazer.

publish — publishes an HTML file. By default, anyone with an email on your company domain can open it; use --to to allow only specific emails. There is a per-publish size limit set by the service. If the file is too large, the CLI stops before sending and says what to do.

## Access (V1)

| UI label | Command | What it actually checks |
|----------|---------|-------------------------|
| Toda a empresa / Whole company | default (no `--to`) | Email **domain** after sign-in. Example: `@empresa.com`. |
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
| File over the per-publish size limit | Repeat the CLI message as written. Do not invent a size, a limit, or tips. | Repeat the CLI message as written. Do not invent a size, a limit, or tips. |

## Do not claim

1. A “Continuar como …” screen on the landing/demo proves the *flow*; it authenticates nobody.
2. Do not imitate the Google window. No logos or brand colors on a fake sign-in.
3. The panel URL is not a credential. Without sign-in, the page does not return the HTML.
4. A domain list is not org membership.
5. Do not claim E2E encryption, compliance/SOC2, “nobody ever leaks”, or a waitlist that already saved the email.

Do not use: gate, gated, waitlist, early access, “SSO coming soon”, compliance, E2E, zero trust, “org member”, “Workspace membership”.
