# Secure Publish

**Who operates this and where the data goes.** Secure Publish is operated by SecurePublish. The HTML your agent publishes is stored in our service and only opens for people who sign in with a company login on the domain you authorized. It stays stored until you delete it. After you delete it, the link stops opening in about a minute.

**Quem opera e para onde vão os dados.** O Secure Publish é operado por SecurePublish. O HTML que seu agente publica fica guardado no nosso serviço e só abre pra quem entrar com o login da empresa no domínio que você autorizou. Fica guardado até você apagar. Ao apagar, o link para de abrir em cerca de um minuto.

**Before you install.** You can read SKILL.md and the CLI source without a GitHub account:

**Antes de instalar.** O SKILL.md e o código da CLI podem ser lidos sem conta no GitHub:

- Skill: https://securepublish.work/skill.md
- CLI: https://securepublish.work/cli
- npm: https://www.npmjs.com/package/@securepublish/cli
- Source for this version: https://unpkg.com/browse/@securepublish/cli@1.0.4/ · https://cdn.jsdelivr.net/npm/@securepublish/cli@1.0.4/

**About code sign-in.** The CLI shows a code and opens app.securepublish.work. Check the address, type the code there, and only approve if you started the login in the terminal. We never ask for this code by email, chat, or phone.

**Sobre o login por código.** A CLI mostra um código e abre app.securepublish.work. Confira o endereço, digite o código lá e só aprove se foi você quem começou o login no terminal. Nunca pedimos esse código por e-mail, chat ou telefone.

Security & data: https://securepublish.work/security · PT: https://securepublish.work/pt/seguranca

---

Publish agent-made pages and panels that only your company — or the people you list — can open.

There is no web publish button. Install the skill, or run the CLI.

## Requisitos

Node 22 LTS (`node -v`). `npx skills add` needs 22 (verified on v22.23.3; the skills CLI crashes on Node 20). The CLI itself runs on Node 20+. If `node -v` is older, install Node 22 LTS from https://nodejs.org.

## Skill

```text
npx skills add https://github.com/SecurePublish/secure-publish --skill "secure-publish"
```

Then ask: *Publish this HTML dashboard with Secure Publish.*

## CLI

The bin name is **`securepublish-cli`**. Do **not** `npm install secure-publish` or `npx secure-publish` (unrelated public package). Use the scoped npm package every time (npx does not leave `securepublish-cli` on PATH):

```bash
npx --yes @securepublish/cli@1.0.4 login
npx --yes @securepublish/cli@1.0.4 login --finish
npx --yes @securepublish/cli@1.0.4 login --wait
npx --yes @securepublish/cli@1.0.4 publish ./dashboard.html --title "Painel" --name "vendas-q3"
npx --yes @securepublish/cli@1.0.4 publish ./dashboard.html --to ana@empresa.com,bia@empresa.com --name "ops-ana"
npx --yes @securepublish/cli@1.0.4 rename <id-or-url> --name "vendas-q3"
npx --yes @securepublish/cli@1.0.4 revoke <id-or-url>
npx --yes @securepublish/cli@1.0.4 list
npx --yes @securepublish/cli@1.0.4 logout
npx --yes @securepublish/cli@1.0.4 doctor
```

Agents: run `login`, show the URL and `user_code` in your own message, then run `login --finish`. Never run `login` through an output-condensing filter or wrapper (for example `rtk` in Claude Code).

- **login** — request a one-time code, print the URL + code, flush, and exit. Then the user enters the code in the browser.
- **login --finish** — poll until the browser sign-in is approved and store the session.
- **login --wait** — old blocking behavior (print the code and wait in the same process).
- **publish** — publishes an HTML file. By default, anyone with an email on your company domain can open it; use --to to allow only specific emails. There is a per-publish size limit set by the service; if the file is over it, the CLI warns before sending and explains what to do.
- **logout** — disconnect this machine.
- **revoke** — take a published link down. Accepts the panel id or the full URL. Uses the signed-in account (not Cloudflare credentials). Only the person who published it or the company account owner can remove it. An unknown or already-deleted id is treated as already removed.
- **list** / **rename** / **doctor** — list published panels, change the link name, or check whether this machine is signed in.

Company-wide means the same email domain as the signed-in account. It is not Google Workspace, Microsoft Entra, or GitHub Org membership.
