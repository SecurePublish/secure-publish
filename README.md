# Secure Publish

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
npx --yes @securepublish/cli@1.0.0 login
npx --yes @securepublish/cli@1.0.0 publish ./dashboard.html --title "Painel" --name "vendas-q3"
npx --yes @securepublish/cli@1.0.0 publish ./dashboard.html --to ana@empresa.com,bia@empresa.com --name "ops-ana"
npx --yes @securepublish/cli@1.0.0 rename <id-or-url> --name "vendas-q3"
npx --yes @securepublish/cli@1.0.0 list
npx --yes @securepublish/cli@1.0.0 logout
npx --yes @securepublish/cli@1.0.0 doctor
```

- **login** — connect this machine to your company account (browser + one-time code).
- **publish** — upload an HTML file. Default access is everyone on your company email domain. `--to` limits it to specific emails.
- **logout** — disconnect this machine.
- **list** / **rename** / **doctor** — list published panels, change the link name, or check whether this machine is signed in.

Company-wide means the same email domain as the signed-in account. It is not Google Workspace, Microsoft Entra, or GitHub Org membership.
