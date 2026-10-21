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
npx --yes @securepublish/cli@1.0.3 login
npx --yes @securepublish/cli@1.0.3 login --finish
npx --yes @securepublish/cli@1.0.3 login --wait
npx --yes @securepublish/cli@1.0.3 publish ./dashboard.html --title "Painel" --name "vendas-q3"
npx --yes @securepublish/cli@1.0.3 publish ./dashboard.html --to ana@empresa.com,bia@empresa.com --name "ops-ana"
npx --yes @securepublish/cli@1.0.3 rename <id-or-url> --name "vendas-q3"
npx --yes @securepublish/cli@1.0.3 revoke <id-or-url>
npx --yes @securepublish/cli@1.0.3 list
npx --yes @securepublish/cli@1.0.3 logout
npx --yes @securepublish/cli@1.0.3 doctor
```

Agents: run `login`, show the URL and `user_code` in your own message, then run `login --finish`. Never run `login` through an output-condensing filter or wrapper (for example `rtk` in Claude Code).

- **login** — request a one-time code, print the URL + code, flush, and exit. Then the user enters the code in the browser.
- **login --finish** — poll until the browser sign-in is approved and store the session.
- **login --wait** — old blocking behavior (print the code and wait in the same process).
- **publish** — upload an HTML file. Default access is everyone on your company email domain. `--to` limits it to specific emails. Each publish has an upload size limit (default **3 MB** = `3 * 1024 * 1024` = 3145728 bytes). The CLI uses `SECUREPUBLISH_MAX_UPLOAD_BYTES` if set, otherwise `GET /api/limits` from the server, otherwise that 3 MB default. If the file is over the limit, it is not uploaded; the CLI prints the file size, the limit in MB, and tips (compress or inline fewer images, move large images or assets out, split into several pages). A file close to the limit gets a warning but still uploads.
- **logout** — disconnect this machine.
- **revoke** — take a published link down. Accepts the panel id or the full URL. Uses the signed-in account (not Cloudflare credentials). Only the person who published it or the company account owner can remove it. An unknown or already-deleted id is treated as already removed.
- **list** / **rename** / **doctor** — list published panels, change the link name, or check whether this machine is signed in.

Company-wide means the same email domain as the signed-in account. It is not Google Workspace, Microsoft Entra, or GitHub Org membership.
