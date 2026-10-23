/**
 * User-facing CLI copy. Product rewords these strings; keep the keys stable.
 *
 * Skill users run the CLI via npx; the bin name is not on PATH.
 * Same invocation as skills/secure-publish/SKILL.md and README.md.
 */
export const NPX_CLI = "npx --yes @securepublish/cli@1.0.4";

export const MESSAGES = {
  sessionExpired: {
    pt: `Sua sessão expirou ou foi encerrada. Rode ${NPX_CLI} login para entrar de novo.`,
    en: `Your session expired or was ended. Run ${NPX_CLI} login to sign in again.`,
  },
  notLoggedIn: {
    pt: `Conta não ligada nesta máquina. Rode ${NPX_CLI} login.`,
    en: `This machine is not signed in. Run ${NPX_CLI} login.`,
  },
  noHostLogin: {
    pt: "Login feito. Falta só um passo, que você faz uma vez só: escolher o endereço da sua empresa, como suaempresa.securepublish.work. Escolha em https://app.securepublish.work/app/hosting.html e depois volte aqui pra publicar.",
    en: "You're signed in. One step left, and you only do it once: choose your company's address, like yourcompany.securepublish.work. Choose it at https://app.securepublish.work/app/hosting.html, then come back here to publish.",
  },
  noHostPublish: {
    pt: "Ainda não publiquei: sua empresa não tem um endereço no Secure Publish. Escolha um em https://app.securepublish.work/app/hosting.html e tente publicar de novo. Isso só precisa ser feito uma vez.",
    en: "Not published yet: your company doesn't have a Secure Publish address. Choose one at https://app.securepublish.work/app/hosting.html and try publishing again. You only need to do this once.",
  },
};

export function message(key, lang) {
  const pack = MESSAGES[key];
  if (!pack) return "";
  return lang === "en" ? pack.en : pack.pt;
}
