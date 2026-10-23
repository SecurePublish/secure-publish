/**
 * User-facing CLI copy. Product rewords these strings; keep the keys stable.
 */

export const MESSAGES = {
  sessionExpired: {
    pt: "Sua sessão expirou ou foi encerrada. Rode securepublish-cli login para entrar de novo.",
    en: "Your session expired or was ended. Run securepublish-cli login to sign in again.",
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
