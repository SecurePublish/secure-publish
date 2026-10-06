/**
 * DNS helpers for custom-domain ownership (TXT via Cloudflare DNS-over-HTTPS).
 * No Node dns — Workers-safe fetch only.
 */

const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";

/**
 * Unquote DoH TXT `data` fields.
 * Cloudflare often returns `"sp-verify=<token>"` or adjacent chunks `"a""b"`.
 * @param {string} data
 * @returns {string}
 */
export function unquoteTxt(data) {
  let s = String(data ?? "").trim();
  if (!s) return "";
  // Adjacent quoted strings: "foo""bar" → foobar (RFC 1035 style in JSON DoH)
  if (s.includes('"')) {
    const parts = [];
    const re = /"((?:\\.|[^"\\])*)"/g;
    let m;
    let matched = false;
    while ((m = re.exec(s))) {
      matched = true;
      parts.push(m[1].replace(/\\"/g, '"').replace(/\\\\/g, "\\"));
    }
    if (matched) return parts.join("").trim();
    // Single leading/trailing quote
    if (s.startsWith('"') && s.endsWith('"') && s.length >= 2) {
      return s.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, "\\").trim();
    }
  }
  return s;
}

/**
 * @param {string[]} records unquoted TXT strings
 * @param {string} expected e.g. sp-verify=<opaque-token>
 * @returns {boolean}
 */
export function txtMatchesVerify(records, expected) {
  const want = String(expected || "").trim();
  if (!want) return false;
  for (const raw of records || []) {
    const r = String(raw || "").trim();
    if (!r) continue;
    if (r === want) return true;
    // Whitespace-separated chunks (multi-string TXT)
    for (const part of r.split(/\s+/)) {
      if (part === want) return true;
    }
    // Substring with token boundaries (hypothesis: concatenated chunks)
    let idx = 0;
    while ((idx = r.indexOf(want, idx)) !== -1) {
      const beforeOk = idx === 0 || /\s/.test(r[idx - 1]);
      const afterOk =
        idx + want.length === r.length || /\s/.test(r[idx + want.length]);
      if (beforeOk && afterOk) return true;
      idx += 1;
    }
  }
  return false;
}

/**
 * Lookup TXT records via Cloudflare DoH (application/dns-json).
 * @param {string} name FQDN without trailing requirement
 * @param {typeof fetch} [fetchFn]
 * @returns {Promise<{ ok: true, records: string[] } | { ok: false, error: string }>}
 */
export async function lookupTxt(name, fetchFn = fetch) {
  const n = String(name || "")
    .trim()
    .replace(/\.$/, "");
  if (!n) return { ok: false, error: "dns_lookup_failed" };
  const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(n)}&type=TXT`;
  let res;
  try {
    res = await fetchFn(url, {
      headers: { Accept: "application/dns-json" },
    });
  } catch {
    return { ok: false, error: "dns_lookup_failed" };
  }
  if (!res.ok) return { ok: false, error: "dns_lookup_failed" };
  let j;
  try {
    j = await res.json();
  } catch {
    return { ok: false, error: "dns_lookup_failed" };
  }
  const answers = Array.isArray(j?.Answer) ? j.Answer : [];
  const records = [];
  for (const a of answers) {
    // type 16 = TXT
    if (a.type !== 16 && a.type !== "TXT") continue;
    const unquoted = unquoteTxt(a.data);
    if (unquoted) records.push(unquoted);
  }
  return { ok: true, records };
}
