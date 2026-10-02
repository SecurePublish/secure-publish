/**
 * Cloudflare REST API helpers for Workers KV.
 */

const CF_API = "https://api.cloudflare.com/client/v4";

async function cfFetch(path, { method = "GET", token, body, contentType } = {}) {
  const headers = {
    Authorization: `Bearer ${token}`,
  };
  if (contentType) headers["Content-Type"] = contentType;

  const res = await fetch(`${CF_API}${path}`, {
    method,
    headers,
    body,
  });

  const text = await res.text();
  let json;
  try {
    json = JSON.parse(text);
  } catch {
    json = { success: res.ok, raw: text };
  }

  if (!res.ok || json.success === false) {
    const errs =
      (json.errors && json.errors.map((e) => e.message).join("; ")) ||
      text ||
      res.statusText;
    const err = new Error(`Cloudflare API ${res.status}: ${errs}`);
    err.status = res.status;
    err.body = json;
    throw err;
  }
  return json;
}

export async function kvPut({ accountId, namespaceId, token, key, value }) {
  const path = `/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`;
  return cfFetch(path, {
    method: "PUT",
    token,
    body: value,
    contentType: "application/json; charset=utf-8",
  });
}

export async function kvDelete({ accountId, namespaceId, token, key }) {
  const path = `/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`;
  return cfFetch(path, { method: "DELETE", token });
}

export async function kvList({ accountId, namespaceId, token, limit = 1000 }) {
  const keys = [];
  let cursor = undefined;
  do {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (cursor) qs.set("cursor", cursor);
    const path = `/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/keys?${qs}`;
    const json = await cfFetch(path, { method: "GET", token });
    const batch = (json.result || []).map((k) => k.name);
    keys.push(...batch);
    cursor = json.result_info?.cursor || null;
  } while (cursor);
  return keys;
}


export async function kvGet({ accountId, namespaceId, token, key }) {
  const path = `/accounts/${accountId}/storage/kv/namespaces/${namespaceId}/values/${encodeURIComponent(key)}`;
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method: "GET",
    headers: { Authorization: `Bearer ${token}` },
  });
  if (res.status === 404) return null;
  const text = await res.text();
  if (!res.ok) {
    const err = new Error(`Cloudflare API ${res.status}: ${text || res.statusText}`);
    err.status = res.status;
    throw err;
  }
  return text;
}

export async function verifyToken(token) {
  return cfFetch("/user/tokens/verify", { method: "GET", token });
}
