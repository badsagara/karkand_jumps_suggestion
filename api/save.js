/**
 * POST /api/save  — writes jumps.json into the GitHub repository, which makes
 *                   Cloudflare Pages redeploy the site.
 * GET  /api/save   — reports who is signed in and where the data will land.
 *
 * Two independent gates protect this endpoint:
 *
 *   1. A Cloudflare Access policy in front of /api/* and /edit* stops anyone
 *      who is not on your allow-list from reaching the function at all.
 *   2. The function itself verifies the JWT that Access attaches to the
 *      request. This matters because Access policies are bound to hostnames,
 *      and a Pages project also answers on its preview deployment URLs, which
 *      the policy may not cover. Without this check those URLs would be an
 *      open back door.
 *
 * Environment (Pages → Settings → Environment variables):
 *   GITHUB_TOKEN         secret. Fine-grained PAT, Contents: Read and write,
 *                        scoped to this one repository.
 *   GITHUB_REPO          "owner/name", e.g. "sagara/karkand-jumps"
 *   GITHUB_BRANCH        optional, defaults to "main"
 *   JUMPS_PATH           optional, defaults to "public/jumps.json" — the path
 *                        INSIDE THE REPOSITORY, which is not the URL. Static
 *                        files are served out of public/, so a file committed
 *                        to the repository root is never served at all.
 *   ACCESS_TEAM_DOMAIN   your Zero Trust team name, e.g. "first-legion"
 *                        (the part before .cloudflareaccess.com)
 *   ACCESS_AUD           the Application Audience (AUD) tag of the Access app
 */

const MAX_BYTES = 2 * 1024 * 1024;

export async function onRequestGet({ request, env }) {
  const seen = await verifyAccess(request, env);
  if (!seen) return json({ error: "not_authenticated" }, 401);

  /* The signature and issuer checked out but the AUD did not. That is the
     usual state while setting up, so say which value the token actually
     carries — it is the one that belongs in ACCESS_AUD. Nothing is disclosed:
     the caller already holds this token and a JWT is not encrypted. */
  if (!seen.audOk) {
    return json({
      error: "aud_mismatch",
      tokenAud: seen.aud,
      hint: "Put one of these values into the ACCESS_AUD environment variable, then redeploy.",
    }, 401);
  }

  const identity = seen.payload;
  return json({
    email: identity.email || null,
    repo: env.GITHUB_REPO || null,
    branch: env.GITHUB_BRANCH || "main",
    path: env.JUMPS_PATH || "public/jumps.json",
    configured: Boolean(env.GITHUB_TOKEN && env.GITHUB_REPO),
  });
}

export async function onRequestPost({ request, env }) {
  const seen = await verifyAccess(request, env);
  if (!seen) return json({ error: "not_authenticated" }, 401);
  if (!seen.audOk) return json({ error: "aud_mismatch", tokenAud: seen.aud }, 401);
  const identity = seen.payload;

  if (!env.GITHUB_TOKEN || !env.GITHUB_REPO) {
    return json({ error: "not_configured", detail: "GITHUB_TOKEN or GITHUB_REPO is missing" }, 500);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "bad_json" }, 400);
  }
  if (!body || !Array.isArray(body.spots)) {
    return json({ error: "bad_shape", detail: "expected an object with a spots array" }, 400);
  }

  const text = JSON.stringify(body, null, 2);
  const bytes = new TextEncoder().encode(text);
  if (bytes.length > MAX_BYTES) {
    return json({ error: "too_large", bytes: bytes.length, limit: MAX_BYTES }, 413);
  }

  const repo = env.GITHUB_REPO;
  const branch = env.GITHUB_BRANCH || "main";
  const path = env.JUMPS_PATH || "public/jumps.json";
  const api = `https://api.github.com/repos/${repo}/contents/${encodeURI(path)}`;

  // The Contents API needs the blob SHA of the file being replaced. Its absence
  // is not an error: it just means this is the first commit of the file.
  let sha = null;
  const head = await gh(`${api}?ref=${encodeURIComponent(branch)}`, env, { method: "GET" });
  if (head.status === 200) {
    sha = (await head.json()).sha;
  } else if (head.status !== 404) {
    return json({ error: "github_read_failed", status: head.status, detail: await head.text() }, 502);
  }

  const who = identity.email || "map editor";
  const put = await gh(api, env, {
    method: "PUT",
    body: JSON.stringify({
      message: `Update ${path} — ${body.spots.length} spot(s) via the map editor`,
      content: base64(bytes),
      branch,
      sha: sha || undefined,
      committer: { name: "Karkand map editor", email: mailboxFor(who) },
    }),
  });

  if (put.status !== 200 && put.status !== 201) {
    return json({ error: "github_write_failed", status: put.status, detail: await put.text() }, 502);
  }

  const result = await put.json();
  return json({
    ok: true,
    spots: body.spots.length,
    by: who,
    commit: result.commit && result.commit.sha ? result.commit.sha.slice(0, 7) : null,
    url: result.commit && result.commit.html_url ? result.commit.html_url : null,
  });
}

/* ---------- Cloudflare Access ---------- */

export async function verifyAccess(request, env) {
  const team = env.ACCESS_TEAM_DOMAIN;
  const aud = env.ACCESS_AUD;
  /* Without a team domain there is nothing to verify a signature against, so
     refuse outright: an unconfigured gate is not a gate. A missing AUD is
     different — the signature can still be checked, and reporting the
     mismatch is what makes the setup diagnosable. */
  if (!team) return null;

  const token =
    request.headers.get("Cf-Access-Jwt-Assertion") ||
    cookie(request, "CF_Authorization");
  if (!token) return null;

  const parts = token.split(".");
  if (parts.length !== 3) return null;

  let header, payload;
  try {
    header = JSON.parse(decodeUtf8(fromB64Url(parts[0])));
    payload = JSON.parse(decodeUtf8(fromB64Url(parts[1])));
  } catch (e) {
    return null;
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now >= payload.exp) return null;
  if (payload.nbf && now < payload.nbf - 60) return null;

  /* Each Access application has its own AUD tag. If /edit and /api/save ended
     up as two separate applications, list both here, comma-separated — the
     function only ever sees /api/save, but accepting either keeps the setup
     forgiving without widening it to the whole Zero Trust team. */
  const allowed = String(aud || "").split(",").map(function (s) { return s.trim(); }).filter(Boolean);
  const auds = (Array.isArray(payload.aud) ? payload.aud : [payload.aud]).filter(Boolean);
  const audOk = allowed.length > 0 && auds.some(function (a) { return allowed.indexOf(a) !== -1; });

  const iss = `https://${team}.cloudflareaccess.com`;
  if (payload.iss && payload.iss !== iss) return null;

  const jwks = await certs(iss);
  if (!jwks) return null;
  const jwk = jwks.filter(function (k) { return k.kid === header.kid; })[0];
  if (!jwk) return null;

  let key;
  try {
    key = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
  } catch (e) {
    return null;
  }

  const ok = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    fromB64Url(parts[2]),
    new TextEncoder().encode(parts[0] + "." + parts[1])
  );
  return ok ? { payload: payload, audOk: audOk, aud: auds } : null;
}

async function certs(iss) {
  try {
    const r = await fetch(iss + "/cdn-cgi/access/certs", {
      cf: { cacheTtl: 3600, cacheEverything: true },
    });
    if (!r.ok) return null;
    const d = await r.json();
    return Array.isArray(d.keys) ? d.keys : null;
  } catch (e) {
    return null;
  }
}

/* ---------- helpers ---------- */

function gh(url, env, init) {
  return fetch(url, {
    method: init.method,
    body: init.body,
    headers: {
      Authorization: "Bearer " + env.GITHUB_TOKEN,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "karkand-jump-map",
      "Content-Type": "application/json",
    },
  });
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function cookie(request, name) {
  const raw = request.headers.get("Cookie");
  if (!raw) return null;
  const parts = raw.split(";");
  for (let i = 0; i < parts.length; i++) {
    const p = parts[i].trim();
    if (p.indexOf(name + "=") === 0) return p.slice(name.length + 1);
  }
  return null;
}

function fromB64Url(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

function base64(bytes) {
  let bin = "";
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + step));
  }
  return btoa(bin);
}

/* GitHub wants a syntactically valid committer address. */
function mailboxFor(who) {
  return /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(who) ? who : "noreply@users.noreply.github.com";
}
