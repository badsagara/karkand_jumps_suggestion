/**
 * GET  /api/suggestions — open suggestions, parsed, for the editor's panel.
 * POST /api/suggestions — {number, note} closes one with a comment.
 *
 * OWNER ONLY. Both verbs go through the same Cloudflare Access check as
 * /api/save, and the same reasoning applies: /api/suggest (singular) is the
 * public door strangers post through, this one (plural) is the desk you read
 * them at. Protect this path in Access alongside /api/save.
 *
 * Nothing here writes to jumps.json. A suggestion reaches the map only when
 * the owner applies it in the editor and presses Save — the payload below is
 * strangers' input and is treated as such: it fills a form, it never lands in
 * the file by itself.
 */

import { verifyAccess } from "./save.js";

const MAX = 50;

export async function onRequestGet({ request, env }) {
  const who = await verifyAccess(request, env);
  if (!who) return json({ error: "not_signed_in" }, 401);
  if (!who.audOk) return json({ error: "aud_mismatch", tokenAud: who.aud }, 403);
  if (!env.GITHUB_TOKEN || !env.GITHUB_REPO) return json({ error: "not_configured" }, 503);

  const label = env.SUGGEST_LABEL || "suggestion";
  const url =
    "https://api.github.com/repos/" + env.GITHUB_REPO +
    "/issues?state=open&per_page=" + MAX + "&labels=" + encodeURIComponent(label);

  const r = await gh(url, env, { method: "GET" });
  if (!r.ok) return json({ error: "github_failed", status: r.status, detail: await r.text() }, 502);

  const raw = await r.json();
  const items = (Array.isArray(raw) ? raw : [])
    // The issues endpoint also returns pull requests. They are not suggestions.
    .filter(function (i) { return !i.pull_request; })
    .map(function (i) {
      return {
        number: i.number,
        title: i.title || "",
        url: i.html_url,
        created: i.created_at,
        payload: parsePayload(i.body || ""),
      };
    });

  return json({ ok: true, repo: env.GITHUB_REPO, count: items.length, items: items });
}

export async function onRequestPost({ request, env }) {
  const who = await verifyAccess(request, env);
  if (!who) return json({ error: "not_signed_in" }, 401);
  if (!who.audOk) return json({ error: "aud_mismatch", tokenAud: who.aud }, 403);
  if (!env.GITHUB_TOKEN || !env.GITHUB_REPO) return json({ error: "not_configured" }, 503);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "bad_json" }, 400);
  }

  const number = Math.floor(Number(body.number));
  if (!(number > 0)) return json({ error: "bad_number" }, 400);

  const base = "https://api.github.com/repos/" + env.GITHUB_REPO + "/issues/" + number;
  const note = typeof body.note === "string" ? body.note.slice(0, 500).trim() : "";

  // Comment first, close second. If the close fails the trail still shows what
  // happened; if the comment fails there is nothing worth closing over.
  if (note) {
    const c = await gh(base + "/comments", env, {
      method: "POST",
      body: JSON.stringify({ body: note }),
    });
    if (!c.ok) return json({ error: "comment_failed", status: c.status, detail: await c.text() }, 502);
  }

  const r = await gh(base, env, {
    method: "PATCH",
    body: JSON.stringify({ state: "closed", state_reason: "completed" }),
  });
  if (!r.ok) return json({ error: "close_failed", status: r.status, detail: await r.text() }, 502);

  return json({ ok: true, number: number });
}

/* ---------- helpers ---------- */

/* The machine-readable block /api/suggest leaves at the end of every issue.
   Absent or mangled (someone edited the issue by hand) is normal, not an
   error — the panel then shows the issue with its text and no Apply button.
 *
 * THE LAST BLOCK WINS, and that is the whole security of this function. A
 * visitor's own words are quoted above it and could contain a block of their
 * own; /api/suggest now escapes the opening marker so they cannot, but this
 * side does not rely on that. The generator always appends its block last, so
 * taking the last parseable one makes an injected block unreachable however it
 * got into the text.
 */
function parsePayload(bodyText) {
  const re = /<!--\s*karkand-suggestion\s*([\s\S]*?)-->/g;
  let m, last = null;
  while ((m = re.exec(bodyText)) !== null) {
    try {
      const obj = JSON.parse(m[1].trim().split("--\\u003e").join("--" + ">"));
      if (obj && typeof obj === "object" && obj.v === 1) last = obj;
    } catch (e) {
      /* keep looking: a half-written block earlier in the body is not fatal */
    }
  }
  return last;
}

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
