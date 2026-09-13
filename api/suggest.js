/**
 * POST /api/suggest — turns a visitor's proposal into a GitHub issue.
 * GET  /api/suggest — tells the page whether suggestions are on, and hands it
 *                     the Turnstile site key when one is configured.
 *
 * This endpoint is PUBLIC on purpose: requiring an account to suggest one jump
 * means getting no suggestions. It therefore never touches jumps.json — the
 * worst a stranger can do is open an issue you close. Keep it OUTSIDE the
 * Cloudflare Access path (protect /api/save, not all of /api).
 *
 * Environment (Pages → Settings → Environment variables):
 *   GITHUB_TOKEN         same token as save.js, with Issues: Read and write
 *   GITHUB_REPO          "owner/name"
 *   SUGGEST_LABEL        optional, defaults to "suggestion"
 *   TURNSTILE_SITE_KEY   optional, public key of the Turnstile widget
 *   TURNSTILE_SECRET     optional, its secret. Present = every submission is
 *                        verified; absent = the endpoint still works, which is
 *                        fine while testing and unwise once the link is public.
 */

const LIMITS = { message: 4000, title: 120, author: 40, contact: 120, clip: 500 };

export async function onRequestGet({ request, env }) {
  const out = {
    enabled: Boolean(env.GITHUB_TOKEN && env.GITHUB_REPO),
    captcha: env.TURNSTILE_SITE_KEY || null,
    repo: env.GITHUB_REPO || null,
  };

  // ?debug=1 answers the only question a false "enabled" ever raises: which of
  // the two is missing, and — the usual culprit — under what name the value was
  // actually saved. NAMES ONLY. No value is ever read out of env here, so this
  // stays safe on a public endpoint; a typo'd or wrong-environment secret shows
  // up as a name in the list that isn't the one being looked for.
  if (new URL(request.url).searchParams.get("debug") === "1") {
    out.has = {
      GITHUB_TOKEN: Boolean(env.GITHUB_TOKEN),
      GITHUB_REPO: Boolean(env.GITHUB_REPO),
      GITHUB_BRANCH: Boolean(env.GITHUB_BRANCH),
      TURNSTILE_SECRET: Boolean(env.TURNSTILE_SECRET),
    };
    out.bindings = Object.keys(env).sort();
  }

  return json(out);
}

export async function onRequestPost({ request, env }) {
  if (!env.GITHUB_TOKEN || !env.GITHUB_REPO) {
    return json({ error: "not_configured" }, 503);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return json({ error: "bad_json" }, 400);
  }

  const kind = body.kind === "new" ? "new" : "edit";
  const message = clean(body.message, LIMITS.message);
  const author = clean(body.author, LIMITS.author);
  const title = clean(body.title, LIMITS.title);
  const contact = clean(body.contact, LIMITS.contact);
  const clip = clean(body.clip, LIMITS.clip);

  if (!message) return json({ error: "message_required" }, 400);
  if (!author) return json({ error: "author_required" }, 400);
  if (kind === "new" && !title) return json({ error: "title_required" }, 400);
  if (clip && !/^https?:\/\//i.test(clip)) return json({ error: "clip_not_a_link" }, 400);

  if (env.TURNSTILE_SECRET) {
    const ok = await turnstile(env.TURNSTILE_SECRET, body.turnstile, request.headers.get("CF-Connecting-IP"));
    if (!ok) return json({ error: "captcha_failed" }, 403);
  }

  const spotLabel = clean(body.spotLabel, 120);
  const jumpName = clean(body.jumpName, 120);
  const coords =
    typeof body.x === "number" && typeof body.y === "number"
      ? "X " + body.x.toFixed(3) + " · Y " + body.y.toFixed(3)
      : null;

  const issueTitle =
    kind === "new"
      ? "New jump: " + title
      : "Edit: " + (jumpName || spotLabel || "a jump") + (spotLabel && jumpName ? " (" + spotLabel + ")" : "");

  const lines = [];
  lines.push("**Type:** " + (kind === "new" ? "new jump" : "edit to an existing jump"));
  if (spotLabel) lines.push("**Spot:** " + spotLabel);
  if (jumpName) lines.push("**Jump:** " + jumpName);
  if (coords) lines.push("**Where:** `" + coords + "`");
  if (clip) lines.push("**Clip:** " + clip);
  lines.push("**From:** " + author + (contact ? " — " + contact : ""));
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push(quote(message));
  lines.push("");
  lines.push(payloadComment({
    v: 1, kind: kind, title: title,
    spotId: clean(body.spotId, 64), jumpId: clean(body.jumpId, 64),
    spotLabel: spotLabel, jumpName: jumpName, x: body.x, y: body.y,
    clip: clip, author: author, contact: contact, message: message,
  }));

  const r = await fetch("https://api.github.com/repos/" + env.GITHUB_REPO + "/issues", {
    method: "POST",
    headers: {
      Authorization: "Bearer " + env.GITHUB_TOKEN,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "karkand-jump-map",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      title: issueTitle,
      body: lines.join("\n"),
      labels: [env.SUGGEST_LABEL || "suggestion"],
    }),
  });

  if (r.status !== 201) {
    return json({ error: "github_failed", status: r.status, detail: await r.text() }, 502);
  }
  const issue = await r.json();
  return json({ ok: true, number: issue.number, url: issue.html_url });
}

/* ---------- helpers ---------- */

async function turnstile(secret, token, ip) {
  if (!token) return false;
  try {
    const form = new FormData();
    form.append("secret", secret);
    form.append("response", token);
    if (ip) form.append("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: form,
    });
    if (!r.ok) return false;
    const d = await r.json();
    return d.success === true;
  } catch (e) {
    return false;
  }
}

/* Trim, cap, and drop control characters that would mangle the issue body. */
function clean(v, max) {
  if (typeof v !== "string") return "";
  let s = v.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "").trim();
  if (s.length > max) s = s.slice(0, max);
  return s;
}

/* The visitor's own words go in a blockquote so they cannot forge the
   structured fields above them. */
function quote(text) {
  /* `&lt;!--` renders as the literal characters "<!--" and opens nothing, so
     the visitor's text still reads exactly as they wrote it while losing the
     ability to plant a payload block of its own above the real one. */
  const safe = text.split("<!--").join("&lt;!--");
  return safe.split("\n").map(function (l) { return "> " + l; }).join("\n");
}

/* A machine-readable copy, so a proposal can later be applied without
   re-typing it. The comment terminator is escaped so the payload cannot
   close the comment early and inject markdown of its own. */
function payloadComment(obj) {
  const raw = JSON.stringify(obj).split("--" + ">").join("--\\u003e");
  return "<!-- karkand-suggestion\n" + raw + "\n--" + ">";
}

function json(obj, status) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
