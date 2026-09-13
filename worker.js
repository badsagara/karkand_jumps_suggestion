/**
 * Entry point for a Cloudflare Worker that serves this site.
 *
 * Static files live in ./public and are served by the assets binding.
 * Two paths are handled by code instead:
 *
 *   /api/save        writes jumps.json to GitHub       (behind Cloudflare Access)
 *   /api/suggestions reads and closes open suggestions (behind Cloudflare Access)
 *   /api/suggest     turns a visitor's proposal into an issue (deliberately open)
 *
 * The singular and the plural are deliberately different doors: /api/suggest is
 * the public one, /api/suggestions is the owner's. Protect the plural.
 *
 * Note for anyone moving this to Cloudflare Pages instead: Pages routes files
 * under `functions/` automatically, so there this file and wrangler.jsonc are
 * unnecessary — put api/save.js and api/suggest.js in functions/api/ and
 * delete both. The handler modules themselves are identical either way.
 */

import * as save from "./api/save.js";
import * as suggest from "./api/suggest.js";
import * as suggestions from "./api/suggestions.js";

const ROUTES = {
  "/api/save": save,
  "/api/suggest": suggest,
  "/api/suggestions": suggestions,
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const route = ROUTES[path];

    if (route) {
      const handler =
        request.method === "GET" ? route.onRequestGet :
        request.method === "POST" ? route.onRequestPost : null;

      if (!handler) {
        return new Response(JSON.stringify({ error: "method_not_allowed" }), {
          status: 405,
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Allow": "GET, POST",
          },
        });
      }
      return handler({ request, env, ctx });
    }

    /* Everything else is a static file. */
    return env.ASSETS.fetch(request);
  },
};
