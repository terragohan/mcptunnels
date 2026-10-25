# SEO / Discoverability — mcptunnels

Internal reference for how mcptunnels is positioned for search engines and AI
crawlers, what this repo implements, and what remains manual. For the repo
itself see `README.md`, `DESIGN.md`, and `AGENTS.md`.

## Surfaces

| Host | Served by | Indexable? |
|---|---|---|
| `https://mcptunnels.terragohan.com` | Astro + Starlight static site (`site/`), GitHub Pages (`gh-pages` branch via `npm run deploy`) | Yes — the whole point |
| `https://t-mcptunnels.terragohan.com` | `tunneld` (Go), ephemeral tenant URLs under `/t/{tenant}/` | No — disallow-all `robots.txt` served by `internal/server/server.go` |

There are no per-user or secret pages on the docs host; nothing needs
`noindex` there. The relay host must never be indexed (ephemeral, untrusted
tenant content), hence `User-agent: * / Disallow: /` from tunneld.

## Indexable routes (exactly these)

| Route | Purpose |
|---|---|
| `/` | Positioning, feature grid, ngrok/cloudflared comparison, roadmap |
| `/get-started/` | Install → expose → connect a client |
| `/how-it-works/` | Architecture: outbound WSS + yamux, stdio bridging, per-tunnel OAuth |
| `/self-hosting/` | Run your own tunneld; endpoints; abuse controls |
| `/security/` | Trust model, threat model, vuln reporting |
| `/faq/` | Hosted instance, 24h TTL, encryption, NAT, comparison |

The sitemap (`@astrojs/sitemap`, pulled in by Starlight) must list exactly
this set — `site/scripts/seo-check.mjs` enforces it. When adding a page that
should be indexed, add it to the checker's `ROUTES` and to
`site/public/llms.txt`.

## What the site serves for crawlers

- `robots.txt` (`site/public/robots.txt`): allow all + `Sitemap:` line
  pointing at `/sitemap-index.xml`.
- `sitemap.xml`: the single merged URL set — generated at build time from
  `site:` in `astro.config.mjs` with absolute URLs. `@astrojs/sitemap`
  always writes `sitemap-index.xml` + numbered `sitemap-N.xml` chunks and
  offers no rename, so `scripts/sitemap-finalize.mjs` (chained onto
  `npm run build`) merges the chunk into the conventional `/sitemap.xml`
  and deletes the index/chunk files. This site is nowhere near the
  protocol's 50k-URL single-file limit; the script fails the build loudly
  if it ever gets close. robots.txt and the `<link rel="sitemap">` head tag
  (rewritten by `Head.astro`) both point at `/sitemap.xml`.
- `llms.txt` (`site/public/llms.txt`): summary + doc links for LLM crawlers.
- `og-image.png` (1200×630): social card. Source SVG at
  `site/assets/og-image.svg`; regenerate with headless Chrome, e.g.
  `"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" --headless
  --disable-gpu --screenshot=site/public/og-image.png --window-size=1200,630
  --default-background-color=FFFFFFFF "file://$PWD/site/assets/og-image.svg"`
  (qlmanage rasterizes to a square canvas — do not use it for this).
- Per-page metadata comes from Starlight frontmatter (`title`,
  `description`) plus config-level `head` entries in `astro.config.mjs`
  (og:image + twitter:image on every page).

## Metadata conventions

- Page `title` frontmatter drives both `<title>` (`{title} | mcptunnels`)
  and the on-page `<h1>` — keep it descriptive, not bare brand. The homepage
  idiom in this repo: title = the value proposition
  ("Public URLs for local MCP servers"), site title stays the brand.
- Starlight emits `og:type=article` everywhere by default;
  `site/src/components/Head.astro` overrides the homepage to `website`
  (homepage route id is the empty string in Starlight's route data).
- Homepage carries `SoftwareApplication` JSON-LD (free offer, feature list).
  No Organization, ratings, or review markup — none exist.
- FAQ questions are real `<h2>` headings (per-question anchors); no FAQ
  structured data, matching the product's honest-v1 positioning.

## Verified product claims (safe to publish)

Cross-checked against code on 2026-10-10:

- One command (`mcptunnel expose -- <cmd>`) → public URL; hosted relay is the
  default `--server`.
- No accounts, no signup, no config; anonymous quick tunnels.
- 24-hour tenant TTL (`internal/controlplane`: `QuickTTL = 24h`); janitor
  sweep every minute; Ctrl-C deletes the tunnel immediately.
- OAuth 2.1 by default: per-tunnel password page, one-time codes, DCR,
  RFC 8414 / RFC 9728 discovery; `--no-auth` for open URLs.
- Passwords and agent keys stored as bcrypt hashes only; per-tenant ES256 JWT
  keys cascade-delete with the tenant.
- Outbound-only agent connection (WebSocket + yamux); works behind NAT;
  reconnects after laptop sleep.
- stdio → Streamable HTTP bridging built in.
- Self-hostable `tunneld`: single binary, SQLite or Cloudflare D1, ACME TLS,
  Docker; abuse takedown via `-kill-tenant`.
- Rate limits: quick-tunnel creation 10/hour/IP (persisted across restarts;
  503 at 500 live tunnels), DCR registration 20/hour/IP.
- Hosted relay is free and best-effort: no SLA, no uptime guarantee.

## Must NOT claim

- Permanent/stable/named tunnels (roadmap phase 02), pluggable IdPs, or
  identity pass-through (phase 04) — not built.
- End-to-end encryption — the relay operator can read payloads by design.
- Guaranteed compatibility with every hosted MCP client (README/site say
  "not yet exhaustively verified").
- Any SLA, uptime, or takedown-time guarantee.
- Generic TCP/HTTP tunneling of non-MCP services (explicit non-goal).
- CAPTCHA/spam filtering on the relay (only the deliberately weak per-IP
  creation limit exists).
- Pricing beyond "free today" — there is no payment anything.

## Crawler policy observations (probed 2026-10-10)

- GitHub Pages serves all pages 200 to Googlebot, bingbot, OAI-SearchBot,
  GPTBot, ClaudeBot, and PerplexityBot — no bot blocking anywhere. No
  changes needed; the product wants AI-client discoverability.
- Missing pages return real 404s with a branded `404.html` (Starlight).
- `HEAD` on `/how-it-works/` returns 200 (GitHub Pages); harmless.

## Remaining manual owner actions / launch checklist

1. Deploy the site: `cd site && npm run build && npm run check && npm run
   deploy`. gh-pages syncs deletions, so the stale `/roadmap/` (removed from
   the source earlier) disappears on deploy.
2. Verify live: `curl -sf https://mcptunnels.terragohan.com/robots.txt`,
   `/sitemap-index.xml`, `/og-image.png`, `/llms.txt` — all must be 200.
3. Google Search Console: verify property, submit
   `https://mcptunnels.terragohan.com/sitemap.xml`, inspect the
   homepage URL.
4. Bing Webmaster Tools: import/verify and submit the same sitemap.
5. Optional: IndexNow key for Bing; rich-result test on `/` for the
   SoftwareApplication JSON-LD.
6. Check that `https://t-mcptunnels.terragohan.com/robots.txt` returns the
   disallow-all file after the next tunneld release/deploy.

## CI

The `site` job in `.github/workflows/ci.yml` builds the site and runs
`npm run check` (the seo-check script) so the metadata cannot silently
regress. `make site-check` runs the same thing locally.
