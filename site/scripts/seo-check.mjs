#!/usr/bin/env node
// Post-build SEO checks for the mcptunnels docs site (https://mcptunnels.terragohan.com).
// Runs against site/dist with no dependencies: `npm run build && npm run check`.
// See SEO_DISCOVERABILITY.md at the repo root for what this guards and why.
import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../dist');
const SITE = 'https://mcptunnels.terragohan.com';

// The complete set of indexable routes. The sitemap must match this exactly;
// add new pages here when they are meant to be indexed.
const ROUTES = ['/', '/faq/', '/get-started/', '/how-it-works/', '/security/', '/self-hosting/'];

const failures = [];
let checked = 0;
function check(name, cond, detail = '') {
	checked++;
	if (!cond) failures.push(`${name}${detail ? ` — ${detail}` : ''}`);
}

const read = (rel) => {
	const p = path.join(dist, rel);
	if (!existsSync(p)) return null;
	return readFileSync(p, 'utf8');
};
const pageFile = (route) => (route === '/' ? 'index.html' : `${route.slice(1, -1)}/index.html`);
const first = (html, re) => html.match(re)?.[1]?.trim();

// --- robots.txt / llms.txt ---
const robots = read('robots.txt');
check('robots.txt exists', robots !== null);
check('robots.txt allows crawling', robots?.includes('User-agent: *') && !robots.includes('Disallow: /'));
check(
	'robots.txt points at the sitemap',
	robots?.includes(`Sitemap: ${SITE}/sitemap-index.xml`)
);

const llms = read('llms.txt');
check('llms.txt exists', llms !== null);
for (const route of ROUTES) {
	if (route === '/') continue;
	check(`llms.txt links ${route}`, llms?.includes(`${SITE}${route}`));
}

// --- og-image.png: valid PNG, 1200x630 ---
{
	const p = path.join(dist, 'og-image.png');
	check('og-image.png exists', existsSync(p));
	if (existsSync(p)) {
		const buf = readFileSync(p);
		const png = buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
		check('og-image.png is a PNG', png);
		check('og-image.png is 1200x630', buf.readUInt32BE(16) === 1200 && buf.readUInt32BE(20) === 630,
			`${buf.readUInt32BE(16)}x${buf.readUInt32BE(20)}`);
	}
}

// --- sitemap: exists, matches the indexable route set exactly, no stale hosts ---
const sitemapIndex = read('sitemap-index.xml');
check('sitemap-index.xml exists', sitemapIndex !== null);
check('sitemap index references sitemap-0.xml', sitemapIndex?.includes(`${SITE}/sitemap-0.xml`));
const sitemap = read('sitemap-0.xml');
const locs = sitemap ? [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]) : [];
check('sitemap has exactly the indexable routes', sitemap !== null && locs.length === ROUTES.length,
	`got ${locs.length}, want ${ROUTES.length}`);
for (const route of ROUTES) {
	check(`sitemap contains ${route}`, locs.includes(`${SITE}${route}`));
}
check('sitemap has no stale github.io URLs', locs.every((l) => l.startsWith(`${SITE}/`)));

// /sitemap.xml alias: same URL set, copied from sitemap-0.xml at build time.
const alias = read('sitemap.xml');
const aliasLocs = alias ? [...alias.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]) : [];
check('sitemap.xml alias exists', alias !== null);
check(
	'sitemap.xml alias lists exactly the indexable routes',
	aliasLocs.length === ROUTES.length && ROUTES.every((r) => aliasLocs.includes(`${SITE}${r}`)),
	`got ${aliasLocs.length}`
);

// --- per-page metadata ---
for (const route of ROUTES) {
	const html = read(pageFile(route));
	check(`${route} built`, html !== null);
	if (html === null) continue;

	const title = first(html, /<title>([^<]*)<\/title>/);
	check(`${route} has a title naming mcptunnels`, !!title && title.includes('mcptunnels'), title ?? 'missing');
	check(`${route} title is not bare duplicated brand`, title !== 'mcptunnels | mcptunnels', title);

	const h1s = html.match(/<h1[\s>]/g) ?? [];
	check(`${route} has exactly one <h1>`, h1s.length === 1, `${h1s.length} found`);

	const desc = first(html, /<meta name="description" content="([^"]*)"/);
	check(`${route} has a real meta description (>=50 chars)`, !!desc && desc.length >= 50,
		desc ? `${desc.length} chars` : 'missing');

	const canonical = first(html, /<link rel="canonical" href="([^"]*)"/);
	check(`${route} canonical is absolute on-site`, !!canonical && canonical.startsWith(`${SITE}/`), canonical ?? 'missing');

	const ogImage = first(html, /<meta property="og:image" content="([^"]*)"/);
	check(`${route} og:image is absolute on-site`, !!ogImage && ogImage.startsWith(`${SITE}/`), ogImage ?? 'missing');
	check(`${route} has og:description`, /<meta property="og:description" content="[^"]+"/.test(html));
	check(`${route} has twitter:image`, /<meta name="twitter:image" content="[^"]+"/.test(html));
	check(`${route} is not noindexed`, !html.includes('noindex'));

	const ogType = first(html, /<meta property="og:type" content="([^"]*)"/);
	check(`${route} og:type is ${route === '/' ? 'website' : 'article'}`, ogType === (route === '/' ? 'website' : 'article'), ogType ?? 'missing');

	// Footer nav is the only crawlable cross-link block on docs pages.
	check(`${route} footer links to get-started and faq`, html.includes('href="/get-started/"') && html.includes('href="/faq/"'));
}

// --- homepage structured data ---
{
	const html = read('index.html');
	const m = html?.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/);
	check('homepage has JSON-LD', !!m);
	if (m) {
		try {
			const data = JSON.parse(m[1]);
			check('JSON-LD @type is SoftwareApplication', data['@type'] === 'SoftwareApplication', data['@type']);
			check('JSON-LD name is mcptunnels', data.name === 'mcptunnels');
			check('JSON-LD is free (offers.price 0)', data.offers?.price === '0');
		} catch (err) {
			check('JSON-LD parses', false, String(err));
		}
	}
	check('homepage references the demo gif', !!html?.includes('demo.gif'));
}

// --- 404 page ships (served by GitHub Pages with a real 404 status) ---
{
	const html = read('404.html');
	check('404.html exists', html !== null && /<title>404/.test(html));
}

if (failures.length > 0) {
	console.error(`SEO checks FAILED (${failures.length}/${checked}):`);
	for (const f of failures) console.error(`  ✗ ${f}`);
	process.exit(1);
}
console.log(`SEO checks passed (${checked} checks across ${ROUTES.length} pages).`);
