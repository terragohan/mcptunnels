#!/usr/bin/env node
// Postbuild step: collapse the generated sitemap into a single sitemap.xml.
// @astrojs/sitemap always writes sitemap-index.xml + one or more
// sitemap-N.xml chunks and offers no rename; this site is far below the
// protocol's single-file limit (50,000 URLs), so we merge the chunk into the
// conventional filename and drop the index. If the site ever outgrows a
// single file this fails the build loudly instead of emitting an invalid
// sitemap. Chained onto `astro build` in package.json; verified by
// scripts/seo-check.mjs — never edit dist by hand.
import { existsSync, readdirSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../dist');

const chunks = readdirSync(dist).filter((f) => /^sitemap-\d+\.xml$/.test(f)).sort();
if (chunks.length !== 1) {
	console.error(
		`sitemap-finalize: expected exactly 1 sitemap chunk in dist, found ${chunks.length} ` +
			'(site outgrew a single sitemap file) — revert to the generated index scheme.'
	);
	process.exit(1);
}

const body = readFileSync(path.join(dist, chunks[0]));
const urls = (body.toString().match(/<loc>/g) ?? []).length;
if (urls > 45000) {
	console.error(`sitemap-finalize: ${urls} URLs exceed the 45k single-file safety margin.`);
	process.exit(1);
}

writeFileSync(path.join(dist, 'sitemap.xml'), body);
unlinkSync(path.join(dist, chunks[0]));
if (existsSync(path.join(dist, 'sitemap-index.xml'))) unlinkSync(path.join(dist, 'sitemap-index.xml'));
console.log(`sitemap-finalize: merged ${chunks[0]} (${urls} URLs) → sitemap.xml`);
