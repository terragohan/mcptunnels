#!/usr/bin/env node
// Postbuild step: also serve the generated URL set at the conventional
// /sitemap.xml path. @astrojs/sitemap writes sitemap-index.xml + sitemap-0.xml
// and offers no rename; nothing in the sitemap protocol requires the filename
// sitemap.xml (robots.txt declares the real location), but naive tools probe
// it. Chained onto `astro build` in package.json, and verified by
// scripts/seo-check.mjs — never edit dist by hand.
import { copyFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const dist = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../dist');
const src = path.join(dist, 'sitemap-0.xml');
const dst = path.join(dist, 'sitemap.xml');

if (!existsSync(src)) {
	console.error('sitemap-alias: sitemap-0.xml missing — did `astro build` run its sitemap step?');
	process.exit(1);
}
copyFileSync(src, dst);
console.log('sitemap-alias: dist/sitemap-0.xml → dist/sitemap.xml');
