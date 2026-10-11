// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://mcptunnels.terragohan.com',
	integrations: [
		starlight({
			pagefind: false,
			customCss: ['./src/styles/custom.css'],
			title: 'mcptunnels',
			description:
				'Give a local MCP server a public URL with one command. Anonymous, ephemeral, OAuth 2.1-protected tunnels for MCP servers.',
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/terragohan/mcptunnels',
				},
			],
			editLink: {
				baseUrl: 'https://github.com/terragohan/mcptunnels/edit/main/site/',
			},
			head: [
				{
					tag: 'meta',
					attrs: {
						property: 'og:image',
						content: 'https://mcptunnels.terragohan.com/og-image.png',
					},
				},
				{ tag: 'meta', attrs: { property: 'og:image:width', content: '1200' } },
				{ tag: 'meta', attrs: { property: 'og:image:height', content: '630' } },
				{
					tag: 'meta',
					attrs: {
						property: 'og:image:alt',
						content: 'mcptunnels — public URLs for local MCP servers in one command',
					},
				},
				{
					tag: 'meta',
					attrs: {
						name: 'twitter:image',
						content: 'https://mcptunnels.terragohan.com/og-image.png',
					},
				},
			],
			components: {
				Header: './src/components/Header.astro',
				Footer: './src/components/Footer.astro',
				Head: './src/components/Head.astro',
				ThemeProvider: './src/components/ThemeProvider.astro',
			},
			sidebar: [
				{ label: 'Get started', slug: 'get-started' },
				{ label: 'How it works', slug: 'how-it-works' },
				{ label: 'Self-hosting', slug: 'self-hosting' },
				{ label: 'Security', slug: 'security' },
				{ label: 'FAQ', slug: 'faq' },
			],
		}),
	],
});
