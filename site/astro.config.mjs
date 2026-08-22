// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://terragohan.github.io',
	base: '/mcptunnels',
	integrations: [
		starlight({
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
			sidebar: [
				{ label: 'Get started', slug: 'get-started' },
				{ label: 'How it works', slug: 'how-it-works' },
				{ label: 'Self-hosting', slug: 'self-hosting' },
				{ label: 'Security', slug: 'security' },
				{ label: 'FAQ', slug: 'faq' },
				{ label: 'Roadmap', slug: 'roadmap' },
			],
		}),
	],
});
