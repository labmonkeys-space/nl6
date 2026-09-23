import {execSync} from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';
import cspMetaPlugin from './src/plugins/csp-meta';

// Resolved at build time and exposed to the landing page via `customFields`.
// Precedence: APP_VERSION env (CI override) > latest git tag > 'dev' (shallow
// clone or pre-tag checkout). Keeping this logic in config avoids shipping a
// hardcoded version string that drifts from releases. Only stable `vX.Y.Z`
// tags are ever published (RCs live on the floating `:rc` Docker tag pushed
// from main by ci.yml, not as git tags), so no pre-release filter is needed.
function resolveAppVersion(): string {
  if (process.env.APP_VERSION) return process.env.APP_VERSION;
  try {
    return execSync('git describe --tags --abbrev=0', {
      stdio: ['ignore', 'pipe', 'ignore'],
    })
      .toString()
      .trim();
  } catch {
    return 'dev';
  }
}

// Parsed from go/go.mod so the landing page tracks the toolchain the binary
// is actually built against. We surface only MAJOR.MINOR to match the marketing
// style used elsewhere on the page (e.g. "go 1.26+").
function resolveGoVersion(): string {
  const modPath = path.join(__dirname, 'go', 'go.mod');
  const src = fs.readFileSync(modPath, 'utf8');
  const match = src.match(/^go\s+(\d+\.\d+)(?:\.\d+)?/m);
  if (!match) throw new Error(`Could not parse Go version from ${modPath}`);
  return `Go ${match[1]}`;
}

const config: Config = {
  title: 'nl6',
  tagline: 'Network device simulator — SNMP/SSH/HTTPS at 30,000-device scale',
  favicon: 'img/nl6-logo.svg',

  future: {
    v4: true,
  },

  // Canonical published URL — custom domain at the apex.
  url: 'https://nl6.eu',
  baseUrl: '/',

  // GitHub Pages deployment config.
  organizationName: 'labmonkeys-space',
  projectName: 'nl6',
  trailingSlash: false,

  // Strict mode: fail the build on any broken link or anchor.
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  themes: [
    '@docusaurus/theme-mermaid',
    [
      // Local full-text search. Algolia DocSearch is out of scope for phase 1
      // (application process is multi-day); swap later without docs churn.
      '@easyops-cn/docusaurus-search-local',
      {
        hashed: true,
        language: ['en'],
        indexDocs: true,
        indexBlog: false,
        docsRouteBasePath: '/',
      },
    ],
  ],

  plugins: [
    // Mermaid pulls in langium → vscode-languageserver-types, whose UMD
    // bundle does a dynamic `require(...)` webpack cannot statically analyze,
    // emitting a benign "Critical dependency" warning on every build. Silence
    // only that one warning (matched by module + message) so genuine warnings
    // stay visible.
    () => ({
      name: 'ignore-langium-umd-warning',
      configureWebpack: () => ({
        ignoreWarnings: [
          {
            module: /vscode-languageserver-types/,
            message: /Critical dependency/,
          },
        ],
      }),
    }),

    // Old URLs from before the docs/explanation/ section existed. Each entry
    // emits a static HTML page at the old path that forwards to the new one,
    // so bookmarks and search-engine results keep working. Must run BEFORE
    // csp-meta (below), which hashes the inline script those pages carry.
    [
      '@docusaurus/plugin-client-redirects',
      {
        redirects: [
          {from: '/reference/architecture', to: '/explanation/architecture'},
          {from: '/ops/kubernetes', to: '/explanation/kubernetes'},
          {from: '/reference/snmp-data-fidelity', to: '/explanation/snmp-data-fidelity'},
          {from: '/reference/loadtest-collector-ceiling', to: '/explanation/loadtest-collector-ceiling'},
          {from: '/reference/loadtest-scenarios', to: '/ops/loadtest-scenarios'},
          {from: '/reference/loadtest-runbooks', to: '/ops/loadtest-runbooks'},
          // Retired: design plans for external repositories (probler, l8parser).
          {from: ['/reference/gpu/proto-model', '/reference/gpu/pollaris'], to: '/reference/gpu'},
        ],
      },
    ],

    // Content-Security-Policy as a <meta http-equiv> on every built page.
    // GitHub Pages serves the site and cannot be given custom response
    // headers, so meta delivery is the only option. Must stay LAST: it
    // rewrites the emitted HTML in postBuild and hashes the inline scripts it
    // finds there, so any plugin that also touches the output has to run
    // before it. See src/plugins/csp-meta.ts.
    cspMetaPlugin,
  ],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  customFields: {
    appVersion: resolveAppVersion(),
    license: 'Apache-2.0',
    goVersion: resolveGoVersion(),
    // Literals on purpose. GitHub normalises the `github:` key in
    // .github/FUNDING.yml to the *profile* URL (github.com/indigo423), not the
    // sponsors checkout — so these must not be derived from that file.
    sponsorUrl: 'https://github.com/sponsors/indigo423',
    koFiUrl: 'https://ko-fi.com/indigo423',
  },

  presets: [
    [
      'classic',
      {
        docs: {
          path: 'docs',
          routeBasePath: '/',
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/labmonkeys-space/nl6/edit/main/',
          // docs/superpowers/ holds design specs and implementation plans
          // (working documents committed for the engineering record). They
          // are not site pages: excluded here so the build never routes
          // them, and scripts/check-doc-orphans.mjs skips the same prefix.
          // Setting `exclude` REPLACES the plugin defaults, so they are
          // restated.
          exclude: [
            '**/_*.{js,jsx,ts,tsx,md,mdx}',
            '**/_*/**',
            '**/*.test.{js,jsx,ts,tsx}',
            '**/__tests__/**',
            'superpowers/**',
          ],
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      respectPrefersColorScheme: true,
    },
    navbar: {
      logo: {
        alt: 'nl6 — network device simulator',
        src: 'img/nl6-logo-with-text.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'gettingStarted',
          position: 'left',
          label: 'Getting Started',
        },
        {
          type: 'docSidebar',
          sidebarId: 'ops',
          position: 'left',
          label: 'Ops',
        },
        {
          type: 'docSidebar',
          sidebarId: 'reference',
          position: 'left',
          label: 'Reference',
        },
        {
          type: 'docSidebar',
          sidebarId: 'explanation',
          position: 'left',
          label: 'Explanation',
        },
        {
          href: 'https://github.com/labmonkeys-space/nl6',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Quick Start', to: '/getting-started/quick-start'},
            {label: 'CLI Flags', to: '/reference/cli-flags'},
            {label: 'Web API', to: '/reference/web-api'},
          ],
        },
        {
          title: 'Project',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/labmonkeys-space/nl6',
            },
            {
              label: 'Issues',
              href: 'https://github.com/labmonkeys-space/nl6/issues',
            },
            {
              label: 'Releases',
              href: 'https://github.com/labmonkeys-space/nl6/releases',
            },
          ],
        },
        {
          title: 'Legal',
          items: [
            {label: 'Imprint', to: '/imprint'},
            {label: 'Privacy', to: '/privacy'},
          ],
        },
      ],
      copyright: `© ${new Date().getFullYear()} Labmonkeys Space. Licensed under Apache-2.0. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'yaml', 'json', 'go', 'python', 'diff'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
