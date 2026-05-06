import {execSync} from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

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
  // Favicon deliberately omitted until a branded asset is added under static/img/.
  // Docusaurus warns cleanly when the field is absent rather than when it's
  // pointing at a missing file.

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

  // Strict-mode: matches the MkDocs `--strict` posture the project previously had.
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

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  customFields: {
    appVersion: resolveAppVersion(),
    license: 'Apache-2.0',
    goVersion: resolveGoVersion(),
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
      title: 'nl6',
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
