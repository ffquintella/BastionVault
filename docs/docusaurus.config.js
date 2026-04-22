const versions = require('./versions.json');
const {themes} = require('prism-react-renderer');
const lightTheme = themes.github;
const darkTheme = themes.dracula;

function getNextMinorVersionName() {
  const lastVersion = versions[0];
  let majorVersion = parseInt(lastVersion.split('.')[0]);
  let minorVersion = parseInt(lastVersion.split('.')[1]);
  if (majorVersion >= 1) {
    minorVersion += 1;
  } else {
    majorVersion = 0;
    minorVersion = 1;
  }
  return `${majorVersion}.${minorVersion}.x`;
}

/** @type {import('@docusaurus/types').DocusaurusConfig} */
module.exports = {
  title: 'BastionVault',
  tagline: 'A Rust secret management fork with a different library direction.',
  url: 'https://ffquintella.github.io',
  baseUrl: '/',
  onBrokenLinks: 'throw',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },
  favicon: 'img/bastionvault.png',
  organizationName: 'ffquintella',
  projectName: 'BastionVault',
  trailingSlash: true,
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },
  themeConfig: {
    colorMode: {
      defaultMode: 'light',
      disableSwitch: false,
      respectPrefersColorScheme: false,
    },
    image: 'img/BastionVault-arch.svg',
    metadata: [
      {name: 'keywords', content: 'rust, hashicorp-vault, key-management, secure-storage, secrets-management, key-manager-service, secrets-manager, cloudnative-services'},
    ],
    navbar: {
      title: 'BastionVault',
      logo: {
        alt: 'BastionVault Logo',
        src: 'img/bastionvault.png',
      },
      items: [
        {
          type: 'docSidebar',
          position: 'left',
          sidebarId: 'tutorialSidebar',
          label: 'Docs',
        },
        {
          to: 'https://crates.io/crates/bastion_vault',
          label: 'Crate',
          position: 'right',
        },
        {
          to: 'https://github.com/ffquintella/BastionVault',
          label: 'GitHub',
          position: 'right',
        },
        {
          type: 'docsVersionDropdown',
          position: 'right',
          dropdownActiveClassDisabled: true,
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/quick-start/',
            },
            {
              label: 'API Reference',
              to: 'https://docs.rs/bastion_vault/',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'GitHub Discussions',
              to: 'https://github.com/ffquintella/BastionVault/discussions',
            },
            {
              label: 'Issues',
              to: 'https://github.com/ffquintella/BastionVault/issues',
            },
          ],
        },
      ],
      copyright: `Copyright © 2021-${new Date().getFullYear()} BastionVault. Built with Docusaurus.`,
    },
    prism: {
      additionalLanguages: [
        'toml',
        'rust',
        'bash',
        'json',
      ],
      theme: lightTheme,
      darkTheme: darkTheme,
    },
    announcementBar: {
      id: 'bastionvault-bar',
      content: 'BastionVault is a fork of RustyVault with a different library approach. <a target="_blank" href="https://github.com/ffquintella/BastionVault">Follow the fork on GitHub</a>.',
    },
  },
  themes: [
    [
      "@easyops-cn/docusaurus-search-local",
      /** @type {import("@easyops-cn/docusaurus-search-local").PluginOptions} */
      ({
        hashed: true,
        language: ["en"],
        highlightSearchTermsOnTargetPage: true,
        explicitSearchResultPath: true,
      }),
    ],
  ],
  presets: [
    [
      '@docusaurus/preset-classic',
      {
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          editUrl: 'https://github.com/ffquintella/BastionVault/edit/main/docs/',
          showLastUpdateAuthor: true,
          showLastUpdateTime: true,
          versions: {
            current: {
              label: `${getNextMinorVersionName()} 🚧`,
            },
          },
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
        sitemap: {
          changeFreq: 'daily',
          priority: 0.8,
        },
      },
    ],
  ],
};
