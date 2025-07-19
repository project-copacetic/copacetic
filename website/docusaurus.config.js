// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer').themes.github;
const darkCodeTheme = require('prism-react-renderer').themes.dracula;
require('dotenv').config()

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'Copacetic',
  url: 'https://project-copacetic.github.io',
  baseUrl: '/copacetic/website/',
  onBrokenLinks: 'ignore',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/favicon.ico',
  trailingSlash: false,

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'project-copacetic', // Usually your GitHub org/user name.
  projectName: 'copacetic', // Usually your repo name.
  deploymentBranch: 'gh-pages',

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: require.resolve('./sidebars.js'),
          routeBasePath: '/',
        },
        blog: false,
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
        gtag: {
          trackingID: 'G-3RC20QPKNS',
          anonymizeIP: true,
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({  
      colorMode: {
        defaultMode: 'dark',
      },
      navbar: {
        title: 'Copacetic',
        logo: {
          alt: 'Copacetic Logo',
          src: 'img/logo.png',
          href: 'https://project-copacetic.github.io/copacetic/',
        },
        items: [
          {
            type: 'docsVersionDropdown',
            position: 'right',
          },
          {
            href: 'https://cloud-native.slack.com/archives/C071UU5QDKJ',
            position: 'right',
            className: 'header-slack-link',
            'aria-label': 'Slack Connection',
          },
          {
            href: 'https://github.com/project-copacetic/copacetic',
            position: 'right',
            className: 'header-github-link',
            'aria-label': 'GitHub repository',
          },
        ],
      },
      footer: {
        style: 'dark',
        copyright: `Copyright © ${new Date().getFullYear()} Linux Foundation. The Linux Foundation® (TLF) has registered trademarks and uses trademarks. For a list of TLF trademarks, see <a href="https://www.linuxfoundation.org/trademark-usage/">Trademark Usage</a>.`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
      },
      algolia: {
        // For forked PRs, secrets arent available, so we use dummy values to allow build checks to complete
        appId: process.env.ALGOLIA_ID || 'DUMMY_APP_ID_FOR_BUILDS',
        apiKey: process.env.ALGOLIA_API_KEY || 'DUMMY_API_KEY_FOR_BUILDS',
        indexName: 'project-copaceticio',
        contextualSearch: true,
      }
    }),
};

module.exports = config;
