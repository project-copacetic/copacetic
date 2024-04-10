/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */

// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  sidebar: [
    {
      type: 'category',
      label: 'Getting Started',
      collapsed: false,
      items: [
        'introduction',
        'installation',
        'quick-start',
        'best-practices',
        'troubleshooting',
        'faq',
      ],
    },
    {
      type: 'category',
      label: 'Features',
      collapsed: false,
      items: [
        'github-action',
        'custom-address',
        'output',
        'scanner-plugins',
      ],
    },
    {
      type: 'category',
      label: 'Contributing',
      collapsed: false,
      items: [
        'contributing',
        'code-of-conduct',
        'design',
        'development-tips',
        'maintainer-guidelines',
        'release',
      ],
    },
  ],
};

module.exports = sidebars;
