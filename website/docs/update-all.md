---
title: Update All Outdated Packages
---

To update all outdated packages, regardless of their vulnerability status, you can run Copa without providing any scan report.

```bash
    copa patch -i docker.io/library/nginx:1.21.6
 ```

This will patch the original image by upgrading all packages to their latest available version.

:::note

Upgrading all packages might introduce compatibility issues or break existing functionality. Test the patched image to ensure stability.

:::