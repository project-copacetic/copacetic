---
title: Update All Packages
---

Copa can be used to update all outdated packages in a container, regardless of vulnerability status.

Simply run Copa as usual and omit the report flag:

    ```bash
        copa patch -i docker.io/library/nginx:1.21.6
    ```
