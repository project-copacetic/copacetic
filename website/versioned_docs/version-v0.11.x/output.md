---
title: Output
---

:::caution

Experimental: This feature might change without preserving backwards compatibility.

:::

Copa optionally outputs a Vulnerability Exploitability eXchange (VEX) file as a result of the patching process to surface the vulnerabilities and packages that were patched.

Currently, Copa supports the [OpenVEX](https://github.com/openvex) format, but it can be extended to support other formats.

## OpenVEX

OpenVEX is an implementation of Vulnerability Exploitability eXchange (VEX) format. For more information, see [OpenVEX specification](https://github.com/openvex/spec/).

:::tip

- Use `COPA_VEX_AUTHOR` environment variable to set the author of the VEX document. If it's not set, the author will default to `Project Copacetic`.

- A VEX document must contain at least one VEX statement. If there are no fixed vulnerabilities, Copa will not generate a VEX document.

:::

To generate a VEX document using OpenVEX, use `--format="openvex"` flag, and use `--output` to specify a file path. For example:

```bash
copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched --format="openvex" --output "nginx.1.21.6-vex.json"
```

This will generate a VEX Document that looks like:

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/public/vex-a6c44ec1d79e9dd4190dc01b4ecf7527ebb26bd37c01e32e6efcd203ae00d2a5",
  "author": "Project Copacetic",
  "timestamp": "2023-10-11T00:15:00.114768055Z",
  "version": 1,
  "tooling": "Project Copacetic",
  "statements": [
    {
      "vulnerability": {
        "@id": "CVE-2021-22945"
      },
      "products": [
        {
          "@id": "pkg:oci/docker.io/library/nginx:1.21.6-patched",
          "subcomponents": [
            {
              "@id": "pkg:deb/debian/curl@7.74.0-1.3+deb11u2?arch=amd64"
            },
            {
              "@id": "pkg:deb/debian/libcurl4@7.74.0-1.3+deb11u2?arch=amd64"
            }
          ]
        }
      ],
      "status": "fixed"
    },
    ...
}
```