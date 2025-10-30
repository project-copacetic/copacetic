---
title: VEX Output
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
copa patch -i mcr.microsoft.com/azure-cli:2.50.0 -r report.json -t 2.50.0-patched --format="openvex" --output "vex.json"
```

This will generate a VEX Document that looks like:

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/public/vex-e635674468f708838b7bd1b61b1c39bcf98639318eebfb510db519d947a5c204",
  "author": "Project Copacetic",
  "timestamp": "2025-09-10T16:52:53.988017858Z",
  "version": 1,
  "tooling": "Project Copacetic",
  "statements": [
    {
      "vulnerability": {
        "@id": "CVE-2024-0727"
      },
      "products": [
        {
          "@id": "pkg:oci/azure-cli@sha256:b40133b2ab18d506f54e4d42083cb95f814d8397d7ef95abe28e897c18e3091d",
          "subcomponents": [
            {
              "@id": "pkg:apk/alpine/libcrypto3@3.1.4-r5?arch=amd64"
            },
            {
              "@id": "pkg:apk/alpine/libssl3@3.1.4-r5?arch=amd64"
            },
            {
              "@id": "pkg:apk/alpine/openssl@3.1.4-r5?arch=amd64"
            },
            {
              "@id": "pkg:apk/alpine/openssl-dev@3.1.4-r5?arch=amd64"
            },
            {
              "@id": "pkg:pypi/cryptography@41.0.6"
            }
          ]
        }
      ],
      "status": "fixed"
    }
  ]
}
```