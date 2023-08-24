---
title: Output
---

Copa optionally outputs a Vulnerability Exploitability eXchange (VEX) file as a result of the patching process to surface the vulnerabilities and packages that were patched.

Currently, Copa supports the OpenVEX format, but it can be extended to support other formats as well.

## OpenVEX

OpenVEX is an implementation of Vulnerability Exploitability eXchange (VEX) format. For more information, see [OpenVEX specification](https://github.com/openvex/spec/).

To generate a VEX document using OpenVEX, use `--format="openvex"` flag, and use `--output` to specify a file path. For example:

```bash
copa patch -i docker.io/library/nginx:1.21.6 -r nginx.1.21.6.json -t 1.21.6-patched --format="openvex" --output "nginx.1.21.6-vex.json"
```

This will generate a VEX Document that looks like:

```json
{
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/public/vex-6776bfe4124807727d1a9fa90af438838efcf4454c4ed28253a3063ed64210a0",
  "author": "Project Copacetic",
  "role": "",
  "timestamp": "2023-08-24T23:04:51.41869446Z",
  "version": "0.1",
  "tooling": "Project Copacetic",
  "statements": [
    {
      "vulnerability": "CVE-2021-3995",
      "products": [
        "pkg:deb/debian/bsdutils@1:2.36.1-8?amd64",
        "pkg:deb/debian/libblkid1@2.36.1-8?amd64",
        "pkg:deb/debian/libmount1@2.36.1-8?amd64",
        "pkg:deb/debian/libsmartcols1@2.36.1-8?amd64",
        "pkg:deb/debian/libuuid1@2.36.1-8?amd64",
        "pkg:deb/debian/mount@2.36.1-8?amd64",
        "pkg:deb/debian/util-linux@2.36.1-8?amd64"
      ],
      "status": "fixed"
    },
    ...
}
```