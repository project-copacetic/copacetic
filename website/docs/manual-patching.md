---
title: Manual Patch Rules
---

Copa supports patching files in images that do not expose a package manager.
Supply a YAML file describing the replacement and pass it with `--manual-rule`.

Example `manual-rule.yaml`:

```yaml
target:
  path: /usr/local/bin/foo
  sha256: "a3b1...deadbeef"
replacement:
  source: registry.example.com/patches/foo-fixed:1.0
  internalPath: /bin/foo
  sha256: "9c55...cafefeed"
  mode: 0755
```

Patch an image with the rule:

```bash
copa patch -i myimage:latest -m manual-rule.yaml
```
