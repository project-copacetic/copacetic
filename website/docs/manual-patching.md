---
title: Manual Patch Rules
---

Copa supports patching files in images that do not expose a package manager.
Supply a YAML file describing the replacements and pass it with `--manual-rule`.

## YAML Schema

The manual rules file must contain a `rules` array, where each rule specifies:

- **target**: The file to replace in the image
  - `path`: Absolute path to the file in the image
  - `sha256`: (Optional) SHA256 hash to verify the file before replacement
- **replacement**: The new file to copy
  - `source`: Docker image containing the replacement file
  - `internalPath`: Path to the file within the source image
  - `sha256`: (Optional) SHA256 hash of the replacement file
  - `mode`: File permissions (e.g., 0755 for executables, 0644 for regular files)

## Examples

### Single File Replacement

Example `manual-rule.yaml`:

```yaml
rules:
  - target:
      path: /usr/local/bin/foo
      sha256: "a3b1c6d9e2f5a8b1c3d6e9f2a5b8c1d3e6f9"
    replacement:
      source: registry.example.com/patches/foo-fixed:1.0
      internalPath: /bin/foo
      sha256: "9c5589abc123def456789012345678901234"
      mode: 0755
```

### Multiple File Replacements

You can patch multiple files in a single operation:

```yaml
rules:
  - target:
      path: /usr/bin/vulnerable-binary
      sha256: "deadbeef123456789abcdef0123456789abcdef0"
    replacement:
      source: docker.io/library/busybox:latest
      internalPath: /bin/busybox
      sha256: "cafebabe987654321fedcba0987654321fedcba0"
      mode: 0755
  - target:
      path: /etc/vulnerable.conf
      sha256: "badc0de123456789abcdef0123456789abcdef01"
    replacement:
      source: myregistry.io/configs/fixed:v1.0
      internalPath: /etc/fixed.conf
      sha256: "goodc0de987654321fedcba0987654321fedcba0"
      mode: 0644
```

## Usage

Patch an image with manual rules:

```bash
# Apply manual patches
copa patch -i myimage:latest -m manual-rule.yaml -t myimage:patched
```

## Important Notes

- **Manual rules and vulnerability reports are mutually exclusive**: You cannot use `--manual-rule` with `--report` or `--report-directory`. Manual patching is intended for cases where vulnerability scanning is not applicable.
- **SHA256 verification is optional but recommended for security**:
  - Target file SHA256 verification ensures you're replacing the expected file
  - Replacement file SHA256 verification ensures the source file is correct before copying
- The `sha256` field can include or omit the "sha256:" prefix
- File permissions are preserved using the `mode` field
- The source images must be accessible from your Docker registry
- If no tag is specified with `-t`, Copa will append "-patched" to the original tag
