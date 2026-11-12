---
title: OCI Image Layouts
---

An [OCI Image Layout](https://github.com/opencontainers/image-spec/blob/main/image-layout.md) is a directory that stores an image on disk: an `oci-layout` marker file, an `index.json`, and a `blobs/` directory. `skopeo copy` writes one directly. `docker save` (Docker 25 and later) and `docker buildx build --output type=oci` write it as a tar archive, so extract the archive into a directory before passing it to Copa, or use `--output type=oci,dest=<dir>,tar=false` with buildx. Layouts are common in air-gapped and pipeline workflows where images are passed around as files instead of through a registry.

Copa works with OCI layouts in two directions:

- **Output:** write a patched image to a new layout with `--oci-dir`.
- **Input:** patch an image that is stored as a layout with `--input-oci-layout`.

## Writing a Patched Image to a Layout

When you patch a multi-platform image without `--push`, `--oci-dir` writes the complete patched index to a layout directory, including the patched platforms and the platforms preserved unchanged:

```bash
copa patch \
  --image docker.io/library/nginx:1.25.0 \
  --platform linux/amd64,linux/arm64 \
  --tag nginx:1.25.0-patched \
  --oci-dir ./nginx-patched
```

- Copa also loads each patched platform image into the local image store, as described in [Multi-Platform Patching](./multiplatform-patching.md).
- `--oci-dir` is not written for a single-platform image patched by name; that image is loaded into the local image store instead.
- Preserved platforms keep their original blobs and layer compression. New patch layers use `--compression` (default `uncompressed`); see the [Quick Start](./quick-start.md) for details.
- In [bulk mode](./bulk-image-patching.md), `--oci-dir` applies to every job in the config.

## Patching an Image from a Layout

`--input-oci-layout` reads the source image directly from a layout directory. The source is never loaded into Docker or Podman, pulled from a registry, or modified, and the patched image is written to a new layout with `--oci-dir`. This works for both single-platform images and multi-platform indexes.

### Example

```bash
# 1. Get a layout (any OCI layout works)
skopeo copy docker://docker.io/library/nginx:1.25.3 oci:./nginx-layout:1.25.3

# 2. Scan it
trivy image --input ./nginx-layout --pkg-types os --ignore-unfixed -f json -o report.json

# 3. Patch it into a new directory
copa patch \
  --input-oci-layout ./nginx-layout \
  --report report.json \
  --tag example.com/acme/nginx:1.25.3-patched \
  --oci-dir ./nginx-patched \
  --output vex.json

# 4. Use the result, for example by copying it to a registry
skopeo copy oci:./nginx-patched docker://example.com/acme/nginx:1.25.3-patched
```

Omit `--report` to update every package, or pass `--platform` to patch only some platforms of a multi-platform index. The [multi-platform patching strategies](./multiplatform-patching.md#multi-platform-patching-strategies) apply unchanged.

### Selecting the Image

If the layout contains one top-level image, `--image` is optional. A multi-platform index counts as one image, and non-image artifacts in the layout are ignored.

If the layout contains several images, select one with `--image`:

```bash
copa patch --input-oci-layout ./layout --image example.com/acme/app:1.0 --oci-dir ./patched
```

The selector can be a full image name (`io.containerd.image.name`), a tag (`org.opencontainers.image.ref.name`), or a digest such as `sha256:...`. It must match exactly one image; otherwise Copa fails and lists the available selectors.

### Naming the Output

The output name comes from the selected image's `io.containerd.image.name` annotation, using the usual `--tag` and `--tag-suffix` rules. A bare tag such as `1.25.3` or `latest`, which is what `skopeo copy` writes, does not include a repository, so in that case pass a full reference with `--tag`, as in the example above. Naming only labels the output. It never pushes the image or records the local layout path.

### Selecting Platforms

For a multi-platform index:

- Without `--platform` or a report, Copa patches every supported platform.
- With `--platform`, a single report, or a report directory, Copa patches only the matching platforms. Every other platform is preserved byte-for-byte, including unsupported platforms such as Windows.
- Each explicit or report target must match exactly one platform in the source. A report without platform metadata can only be used with a single-platform source; for a multi-platform source, pass `--platform`.
- With `--ignore-errors`, a platform that fails is preserved unchanged as long as another platform is patched. If every platform fails, no output is written.

### Output and VEX

- `--oci-dir` is required and must be a new directory outside the input layout. Copa writes the result atomically: it fails, and leaves the existing path untouched, if the destination already exists or is created by another process during the export.
- With a report, `--output` writes VEX that names the patched platform manifest digests in the output layout. Preserved platforms get no remediation claim, and no VEX is written without a report.
- Copa adds its patch annotations and keeps the source's index, manifest, and descriptor annotations in their original places.

### Limitations

- `--push`, `--loader`, `--config`, and `--chart` cannot be used with `--input-oci-layout`. To publish or load the result, see [Using an Output Layout](#using-an-output-layout).
- Copa does not patch its own output again. If a selected platform carries Copa's `sh.copa.image.patched` annotation, Copa stops before patching. Patch the original layout instead, and rescan it rather than reusing a report scanned from the patched image.
- An image index nested below the selected index is not supported.
- In-place updates, `copa generate` and BuildKit frontend support, direct registry push, and preservation of signatures, attestations, and referrers are not included.
- Local and remote BuildKit both work, because the layout is sent through the BuildKit session; a remote daemon needs no access to the input path. Tooling images and package repositories may still require network access.

<details>
<summary>Validation and edge-case details</summary>

**Input validation.** Before patching, Copa checks the selected content and fails on missing or corrupt blobs, artifact inputs, unsupported image media types, nonempty manifest or index body media types that disagree with their descriptors, and descriptor platform metadata that conflicts with the image config. When a platform manifest descriptor omits the optional `platform` field, Copa discovers the platform from the image config; preserved descriptors keep the field omitted. A source with no supported patch platform is rejected before Copa connects to BuildKit. Nested indexes are rejected before patching.

**Image selection.** A selector must match one image unambiguously across both annotation keys. A full image name never falls back to a matching bare tag on a different named repository. Aliases sharing the selected digest must agree on media type, size, artifact type, and any declared platform; aliases that differ only in annotations are allowed. Descriptors identifying non-image artifacts do not make a single image ambiguous. Standard OCI and Docker image config types in a descriptor's `artifactType` are accepted when they agree with the referenced image config.

**Output naming.** If the source name is missing or ambiguous, Copa requires a full tagged `--tag`. It never invents a source name for provenance.

**Platform targets.** Explicit and report-derived targets must match the source even when it has only one platform. Equivalent selectors are deduplicated after resolving against the source, including with a single report, and a single report must still target exactly one platform. Ambiguous platform constraints fail rather than choosing the first match. Reports that target an unsupported platform are rejected, and unsupported OS reports in a report directory are not silently skipped.

**Paths.** Keep `--working-folder` and VEX `--output` outside the output directory, including through symlinks whose targets do not exist yet. A parent work directory is supported, and work cleanup completes before the output is published. Do not set `TMPDIR` to the input directory or a directory inside it, including through a symlink. A VEX `--output` that is the same file as one in the input, such as a hard link to a blob, is rejected. VEX `--output` must be an existing regular file or a new file in an existing directory, and `--format` must be supported; Copa checks both before patching, because VEX is written after the output layout is published.

**Re-patch detection.** The check looks for `sh.copa.image.patched` on each targeted platform's manifest or its index descriptor. Index-level markers and markers on preserved platforms do not block a patch. An image built from a patched image does not inherit its manifest annotations, so it is patched from its own content; Copa does not follow an inherited `BaseImage` label for layout input. Because detection relies on the annotation, it misses a patched image whose annotations were dropped, for example by a Docker-format export, and it stops images that had the annotation copied onto them. Recovering the original image from a patched layout is not supported.

**Annotations.** Index, manifest-body, and descriptor annotations keep their scopes, including different values for the same key. Copa updates its own patch metadata and the documented mutable image metadata.

</details>

## Using an Output Layout

An output layout is a standard OCI layout, so the usual tools work with it:

```bash
# Scan it
trivy image --input ./nginx-patched

# Copy it to a registry
skopeo copy oci:./nginx-patched docker://example.com/acme/nginx:1.25.3-patched

# Load it into Docker
tar -C ./nginx-patched -cf - . | docker load
```

`docker load` reads an OCI layout archive only when Docker uses the [containerd image store](https://docs.docker.com/engine/storage/containerd/).

For a multi-platform layout:

- Pass `--all` to `skopeo copy` to copy every platform.
- `trivy image --input` scans only one platform of the index. To scan a specific platform, copy it to a single-platform layout first:

  ```bash
  skopeo copy --override-arch arm64 oci:./nginx-patched oci:./nginx-patched-arm64:scan
  trivy image --input ./nginx-patched-arm64
  ```
