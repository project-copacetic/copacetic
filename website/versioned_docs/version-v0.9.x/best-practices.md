---
title: Tagging Guidelines
---

There are some patterns and practices you may want to consider when using Copa to patch images. Remember that these are suggestions that may not fit into your workflow, but we think that staying as close as possible to these practices offers the best experience with Copa.

## Tagging
There are a couple possible patterns that you could follow when tagging patched images.

### Static Incremental Tags
The first approach you could take is incrementing a number you append to the end of an image tag. For example, if you have an image tagged `nginx:1.24.0`, following patches would be tagged as `nginx:1.24.0-1`, `nginx:1.24.0-2`, `nginx:1.24.0-3`, and so on.

With this pattern you are always explicitly aware of the patch state of the image you are using. The downside is that dependabot is currently unable bump to patched images from unmodified images or bump from one patched image to the next.

### Dynamic Tags
Another option is a static tag that is continually reused as new patches are applied. For example, you could have an initial unmodified image that you've tagged `nginx:1.24.0-0` (in this case the `-0` at the end helps identify the base unpatched image). All following patched images are then tagged as `nginx:1.24.0`. You then know that the one tagged image always has the latest patches applied.

This method makes it easy to continually consume the latest patched version of an image, but does contain some tradeoffs. First is that without pinning, image digests could change causing unpredictable behavior. Secondly, if an `ImagePullPolicy` is set to `IfNotPresent`, newly patched images would not be pulled since the tag hasn't changed.

### Dependabot
[Dependabot](https://docs.github.com/en/code-security/dependabot) can create PRs to update image versions to Copa patched versions.

- By default, if no update type is specified, Dependabot will be able to bump from a non-revision version to a revisioned version of an image if it exists. For example from `1.2.3` -> `1.2.3-1`.
- If update type is restricted to patch only, the version would be updated to the patched version unless a minor version exists. For example, `1.2.3` would be updated to `1.2.3-1` and keep bumping revisions (`1.2.3-1 -> 1.2.3-2` etc.) over `1.3.0` or `2.0`. If `1.2.4` exists, however, it would be updated to `1.2.4` instead.
- If patched at build time, Dependabot should pick up the revision of the patch version (`1.2.3-2` -> `1.2.4` -> `1.2.4-1`) to minimize regressions.
