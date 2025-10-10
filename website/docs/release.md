---
title: Release Process
---

## Overview

This document describes the release management process for the Copacetic project, including release versioning, supported releases, upgrade guidelines, and operational details for cutting and publishing releases.

## Frequently Asked Questions

- **What versioning scheme does Copacetic use?** Copacetic uses semantic versioning with the format `vX.Y.Z`, where X is the major version, Y is the minor version, and Z is the patch version. All release tags are prefixed with `v` (e.g., `v0.10.0`).
- **What constitutes a breaking change?** Breaking changes include schema changes, flag changes, or behavioral changes in Copacetic that may require a clean installation during upgrade and may introduce changes that could break backward compatibility.
- **How are milestones used in the release process?** Milestones are designed to encapsulate feature sets that fit within a 3-month release cycle, including testing gates. GitHub's milestones are used by maintainers to manage each release, with PRs and Issues tracked as part of corresponding milestones.
- **What are patch releases?** Patch releases contain applicable fixes, including security fixes, that may be backported to supported releases, depending on severity and feasibility.
- **What testing is required before a release?** Test gates include relevant integration and unit tests to ensure release quality and stability before any release is published.

## Release Versioning

All releases follow the format `vX.Y.Z`, where X is the major version, Y is the minor version, and Z is the patch version. Copacetic uses [semantic versioning](https://semver.org/).

- **Major Releases:** Introduce incompatible API changes or significant design overhauls. As of now, Copacetic is in v0 and has not had a major version increase.
- **Minor Releases:** Add new features in a backward-compatible manner. E.g., v0.9.0, v0.10.0.
- **Patch Releases:** Contain backward-compatible bug fixes or security patches. E.g., v0.6.1, v0.6.2.

### Tagging Strategy

- All release tags are prefixed with `v`, e.g., `v0.10.0`.
- Tags are created on the default branch (typically `main`), or on a release branch when applicable.
- Patch releases increment the Z portion, e.g., `v0.6.1` → `v0.6.2`.
- Minor releases increment the Y portion, e.g., `v0.9.0` → `v0.10.0`.
- Pre-releases (alpha, beta, rc) are not currently in use, but should follow the pattern `vX.Y.Z-rc.N`, etc., if introduced.

## Release Process

Copacetic uses [GoReleaser](https://goreleaser.com/) for automating releases. The release process differs depending on whether you're cutting a major/minor release or a patch release.

### Major/Minor Release Process

For major and minor releases (e.g., v0.11.0, v0.12.0, v1.0.0):

1. **Prepare the Release Branch**

   ```sh
   git checkout main
   git pull upstream main
   ```

2. **Create and Push the Tag**

   ```sh
   git tag -a <NEW VERSION> -m '<NEW VERSION>'
   git push upstream <NEW VERSION>
   ```

3. **Publishing**
   - GoReleaser will automatically create a new release.
   - Release branches are automatically created during the release process. When a tag is pushed, the GitHub workflow automatically creates a corresponding release branch.
   - Review and edit the release at: [GitHub Releases](https://github.com/project-copacetic/copacetic/releases)
   - Review the respective copa-action image at: [GitHub Container Registry](https://github.com/project-copacetic/copacetic/pkgs/container/copa-action)
   - Review the respective copa-extension image at: [GitHub Container Registry](https://github.com/project-copacetic/copacetic/pkgs/container/copa-extension)

### Patch Release Process

For patch releases (e.g., `v<MAJOR>.<MINOR>.<PATCH>`) that contain bug fixes or security patches:

1. **Check out Release Branch**

   Check out release branch from the tag:

   ```sh
   git checkout release-<MAJOR>.<MINOR>
   git pull upstream release-<MAJOR>.<MINOR>
   ```

2. **Cherry-pick the Fix**

   Cherry-pick the commit(s) that contain the fix from the main branch:

   ```sh
   git cherry-pick <COMMIT_HASH>
   ```

   For multiple commits:

   ```sh
   git cherry-pick <COMMIT_HASH_1> <COMMIT_HASH_2>
   ```

3. **Open a Pull Request**

   Create a PR to the release branch:

   ```sh
   git push upstream release-<MAJOR>.<MINOR>
   gh pr create --base release-<MAJOR>.<MINOR> --title "Cherry-pick fix for v<MAJOR>.<MINOR>.<PATCH>" --body "Cherry-picking fix from main branch for patch release v<MAJOR>.<MINOR>.<PATCH>"
   ```

4. **Review and Merge**

   - Get the PR reviewed by maintainers
   - Ensure all CI checks pass
   - Merge the PR to the release branch

5. **Tag the Release**

   After the PR is merged, tag the release from the release branch:

   ```sh
   git checkout release-<MAJOR>.<MINOR>
   git pull upstream release-<MAJOR>.<MINOR>
   git tag -a v<MAJOR>.<MINOR>.<PATCH> -m "Release v<MAJOR>.<MINOR>.<PATCH>"
   git push upstream v<MAJOR>.<MINOR>.<PATCH>
   ```

6. **Publishing**
   - GoReleaser will automatically create a new release
   - Review and edit the release at: [GitHub Releases](https://github.com/project-copacetic/copacetic/releases)
   - Review the respective copa-action image at: [GitHub Container Registry](https://github.com/project-copacetic/copacetic/pkgs/container/copa-action)
   - Review the respective copa-extension image at: [GitHub Container Registry](https://github.com/project-copacetic/copacetic/pkgs/container/copa-extension)

## Supported Releases

Applicable fixes, including security fixes, may be cherry-picked into the release branch depending on severity and feasibility. Patch releases are cut from that branch as necessary.

Users are encouraged to stay reasonably up-to-date with Copacetic versions in production. While immediate upgrades are not required, users should aim to run at least the latest patch release of their chosen minor version.

Copacetic aims to "support" the current major.minor release (n). "Support" means maintainers expect that users may be running that version in production and will provide patches for critical issues. For example, when v0.10.0 is released, v0.9.x will no longer be supported for patches, and users are encouraged to upgrade to the supported version as soon as possible.

## Supported Platforms

Copacetic maintains compatibility with the currently supported versions of its underlying platforms and dependencies. For example, if Copacetic integrates with BuildKit, it is assumed to be compatible with the [current BuildKit supported versions](https://github.com/moby/buildkit/releases) per BuildKit's compatibility guidelines.

If you choose to use Copacetic with a version of a dependency or platform that it does not explicitly support, you do so at your own risk.

## Acknowledgement

This document builds upon the release processes and practices of open-source projects such as Kubernetes, Helm, and Gatekeeper.

---

For full release details and the latest updates, visit the [Copacetic Releases page](https://github.com/project-copacetic/copacetic/releases).
