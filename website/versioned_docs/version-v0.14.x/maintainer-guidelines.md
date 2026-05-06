# Maintainer Guidelines

## Semantic Release Management

This project uses [go-semantic-release](https://github.com/go-semantic-release/semantic-release) to automatically generate the appropriate [semantic version](https://semver.org/) and changelog for a release based on [Angular commit message format](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#-commit-message-format). Of note to maintainers is the need to enforce an empty line-separate format:

```xml
<HEADER>
<-- blank line -->
<BODY>
<-- blank line -->
<FOOTER>
```

For contributor PRs, instead of trying to ensure adherence in every commit message, it's easiest to adopt a [squash and merge](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/configuring-commit-squashing-for-pull-requests) strategy so that the PR description is used as the final commit description with the appropriate semantic release format.

In addition to the semantic release types called out in the [contributor pull request guidelines](./contributing.md#pull-requests), there are several other categories supported by the [default changelog generator](https://github.com/go-semantic-release/changelog-generator-default) that maintainers should be aware of:

- **chore:** Reserved for automated maintenance changes, such as minor version go dependency updates initiated by Dependabot.
- **revert:** Maintainers should use this to mark commits that revert a previous commit, followed by the header of the reverted commit. The message body should include the SHA of the reverted commit, as well as a clear description of the reason for the revert.
- **style:** This is unused for this project.

There are also two special categories to be added to the [message footer](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#commit-message-footer) that maintainers need to pay special attention to when merging changes:

### Breaking change

Breaking changes should be described in the footer as follows:

```text
BREAKING CHANGE: <breaking change summary>
<-- blank line -->
<breaking change description & migration instructions>
<-- blank line -->
<-- blank line -->
Closes #<issue number>
```

> Note that this project currently uses the `allow-initial-development-versions` flag for go-semantic-release, so **breaking changes will still be handled as minor releases** until the workflow is updated for the v1.0.0 release.

### Deprecation

```text
DEPRECATED: <summary of deprecated feature>
<-- blank line -->
<deprecated feature description & migration/workaround instructions>
<-- blank line -->
<-- blank line -->
Closes #<issue number>
```

## Publishing a Release

To avoid inconsistencies in tagging and release branching, this project uses the [Publish release](https://github.com/project-copacetic/copacetic/actions/workflows/release.yml) GitHub Actions workflow to automate the creation of releases.

### Publish a new major/minor version release

1. Review the `main` branch to ensure that it has all the desired changes for the new release branch and that there are no PR merge workflows in flight.
2. Click _Run workflow_ on the [Publish release](https://github.com/project-copacetic/copacetic/actions/workflows/release.yml) against the `main` branch. This will:
   1. Create a new tag with the incremented semantic version (e.g. `v0.9.0`) against the latest commit in `main`.
   2. Create a new GitHub release against that tag with an automatically generated changelog.
   3. Build and upload the new release version of Copa to the GitHub release.
   4. Create a new release branch if it does not already exist (e.g. `release-0.9`)
3. Verify that the workflow ran successfully and review the expected outputs listed above.

### Publish a patch revision release

1. Review the appropriate release branch that the revision patches (e.g. `release-0.9` for an anticipated new `v0.9.x` tag) to ensure that it has all the desired changes for the release and that there are no PR merge workflows in flight.
   1. If there are fixes in `main` intended for the patch release in the latest release branch, they need to be manually ported to the release branch first and the revision released from there.
2. Click _Run workflow_ on the [Publish release](https://github.com/project-copacetic/copacetic/actions/workflows/release.yml) against the target `release-x.y` branch. This will:
   1. Create a new tag with the incremented semantic version (e.g. `v0.9.4`) against the latest commit in the release branch.
   2. Create a new GitHub release against that tag with an automatically generated changelog.
   3. Build and upload the new release version of Copa to the GitHub release.
3. Verify that the workflow ran successfully and review the expected outputs listed above.
