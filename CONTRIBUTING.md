# Contributing to the Project

Welcome! We are very happy to accept community contributions to the project, whether through [filing issues](#contributing-issues) or [code](#contributing-code) in the form of [Pull Requests](#pull-requests). Please note that by participating in this project, you agree to abide by the [Code of Conduct](./CODE_OF_CONDUCT.md), as well as the terms of the [Developer Certificate of Origin](#developer-certificate-of-origin-dco).

## Contributing Issues

Before opening any new issues, please search our [existing GitHub issues](https://github.com/project-copacetic/copacetic/issues) to check if your bug or suggestion has already been filed. If such an issue already exists, we recommend adding your comments and perspective to that existing issue instead.

When opening an issue, please select the most appropriate template for what you're contributing:

* **Bug Report:** If you would like to report the project or tool behaving in unexpected ways.
* **Documentation Improvement:** If you have corrections or improvements to the project's documents, be they typos, factual errors, or missing content.
* **Request:** If you have a feature request, suggestion, or a even a design proposal to review.
* **Question:** If you would like to ask the maintainers a question about the project.

> If you would like to report a security vulnerability, please follow the instructions for [reporting security issues](./SECURITY.md#reporting-security-issues) instead.

## Contributing Code

### Getting Started

Follow the instructions to [setup your dev environment to build copa](./docs/tutorials/dev-setup.md).

For an overview of the project components, refer to the [copa design](./docs/vulnerability-driven-patching.md) document.

### Tests

Once you can successfully `make` the project, any code contributions should also successfully:

* Pass unit tests via `make test`.
* Lint cleanly via `make lint`.

Pull requests will also be expected to pass the PR functional tests specified by `.github/workflows/build.yml`.

### Pull Requests

If you'd like to start contributing code to the project, you can search for [issues with the `good first issue` label](https://github.com/project-copacetic/copacetic/labels/good%20first%20issue). Other kinds of PR contributions we would look for include:

* Fixes for bugs and other correctness issues.
* Docs and other content improvements (e.g. samples).
* Extensions to support parsing new scanning report formats.
* Extensions to support patching images based on new distros or using new package managers.

For any changes that may involve significant refactoring or development effort, we suggest that you file an issue to discuss the proposal with the maintainers first as it is unlikely that we will accept large PRs without prior discussion that have:

* Architectural changes (e.g. breaking interfaces or violations of [this project's design tenets](./docs/vulnerability-driven-patching.md#design-tenets)).
* Unsolicited features that significantly expand the functional scope of the tool.

Pull requests should be submitted from your fork of the project with the PR template filled out. This project uses the [Angular commit message format](https://github.com/angular/angular/blob/main/CONTRIBUTING.md#-commit-message-format) for automated changelog generation, so it's helpful to be familiar with it as the maintainers will need to ensure adherence to it on accepting PRs.

We suggest:

* Use the standard header format of `"<type>: <short summary>"` where the `<type>` is one of the following:
  * **build:** Changes that affect the build system or external dependencies
  * **ci:** Changes to the GitHub workflows and configurations
  * **docs:** Documentation only changes
  * **feat:** A new feature
  * **fix:** A bug fix
  * **perf:** A code change that improves performance
  * **refactor:** A code change that neither fixes a bug nor adds a feature
  * **test:** Adding missing tests or correcting existing tests
* Use a [concise, imperative description](https://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html) of the changes included in the `<short summary>` of the header, the body of the PR, and generally in your commit messages.
* Use [GitHub keywords](https://docs.github.com/en/get-started/writing-on-github/working-with-advanced-formatting/using-keywords-in-issues-and-pull-requests) in the footer of your PR description, such as `closes` to automatically close issues the PR intends to address.

## Developer Certificate of Origin (DCO)

The [Developer Certificate of Origin](https://wiki.linuxfoundation.org/dco) (DCO) is a lightweight way for contributors to certify that they wrote or otherwise have the right to submit the code they are contributing to the project. Here is the [full text of the DCO](https://developercertificate.org/), reformatted for readability:

> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I
> have the right to submit it under the open source license
> indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
> of my knowledge, is covered under an appropriate open source
> license and I have the right under that license to submit that
> work with modifications, whether created in whole or in part
> by me, under the same open source license (unless I am
> permitted to submit under a different license), as indicated
> in the file; or
>
> (c) The contribution was provided directly to me by some other
> person who certified (a), (b) or (c) and I have not modified
> it.
>
> (d) I understand and agree that this project and the contribution
> are public and that a record of the contribution (including all
> personal information I submit with it, including my sign-off) is
> maintained indefinitely and may be redistributed consistent with
> this project or the open source license(s) involved.

Contributors _sign-off_ that they adhere to these requirements by adding a `Signed-off-by` line to commit messages.

```text
This is my commit message

Signed-off-by: Random J Developer <random@developer.example.org>
```

Git even has a `-s` command line option to append this automatically to your commit message:

```bash
git commit -s -m 'This is my commit message'
```

Pull requests that do not contain a valid `Signed-off-by` line cannot be merged.

### I didn't sign my commit, now what?

No worries - You can easily amend your commit with a sign-off and force push the change to your submitting branch:

```bash
git switch <branch-name>
git commit --amend --no-edit --signoff
git push --force-with-lease <remote-name> <branch-name>
```

## Code of Conduct

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
