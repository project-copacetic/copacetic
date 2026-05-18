# AGENTS.md

## Scope
These instructions apply to the entire repository. If a nested `AGENTS.md` is added later, the nearest file to the changed code takes precedence. Direct user or maintainer instructions take precedence over this file.

Keep this guidance practical: prefer the smallest focused change that satisfies the task, and avoid repo-wide rewrites unless explicitly requested.

## Project overview
Copacetic (`copa`) is a Go CLI for patching vulnerabilities in existing container images with BuildKit. It updates packages in images without requiring a full source rebuild, usually from a scanner report such as Trivy.

- Module: `github.com/project-copacetic/copacetic`
- Main CLI entrypoint: `main.go`
- Primary command: `copa patch -i IMAGE [-r REPORT] -t TAG`
- BuildKit frontend entrypoint: `cmd/frontend/main.go`

## Design and safety guidelines
- Preserve Copa's design tenets: patch existing images, work with the current container/scanner/package-manager ecosystem, enable remediation by non-image-authors, and keep features composable and narrowly scoped.
- Treat image patching as security-sensitive. Do not weaken validation, package selection, provenance, VEX generation, image reference handling, platform handling, or scanner-report parsing.
- Prefer integrating with existing scanners, OS package managers, language package managers, BuildKit, Docker, and Podman instead of adding unrelated build/scanning systems.
- Discuss or confirm large architectural changes, new major features, or broad behavior changes before implementing them.
- Never commit secrets or credentials. Do not disclose suspected vulnerabilities publicly; follow `SECURITY.md`.

## Repository map
- `pkg/cmd/`: Cobra command wiring and patch command flags/validation.
- `pkg/patch/`: core single-arch and multi-platform patch orchestration.
- `pkg/buildkit/`: BuildKit client setup, drivers, and platform discovery helpers.
- `pkg/pkgmgr/`: OS package manager adapters (`apk`, `dpkg`, `rpm`, `pacman`) and scripts/testdata.
- `pkg/langmgr/`: language/library package patching managers.
- `pkg/report/`: vulnerability report parsing and scanner plugin interface; Trivy support lives here.
- `pkg/imageloader/`: Docker/Podman image loading integration.
- `pkg/frontend/`, `cmd/frontend/`: BuildKit frontend support.
- `pkg/bulk/`: bulk patch configuration, discovery, and execution.
- `pkg/generate/`: generation command and related logic.
- `pkg/provenance/`: provenance detection/rebuild helpers.
- `pkg/vex/`: VEX/OpenVEX output.
- `pkg/types/`: shared options, errors, and versioned API types.
- `pkg/common/`, `pkg/utils/`, `pkg/tui/`: shared helpers, logging/display utilities, and terminal output.
- `integration/` and `test/e2e/`: Docker/BuildKit-heavy integration and end-to-end tests.
- `website/docs/`: user documentation; `website/versioned_docs/` contains generated historical docs.

## Build, test, lint, and format
Use the existing Makefile targets when possible:

- Install local tooling: `make setup` (installs pinned `golangci-lint` and `gofumpt`).
- Build CLI: `make build`.
- Run unit tests: `make test` (`go test ./pkg/... $(CODECOV_OPTS)`).
- Run targeted unit tests while iterating: `go test ./pkg/<package>` or `go test ./pkg/<package> -run <TestName>`.
- Lint: `make lint`.
- Format Go code: `make format`.

Integration and e2e tests (`go test ./integration/...`, `go test ./test/e2e/...`) require Docker/BuildKit/container registry behavior and can be slow or environment-sensitive. Run targeted integration/e2e tests when touching those paths, or explain why they were not run.

For docs site changes under `website/`, use Yarn from that directory when verification is needed, for example `cd website && yarn install --frozen-lockfile && yarn build`.

## Go coding conventions
- Follow the Go version in `go.mod`.
- Use `gofumpt` formatting and keep imports clean; linting also enforces `gofmt`, `goimports`, and repository-specific `golangci-lint` rules.
- Keep error messages actionable and wrap underlying errors with context (`fmt.Errorf("...: %w", err)`) unless the surrounding code uses a different established style.
- Use `logrus` for logging where existing code does; avoid ad-hoc `fmt.Println` in library paths.
- Prefer small, testable functions and table-driven tests consistent with nearby code.
- Add or update representative tests and `testdata` for package manager behavior, report parsing, version selection, platform handling, and edge cases.
- Do not edit generated, vendored, or versioned documentation files unless the task specifically requires it.

## Domain-specific notes
- OS package changes must preserve distro-specific semantics for package names, installed/fixed versions, architectures, and package manager commands.
- Scanner/report changes must preserve the scanner plugin interface and avoid assuming Trivy-only fields unless the code path is explicitly Trivy-specific.
- Multi-platform changes must preserve manifest-list behavior, target-platform selection, and platform preservation for unaffected images.
- BuildKit and image-loader changes should keep Docker, Podman, remote BuildKit, and cancellation/timeout behavior in mind.
- Language/library patching is experimental. Respect `COPA_EXPERIMENTAL=1`, `--pkg-types`, `--library-patch-level`, and `--toolchain-patch-level`; update relevant language manager tests when changing this area.
- VEX/provenance changes should not overstate remediation status; only report what the patching flow has actually validated.

## Documentation and PR expectations
- Update `README.md` and/or `website/docs/` when changing user-visible CLI behavior, flags, outputs, configuration, supported platforms, or workflows.
- Keep examples aligned with current command names and flags.
- Contributions are expected to pass `make test`, `make lint`, and `gofumpt` formatting.
- The project uses Angular-style commit messages for changelog automation and requires DCO signoff (`Signed-off-by`) on real commits.
