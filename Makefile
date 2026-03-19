################################################################################
# Global: Variables                                                            #
################################################################################

# Formatted symbol markers (=>, [needs root]) for info output
INFOMARK = $(shell printf "\033[34;1m=>\033[0m")
ROOTMARK = $(shell printf "\033[31;1m[needs root]\033[0m")

# Optional Make arguments
CGO_ENABLED  ?= 0
CLI_VERSION  ?= edge
DEBUG        ?= 0
NODE_VERSION ?= 20-bookworm-slim

# Go build metadata variables
BASE_PACKAGE_NAME := github.com/project-copacetic/copacetic
GIT_COMMIT        := $(shell git rev-list -1 HEAD)
GIT_VERSION       := $(shell git describe --always --tags --dirty)
BUILD_DATE        := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
DEFAULT_LDFLAGS   := -X $(BASE_PACKAGE_NAME)/pkg/version.GitCommit=$(GIT_COMMIT) \
  -X $(BASE_PACKAGE_NAME)/pkg/version.GitVersion=$(GIT_VERSION) \
  -X $(BASE_PACKAGE_NAME)/pkg/version.BuildDate=$(BUILD_DATE) \
  -X main.version=$(CLI_VERSION)
GOARCH            := $(shell go env GOARCH)
GOOS              := $(shell go env GOOS)

# Frontend build variables
FRONTEND_IMAGE_NAME ?= ghcr.io/project-copacetic/copacetic-frontend
FRONTEND_PLATFORMS  ?= linux/amd64,linux/arm64
FRONTEND_VER        ?= $(CLI_VERSION)


# Message lack of native build support in Windows
ifeq ($(GOOS),windows)
  $(error Windows native build is unsupported, use WSL instead)
endif

# Build configuration variables
ifeq ($(DEBUG),0)
  BUILDTYPE_DIR:=release
  LDFLAGS:="$(DEFAULT_LDFLAGS) -s -w -extldflags -static"
else
  BUILDTYPE_DIR:=debug
  LDFLAGS:="$(DEFAULT_LDFLAGS)"
  GCFLAGS:=-gcflags="all=-N -l"
  $(info $(INFOMARK) Build with debug information)
endif

# Build output variables
CLI_BINARY        := copa
OUT_DIR           := ./dist
BINS_OUT_DIR      ?= $(OUT_DIR)/$(GOOS)_$(GOARCH)/$(BUILDTYPE_DIR)

################################################################################
# Target: build (default action)                                               #
################################################################################
.PHONY: build
build: $(CLI_BINARY)

$(CLI_BINARY):
	$(info $(INFOMARK) Building $(CLI_BINARY) ...)
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
	go build $(GCFLAGS) -ldflags $(LDFLAGS) -o $(BINS_OUT_DIR)/$(CLI_BINARY);

################################################################################
# Target: frontend (frontend image)                                            #
################################################################################
.PHONY: frontend
frontend: $(CLI_BINARY)
	$(info $(INFOMARK) Creating multiplatform frontend image ...)
	docker buildx build \
		-f frontend.Dockerfile \
		-t $(FRONTEND_IMAGE_NAME):$(FRONTEND_VER) \
		--platform $(FRONTEND_PLATFORMS) .

################################################################################
# Target: install                                                              #
################################################################################
.PHONY: install
install: $(CLI_BINARY)
	$(info $(INFOMARK) Installing $(CLI_BINARY) ...)
	sudo cp $(BINS_OUT_DIR)/$(CLI_BINARY) /usr/local/bin/$(CLI_BINARY)
	sudo chmod +x /usr/local/bin/$(CLI_BINARY)

################################################################################
# Target: lint                                                                 #
################################################################################
.PHONY: lint
lint:
	$(info $(INFOMARK) Linting go code ...)
	golangci-lint run -v ./...

################################################################################
# Target: format                                                               #
################################################################################
.PHONY: format
format:
	$(info $(INFOMARK) Formatting all go files with gofumpt ...)
	gofumpt -l -w .

################################################################################
# Target: archive                                                              #
################################################################################
ARCHIVE_OUT_DIR ?= $(BINS_OUT_DIR)
ARCHIVE_NAME = $(CLI_BINARY)_$(CLI_VERSION)_$(GOOS)_$(GOARCH).tar.gz
archive: $(ARCHIVE_NAME)
$(ARCHIVE_NAME):
	$(info $(INFOMARK) Building release package $(ARCHIVE_NAME) ...)
	chmod +x $(BINS_OUT_DIR)/$(CLI_BINARY)
	tar czf "$(ARCHIVE_OUT_DIR)/$(ARCHIVE_NAME)" -C "$(BINS_OUT_DIR)" "$(CLI_BINARY)"
	(cd $(ARCHIVE_OUT_DIR) && sha256sum -b "$(ARCHIVE_NAME)" > "$(ARCHIVE_NAME).sha256")

################################################################################
# Target: release                                                              #
################################################################################
.PHONY: release
release: build archive

################################################################################
# Target: release-manifest                                                     #
################################################################################
.PHONY: release-manifest
release-manifest:
	@sed -i -e 's/^CLI_VERSION := .*/CLI_VERSION := ${NEWVERSION}/' ./Makefile

################################################################################
# Target: test - unit testing                                                  #
################################################################################
.PHONY: test
test:
	$(info $(INFOMARK) Running unit tests on pkg libraries ...)
	go test ./pkg/... $(CODECOV_OPTS)

################################################################################
# Target: clean                                                                #
################################################################################
.PHONY: clean
clean:
	$(info $(INFOMARK) Cleaning $(OUT_DIR) folder ...)
	rm -r $(OUT_DIR)

################################################################################
# Target: setup                                                                #
################################################################################
.PHONY: setup
setup:
	$(info $(INFOMARK) Installing Makefile go binary dependencies $(ROOTMARK) ...)
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.10.1
	go install mvdan.cc/gofumpt@latest

################################################################################
# Target: version-docs                                                         #
################################################################################
.PHONY: version-docs
version-docs:
	$(info $(INFOMARK) Creating versioned docs ...)
	docker run --rm \
		-v $(shell pwd)/website:/website \
		-w /website \
		-u $(shell id -u):$(shell id -g) \
		node:${NODE_VERSION} \
		sh -c "yarn install --frozen lockfile && yarn run docusaurus docs:version ${NEWVERSION}"
