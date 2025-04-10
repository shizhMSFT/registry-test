MODULE         = github.com/shizhMSFT/registry-test
GIT_TAG        = $(shell git describe --tags --abbrev=0 --exact-match 2>/dev/null)
BUILD_METADATA =
ifeq ($(GIT_TAG),) # unreleased build
    GIT_COMMIT     = $(shell git rev-parse HEAD)
    GIT_STATUS     = $(shell test -n "`git status --porcelain`" && echo "dirty" || echo "unreleased")
	BUILD_METADATA = $(GIT_COMMIT).$(GIT_STATUS)
endif
LDFLAGS        = -X $(MODULE)/internal/version.BuildMetadata=$(BUILD_METADATA)
GO_BUILD_FLAGS = --ldflags="$(LDFLAGS)"

.PHONY: all
all: build

.PHONY: build
build:
	go build $(GO_BUILD_FLAGS) -o bin/cryptotest ./cmd/cryptotest

.PHONY: install
install: build
	cp bin/cryptotest ~/bin

.PHONY: clean
clean:
	git status --ignored --short | grep '^!! ' | sed 's/!! //' | xargs rm -rf