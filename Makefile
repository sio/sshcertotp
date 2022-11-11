GOOS_ALL=linux windows darwin
GOARCH_ALL=amd64 arm64
BUILD_DIR=build


GO?=go
GOOS?=linux
GOARCH?=amd64
export GOOS
export GOARCH


.PHONY: build
build:
	$(GO) build -o $(BUILD_DIR)/$(GOOS)-$(GOARCH)/ -trimpath


.PHONY: build-all
build-all:
	cd $(BUILD_DIR) && find -type f \
	| cut -c3- \
	| while read NAME; do mv "$$NAME" "$$(echo "$$NAME"|sed 's:/:-:g')"; done
	find $(BUILD_DIR) -type d -empty -print -delete
	cd $(BUILD_DIR) && find -type f ! -name SHA256SUMS \
	| cut -c3- \
	| sort \
	| xargs sha256sum \
	| tee SHA256SUMS


.PHONY: test
test:
	$(GO) test -v .


.PHONY: clean
clean:
	$(RM) -vr $(BUILD_DIR)


define build-recipe
.PHONY: build-${1}-${2}
build-all: build-${1}-${2}
build-${1}-${2}:
	$(MAKE) build GOOS=${1} GOARCH=${2}
endef
$(foreach os,$(GOOS_ALL),\
	$(foreach arch,$(GOARCH_ALL),\
		$(eval $(call build-recipe,$(os),$(arch)))\
	)\
)
