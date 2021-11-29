PKG_NAME ?= didcomm
WASM_TARGET ?= bundler
WASM_OPTS_PUBLISH ?=

ifndef PROJECT_DIR
PROJECT_DIR := $(shell git rev-parse --show-toplevel)
endif

WASM_DIR_NAME := wasm
WASM_DIR := $(PROJECT_DIR)/$(WASM_DIR_NAME)

WASM_PKG_DIR_NAME := pkg
WASM_PKG_DIR := $(WASM_DIR)/$(WASM_PKG_DIR_NAME)

.PHONY: all \
		pkg_clean build install publish clean

all: build

pkg_clean:
	rm -rf $(WASM_PKG_DIR)

build: $(WASM_DIR) pkg_clean
	cd $<
	wasm-pack build --target $(WASM_TARGET) --out-name index
	sed -i -r "s~\"name\": \".+\"~\"name\": \"${PKG_NAME}\"~" $(WASM_PKG_DIR_NAME)/package.json

install: $(WASM_PKG_DIR)
	cd $< && npm install .

pack: $(WASM_PKG_DIR)
	cd $(WASM_DIR)
	wasm-pack pack 

publish: $(WASM_PKG_DIR) 
	cd $(WASM_DIR)
	echo '//registry.npmjs.org/:_authToken=${NPM_TOKEN}' > $</.npmrc
	wasm-pack publish $(WASM_OPTS_PUBLISH)

clean: $(WASM_DIR) pkg_clean
	cd $< && cargo clean
