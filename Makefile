GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
GITCOMMIT := $(shell git describe --always)
VERSION := $(or ${GITTAG}, v0.0.0)

.PHONY: sgx-caching-service installer all test clean

sgx-caching-service:
	env GOOS=linux go build -ldflags "-X intel/isecl/sgx-caching-service/version.Version=$(VERSION) -X intel/isecl/sgx-caching-service/version.GitHash=$(GITCOMMIT)" -o out/sgx-caching-service

test:
	go test ./... -coverprofile cover.out
	go tool cover -func cover.out
	go tool cover -html=cover.out -o cover.html

installer: sgx-caching-service
	mkdir -p out/installer
	cp dist/linux/sgx-caching-service.service out/installer/sgx-caching-service.service
	cp dist/linux/install.sh out/installer/install.sh && chmod +x out/installer/install.sh
	cp dist/linux/db_rotation.sql out/installer/db_rotation.sql
	cp out/sgx-caching-service out/installer/sgx-caching-service
	makeself out/installer out/sgx-caching-service-$(VERSION).bin "SGX Caching Service $(VERSION)" ./install.sh
	cp dist/linux/install_pgscsdb.sh out/install_pgscsdb.sh && chmod +x out/install_pgscsdb.sh

all: clean installer test

clean:
	rm -f cover.*
	rm -rf out/
