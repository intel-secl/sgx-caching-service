GITTAG := $(shell git describe --tags --abbrev=0 2> /dev/null)
#GITCOMMIT := $(shell git describe --always)
GITCOMMIT := e991de2 
GITCOMMITDATE := $(shell git log -1 --date=short --pretty=format:%cd)
VERSION := $(or ${GITTAG}, v0.0.0)

.PHONY: sgx-caching-service installer docker all test clean

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

docker: installer
	cp dist/docker/entrypoint.sh out/entrypoint.sh && chmod +x out/entrypoint.sh
	docker build -t isecl/sgx-caching-service:latest -f ./dist/docker/Dockerfile ./out
	docker save isecl/sgx-caching-service:latest > ./out/docker-sgx-caching-service-$(VERSION)-$(GITCOMMIT).tar

docker-zip: installer
	mkdir -p out/docker-sgx-caching-service
	cp dist/docker/docker-compose.yml out/docker-sgx-caching-service/docker-compose
	cp dist/docker/entrypoint.sh out/docker-sgx-caching-service/entrypoint.sh && chmod +x out/docker-sgx-caching-service/entrypoint.sh
	cp dist/docker/README.md out/docker-sgx-caching-service/README.md
	cp out/sgx-caching-service-$(VERSION).bin out/docker-sgx-caching-service/sgx-caching-service-$(VERSION).bin
	cp dist/docker/Dockerfile out/docker-sgx-caching-service/Dockerfile
	zip -r out/docker-sgx-caching-service.zip out/docker-sgx-caching-service	

all: test docker

clean:
	rm -f cover.*
	rm -f sgx-caching-service
	rm -rf out/
