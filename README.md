# SGX Caching Service

`SGX Caching Service` is a web service whose purpose is to fetch and cache all the SGX Platform collaterals from Intel PCS Server.

## Key features
- Connect to intel PCS server on need basis
- Cache SGX Platform values 
- Fetch and cache PCK Certificates for a platform
- Select Best Suited PCK Cert for Current Raw TCB Level
- Fetch and cache TCBInfo for a platform
- Fetch and cache PCK Certificate Revocation List
- Fetch and cache Quoting Enclave Identity information
- Periodically (configurable) refreshes above data
- Provide TCB UpToDate Status for current Raw TCB Level
- Supports Intel PCS Server V3 APIs for multipackage systems
- RESTful APIs for easy and versatile access to above features

## System Requirements
- RHEL 8.4 or ubuntu 20.04
- Epel 8 Repo
- pgdg 42 Repo
- Proxy settings if applicable

## Software requirements
- git
- makeself
- docker
- Go 1.18.8

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `dnf`
```shell
sudo dnf install -y git wget makeself docker
```

### Install `go 1.18.8`
The `SGX Caching Service` requires Go version 1.18.8 that has support for `go modules`. The build was validated with the version 1.18.8 of `go`. It is recommended that you use 1.18.8 version of `go`. More recent versions may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.18.8.linux-amd64.tar.gz
tar -xzf go1.18.8.linux-amd64.tar.gz
sudo mv go /usr/local
export GOROOT=/usr/local/go
export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
```

## Build SGX Caching service

- Git clone the SGX Caching service
- Run scripts to build the SGX Caching service

```shell
git clone https://github.com/intel-secl/sgx-caching-service.git
cd sgx-caching-service
git checkout v5.1.0
make installer
```

### Deploy
```console
> ./out/scs-*.bin
```

### Manage service
* Start service
    * scs start
* Stop service
    * scs stop
* Status of service
    * scs status

# Third Party Dependencies

## Sgx Caching Service

### Direct dependencies

| Name        | Repo URL                    | Minimum Version Required           |
| ----------- | --------------------------- | :--------------------------------: |
| uuid        | github.com/google/uuid      | v1.2.0                            |
| handlers    | github.com/gorilla/handlers | v1.4.2                             |
| mux         | github.com/gorilla/mux      | v1.7.4                             |
| gorm        | github.com/jinzhu/gorm      | v1.9.16                            |
| testify     | github.com/stretchr/testify | v1.6.1                             |
| logrus      | github.com/sirupsen/logrus  | v1.7.0                             |
| pq          | github.com/lib/pq           | v1.3.0                             |
| errors      | github.com/pkg/errors       | v0.9.1                             |
| yaml.v3     | gopkg.in/yaml.v3            | v3.0.1                             |
| common      | github.com/intel-secl/common| v5.1.0                             |

*Note: All dependencies are listed in go.mod*
