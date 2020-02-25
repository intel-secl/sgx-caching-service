# SGX Caching Service

`SGX Caching Service` is a web service whose purpose is to fetch and cache all the SGX Platform collaterals from Intel PCS Server

## Key features
- Connect to intel PCS server on need basis
- Fetch and cache PCK Certificates for a platform
- Fetch and cache TCBInfo for a platform
- Fetch and cache PCK Certificate Revocation List
- Fetch and cache Quoting Enclave Identity information
- Periodically (configurable) refreshes above data
- RESTful APIs for easy and versatile access to above features

## System Requirements
- RHEL 8.1
- Epel 8 Repo
- pgdg 42 Repo
- Proxy settings if applicable

## Software requirements
- git
- makeself
- `go` version >= `go1.11.4` & <= `go1.12.12`

# Step By Step Build Instructions

## Install required shell commands

### Install tools from `yum`
```shell
sudo yum install -y git wget makeself
```

### Install `go` version >= `go1.11.4` & <= `go1.12.12`
The `SGX Caching Service` requires Go version 1.11.4 that has support for `go modules`. The build was validated with the latest version 1.12.12 of `go`. It is recommended that you use 1.12.12 version of `go`. More recent versions may introduce compatibility issues. You can use the following to install `go`.
```shell
wget https://dl.google.com/go/go1.12.12.linux-amd64.tar.gz
tar -xzf go1.12.12.linux-amd64.tar.gz
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
make all
```

### Deploy
```console
> ./scs-*.bin
```

### Manage service
* Start service
    * scs start
* Stop service
    * scs stop
* Restart service
    * scs restart
* Status of service
    * scs status

# Third Party Dependencies

## Sgx Caching Service

### Direct dependencies

| Name        | Repo URL                    | Minimum Version Required           |
| ----------- | --------------------------- | :--------------------------------: |
| uuid        | github.com/google/uuid      | v1.1.1                             |
| handlers    | github.com/gorilla/handlers | v1.4.0                             |
| mux         | github.com/gorilla/mux      | v1.7.0                             |
| gorm        | github.com/jinzhu/gorm      | v1.9.2                             |
| testify     | github.com/stretchr/testify | v1.3.0                             |
| crypto      | golang.org/x/crypto         | v0.0.0-20190219172222-a4c6cb3142f2 |
| yaml.v2     | gopkg.in/yaml.v2            | v2.2.2                             |
| time        | golang.org/x/time           | v0.0.0-20190308202827-9d24e82272b4 |
| authservice | intel/isecl/authservice     | v0.0.0	                         |
| common      | intel/isecl/lib/common      | v1.0.0-Beta                        |

*Note: All dependencies are listed in go.mod*
