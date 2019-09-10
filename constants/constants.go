/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "crypto"

const (
	HomeDir                       = "/opt/sgx-caching-service/"
	ConfigDir                     = "/etc/sgx-caching-service/"
	ExecutableDir                 = "/opt/sgx-caching-service/bin/"
	ExecLinkPath                  = "/usr/bin/sgx-caching-service"
	RunDirPath                    = "/run/sgx-caching-service"
	LogDir                        = "/var/log/sgx-caching-service/"
	LogFile                       = "sgx-caching-service.log"
	HTTPLogFile                   = "http.log"
	ConfigFile                    = "config.yml"
	TLSCertFile                   = "cert.pem"
	TLSKeyFile                    = "key.pem"
	TrustedJWTSigningCertsDir     = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir            = ConfigDir + "certs/trustedca/"
	RootCADirPath                 = ConfigDir + "certs/cms-root-ca/"
	//RootCACertPath                = RootCADirPath + "root-ca-cert.pem"
	PIDFile                       = "sgx-caching-service.pid"
	ServiceRemoveCmd              = "systemctl disable sgx-caching-service"
	HashingAlgorithm              = crypto.SHA384
	PasswordRandomLength          = 20
	DefaultAuthDefendMaxAttempts  = 5
	DefaultAuthDefendIntervalMins = 5
	DefaultAuthDefendLockoutMins  = 15
	DefaultDBRotationMaxRowCnt    = 100000
	DefaultDBRotationMaxTableCnt  = 10
	DefaultSSLCertFilePath        = ConfigDir + "svsdbcert.pem"
	ServiceName                   = "SVS"
	DefaultHttpPort               = 9443
	DefaultKeyAlgorithm           = "rsa"
	DefaultKeyAlgorithmLength     = 3072
	DefaultIntelProvServerURL     = "https://sbx.api.trustedservices.intel.com/sgx/certification/v1/"
	EncPPID_Key		      = "encrypted_ppid"
	CpuSvn_Key		      = "cpu_svn"
	PceSvn_Key		      = "pce_svn"
	PceId_Key		      = "pce_id"
	QeId_Key		      = "qe_id"
	Ca_Key		      	      = "ca"
	Type_Key		      = "type"
	Ca_Processor		      = "processor"
	Ca_Platform		      = "platform"
	Fmspc_Key		      = "fmspc"
	DefaultScsTlsSan              = "127.0.0.1,localhost"
        DefaultScsTlsCn               = "SCS TLS Certificate"
        DefaultScsCertOrganization    = "INTEL"
        DefaultScsCertCountry         = "US"
        DefaultScsCertProvince        = "SF"
        DefaultScsCertLocality        = "SC"


)

// State represents whether or not a daemon is running or not
type State bool

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)

