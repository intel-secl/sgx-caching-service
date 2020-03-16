/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import "crypto"

const (
	SCSUserName                    = "scs"
	HomeDir                       = "/opt/scs/"
	ConfigDir                     = "/etc/scs/"
	ExecutableDir                 = "/opt/scs/bin/"
	ExecLinkPath                  = "/usr/bin/scs"
	RunDirPath                    = "/run/scs"
	LogDir                        = "/var/log/scs/"
	LogFile                       = LogDir + "scs.log"
	SecLogFile		      = LogDir + "scs-security.log"
	HTTPLogFile                   = LogDir + "http.log"
	ConfigFile                    = "config.yml"
	TLSCertFile                   = "cert.pem"
	TLSKeyFile                    = "key.pem"
	JWTCertsCacheTime              = "1m"
	TrustedJWTSigningCertsDir     = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir            = ConfigDir + "certs/trustedca/"
	RootCADirPath                 = ConfigDir + "certs/cms-root-ca/"
	PIDFile                       = "scs.pid"
	ServiceRemoveCmd              = "systemctl disable scs"
	HashingAlgorithm              = crypto.SHA384
	PasswordRandomLength          = 20
	DefaultAuthDefendMaxAttempts  = 5
	DefaultAuthDefendIntervalMins = 5
	DefaultAuthDefendLockoutMins  = 15
	DefaultSSLCertFilePath        = ConfigDir + "scsdbcert.pem"
	ServiceName                   = "SCS"
	DefaultHttpPort               = 9443
	DefaultKeyAlgorithm           = "rsa"
	DefaultKeyAlgorithmLength     = 3072
	DefaultIntelProvServerURL     = "https://api.trustedservices.intel.com/sgx/certification/v2/"
	EncPPID_Key		      = "encrypted_ppid"
	CpuSvn_Key		      = "cpu_svn"
	PceSvn_Key		      = "pce_svn"
	PceId_Key		      = "pce_id"
	QeId_Key		      = "qe_id"
	Ca_Key			      = "ca"
	Type_Key		      = "type"
	Ca_Processor		      = "processor"
	Fmspc_Key		      = "fmspc"
	DefaultScsTlsSan              = "127.0.0.1,localhost"
        DefaultScsTlsCn               = "SCS TLS Certificate"
        DefaultScsCertOrganization    = "INTEL"
        DefaultScsCertCountry         = "US"
        DefaultScsCertProvince        = "SF"
        DefaultScsCertLocality        = "SC"
	DefaultScsRefreshHours	      = 24
	DefaultJwtValidateCacheKeyMins = 60
	Type_Refresh_Cert		= "certs"
	Type_Refresh_Tcb	      = "tcbs"
	LogEntryMaxlengthEnv          = "LOG_ENTRY_MAXLENGTH"
	DefaultLogEntryMaxlength      = 300
	MaxTcbLevels		      = 16
)

// State represents whether or not a daemon is running or not
type State bool
type CacheType int

const (
	CacheInsert = iota + 1
	CacheRefresh
)

const (
	// Stopped is the default nil value, indicating not running
	Stopped State = false
	// Running means the daemon is active
	Running State = true
)
