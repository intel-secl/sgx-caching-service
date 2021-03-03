/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package constants

import (
	"time"
)

const (
	HomeDir                        = "/opt/scs/"
	ConfigDir                      = "/etc/scs/"
	ExecLinkPath                   = "/usr/bin/scs"
	RunDirPath                     = "/run/scs"
	LogDir                         = "/var/log/scs/"
	LogFile                        = LogDir + "scs.log"
	SecLogFile                     = LogDir + "scs-security.log"
	HTTPLogFile                    = LogDir + "http.log"
	ConfigFile                     = "config.yml"
	DefaultTLSCertFile             = ConfigDir + "tls-cert.pem"
	DefaultTLSKeyFile              = ConfigDir + "tls.key"
	TrustedJWTSigningCertsDir      = ConfigDir + "certs/trustedjwt/"
	TrustedCAsStoreDir             = ConfigDir + "certs/trustedca/"
	ServiceRemoveCmd               = "systemctl disable scs"
	DefaultSSLCertFilePath         = ConfigDir + "scsdbcert.pem"
	ServiceName                    = "SCS"
	ExplicitServiceName            = "SGX Caching Service"
	HostDataUpdaterGroupName       = "HostDataUpdater"
	HostDataReaderGroupName        = "HostDataReader"
	CacheManagerGroupName          = "CacheManager"
	SCSUserName                    = "scs"
	DefaultHTTPSPort               = 9000
	DefaultKeyAlgorithm            = "rsa"
	DefaultKeyAlgorithmLength      = 3072
	DefaultScsTLSSan               = "127.0.0.1,localhost"
	DefaultScsTLSCn                = "SCS TLS Certificate"
	DefaultIntelProvServerURL      = "https://sbx.api.trustedservices.intel.com/sgx/certification/v3/"
	EncPPIDKey                     = "encrypted_ppid"
	CPUSvnKey                      = "cpu_svn"
	PceSvnKey                      = "pce_svn"
	PceIDKey                       = "pce_id"
	QeIDKey                        = "qe_id"
	CaKey                          = "ca"
	EncodingValue                  = "der"
	FmspcKey                       = "fmspc"
	HwUUIDKey                      = "hardware_uuid"
	DefaultScsRefreshHours         = 24
	DefaultJwtValidateCacheKeyMins = 60
	SCSLogLevel                    = "SCS_LOGLEVEL"
	DefaultReadTimeout             = 30 * time.Second
	DefaultReadHeaderTimeout       = 10 * time.Second
	DefaultWriteTimeout            = 10 * time.Second
	DefaultIdleTimeout             = 1 * time.Second
	DefaultMaxHeaderBytes          = 1 << 20
	DefaultLogEntryMaxLength       = 300
	TypeRefreshCert                = "certs"
	TypeRefreshTcb                 = "tcbs"
	MaxTcbLevels                   = 16
	DefaultRetrycount              = 3
	DefaultWaitTime                = 1
)

type CacheType int

const (
	CacheInsert = iota + 1
	CacheRefresh
)