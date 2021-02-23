/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"errors"
	errorLog "github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	commLog "intel/isecl/lib/common/v3/log"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/scs/v3/constants"
	"os"
	"path"
	"time"
)

var slog = commLog.GetSecurityLogger()

// Configuration is the global configuration struct that is marshalled/unmarshaled to a persisted yaml file
// Probably should embed a config generic struct
type Configuration struct {
	configFile       string
	Port             int
	CmsTLSCertDigest string
	Postgres         struct {
		DBName   string
		Username string
		Password string
		Hostname string
		Port     int
		SSLMode  string
		SSLCert  string
	}
	LogMaxLength    int
	LogEnableStdout bool
	LogLevel        log.Level

	Token struct {
		IncludeKid        bool
		TokenDurationMins int
	}
	CMSBaseURL     string
	AuthServiceURL string
	RefreshHours   int

	ProvServerInfo struct {
		ProvServerURL      string
		APISubscriptionkey string
	}
	Subject struct {
		TLSCertCommonName string
		JWTCertCommonName string
	}
	TLSKeyFile        string
	TLSCertFile       string
	CertSANList       string
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int

	CachingModel int

	WaitTime   int
	RetryCount int
}

var global *Configuration

func Global() *Configuration {
	if global == nil {
		global = Load(path.Join(constants.ConfigDir, constants.ConfigFile))
	}
	return global
}

var ErrNoConfigFile = errors.New("no config file")

func (conf *Configuration) Save() error {
	if conf.configFile == "" {
		return ErrNoConfigFile
	}
	file, err := os.OpenFile(conf.configFile, os.O_RDWR, 0)
	if err != nil {
		// we have an error
		if os.IsNotExist(err) {
			// error is that the config doesnt yet exist, create it
			file, err = os.OpenFile(conf.configFile, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
		} else {
			// someother I/O related error
			return err
		}
	}
	defer func() {
		derr := file.Close()
		if derr != nil {
			log.WithError(derr).Error("Failed to flush config.yml")
		}
	}()

	return yaml.NewEncoder(file).Encode(conf)
}

func (conf *Configuration) SaveConfiguration(c setup.Context) error {
	var err error

	tlsCertDigest, err := c.GetenvString("CMS_TLS_CERT_SHA384", "TLS certificate digest")
	if err == nil && tlsCertDigest != "" {
		conf.CmsTLSCertDigest = tlsCertDigest
	} else if conf.CmsTLSCertDigest == "" {
		commLog.GetDefaultLogger().Error("CMS_TLS_CERT_SHA384 is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_TLS_CERT_SHA384 is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	cmsBaseURL, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
	if err == nil && cmsBaseURL != "" {
		conf.CMSBaseURL = cmsBaseURL
	} else if conf.CMSBaseURL == "" {
		commLog.GetDefaultLogger().Error("CMS_BASE_URL is not defined in environment")
		return errorLog.Wrap(errors.New("CMS_BASE_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	tlsCertCN, err := c.GetenvString("SCS_TLS_CERT_CN", "SCS TLS Certificate Common Name")
	if err == nil && tlsCertCN != "" {
		conf.Subject.TLSCertCommonName = tlsCertCN
	} else if conf.Subject.TLSCertCommonName == "" {
		conf.Subject.TLSCertCommonName = constants.DefaultScsTLSCn
	}

	tlsKeyPath, err := c.GetenvString("KEY_PATH", "Path of file where TLS key needs to be stored")
	if err == nil && tlsKeyPath != "" {
		conf.TLSKeyFile = tlsKeyPath
	} else if conf.TLSKeyFile == "" {
		conf.TLSKeyFile = constants.DefaultTLSKeyFile
	}

	tlsCertPath, err := c.GetenvString("CERT_PATH", "Path of file/directory where TLS certificate needs to be stored")
	if err == nil && tlsCertPath != "" {
		conf.TLSCertFile = tlsCertPath
	} else if conf.TLSCertFile == "" {
		conf.TLSCertFile = constants.DefaultTLSCertFile
	}

	logLevel, err := c.GetenvString("SCS_LOGLEVEL", "SCS Log Level")
	if err != nil {
		slog.Infof("config/config:SaveConfiguration() %s not defined, using default log level: Info", constants.SCSLogLevel)
		conf.LogLevel = log.InfoLevel
	} else {
		llp, err := log.ParseLevel(logLevel)
		if err != nil {
			slog.Info("config/config:SaveConfiguration() Invalid log level specified in env, using default log level: Info")
			conf.LogLevel = log.InfoLevel
		} else {
			conf.LogLevel = llp
			slog.Infof("config/config:SaveConfiguration() Log level set %s\n", logLevel)
		}
	}

	sanList, err := c.GetenvString("SAN_LIST", "SAN list for TLS")
	if err == nil && sanList != "" {
		conf.CertSANList = sanList
	} else if conf.CertSANList == "" {
		conf.CertSANList = constants.DefaultScsTLSSan
	}

	return conf.Save()
}

func Load(filePath string) *Configuration {
	var c Configuration
	file, _ := os.Open(filePath)
	if file != nil {
		defer func() {
			derr := file.Close()
			if derr != nil {
				log.WithError(derr).Error("Failed to close config.yml")
			}
		}()
		err := yaml.NewDecoder(file).Decode(&c)
		if err != nil {
			log.WithError(err).Error("Failed to decode config.yml contents")
		}
	} else {
		c.LogLevel = log.InfoLevel
	}

	c.configFile = filePath
	return &c
}
