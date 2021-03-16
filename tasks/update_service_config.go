/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/scs/v3/config"
	"intel/isecl/scs/v3/constants"
	"io"
	"net/url"
	"time"
)

type Update_Service_Config struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (u Update_Service_Config) Run(c setup.Context) error {
	fmt.Fprintln(u.ConsoleWriter, "Running server setup...")
	defaultPort, err := c.GetenvInt("SCS_PORT", "SGX Caching Service http port")
	if err != nil {
		defaultPort = constants.DefaultHTTPSPort
	}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)

	fs.IntVar(&u.Config.Port, "port", defaultPort, "SGX Caching Service http port")
	err = fs.Parse(u.Flags)
	if err != nil {
		return errors.Wrap(err, "tasks/Update_Service_Config:Run() Could not parse input flags")
	}
	if u.Config.Port > 65535 || u.Config.Port <= 1024 {
		return errors.New("Invalid or reserved port")
	}
	fmt.Fprintf(u.ConsoleWriter, "Using HTTPS port: %d\n", u.Config.Port)

	readTimeout, err := c.GetenvString("SCS_SERVER_READ_TIMEOUT", "SGX Caching Service Read Timeout")
	if err != nil {
		u.Config.ReadTimeout = constants.DefaultReadTimeout
	} else {
		u.Config.ReadTimeout, err = time.ParseDuration(readTimeout)
		if err != nil {
			fmt.Fprintf(u.ConsoleWriter, "Invalid duration provided for SCS_SERVER_READ_TIMEOUT setting it to the default value\n")
			u.Config.ReadTimeout = constants.DefaultReadTimeout
		}
	}

	readHeaderTimeout, err := c.GetenvString("SCS_SERVER_READ_HEADER_TIMEOUT", "SGX Caching Service Read Header Timeout")
	if err != nil {
		u.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		u.Config.ReadHeaderTimeout, err = time.ParseDuration(readHeaderTimeout)
		if err != nil {
			fmt.Fprintf(u.ConsoleWriter, "Invalid duration provided for SCS_SERVER_READ_HEADER_TIMEOUT setting it to the default value\n")
			u.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
		}
	}

	writeTimeout, err := c.GetenvString("SCS_SERVER_WRITE_TIMEOUT", "SGX Caching Service Write Timeout")
	if err != nil {
		u.Config.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		u.Config.WriteTimeout, err = time.ParseDuration(writeTimeout)
		if err != nil {
			fmt.Fprintf(u.ConsoleWriter, "Invalid duration provided for SCS_SERVER_WRITE_TIMEOUT setting it to the default value\n")
			u.Config.WriteTimeout = constants.DefaultWriteTimeout
		}
	}

	idleTimeout, err := c.GetenvString("SCS_SERVER_IDLE_TIMEOUT", "SGX Caching Service Service Idle Timeout")
	if err != nil {
		u.Config.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		u.Config.IdleTimeout, err = time.ParseDuration(idleTimeout)
		if err != nil {
			fmt.Fprintf(u.ConsoleWriter, "Invalid duration provided for SCS_SERVER_IDLE_TIMEOUT setting it to the default value\n")
			u.Config.IdleTimeout = constants.DefaultIdleTimeout
		}
	}

	maxHeaderBytes, err := c.GetenvInt("SCS_SERVER_MAX_HEADER_BYTES", "SGX Caching Service Max Header Bytes Timeout")
	if err != nil {
		u.Config.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	} else {
		u.Config.MaxHeaderBytes = maxHeaderBytes
	}

	intelProvURL, err := c.GetenvString("INTEL_PROVISIONING_SERVER", "Intel ECDSA Provisioning Server URL")
	if err != nil {
		intelProvURL = constants.DefaultIntelProvServerURL
	} else if _, err = url.ParseRequestURI(intelProvURL); err != nil {
		return errors.Wrap(err, "SaveConfiguration() INTEL_PROVISIONING_SERVER provided is invalid")
	}
	u.Config.ProvServerInfo.ProvServerURL = intelProvURL

	intelProvAPIKey, err := c.GetenvString("INTEL_PROVISIONING_SERVER_API_KEY", "Intel ECDSA Provisioning Server API Subscription key")
	if err != nil {
		return errors.Wrap(err, "Intel API Subscription key not provided")
	}
	u.Config.ProvServerInfo.APISubscriptionkey = intelProvAPIKey

	logLevel, err := c.GetenvString("SCS_LOGLEVEL", "SCS Log Level")
	if err != nil {
		slog.Infof("config/config:SaveConfiguration() %s not defined, using default log level: Info", constants.SCSLogLevel)
		u.Config.LogLevel = log.InfoLevel
	} else {
		llp, err := log.ParseLevel(logLevel)
		if err != nil {
			slog.Info("config/config:SaveConfiguration() Invalid log level specified in env, using default log level: Info")
			u.Config.LogLevel = log.InfoLevel
		} else {
			u.Config.LogLevel = llp
			slog.Infof("config/config:SaveConfiguration() Log level set %s\n", logLevel)
		}
	}

	logMaxLen, err := c.GetenvInt("SCS_LOG_MAX_LENGTH", "SGX Caching Service Log maximum length")
	if err != nil || logMaxLen < constants.DefaultLogEntryMaxLength {
		u.Config.LogMaxLength = constants.DefaultLogEntryMaxLength
	} else {
		u.Config.LogMaxLength = logMaxLen
	}

	u.Config.LogEnableStdout = false
	logEnableStdout, err := c.GetenvString("SCS_ENABLE_CONSOLE_LOG", "SGX Caching Service Enable standard output")
	if err != nil || logEnableStdout == "" {
		u.Config.LogEnableStdout = false
	} else {
		u.Config.LogEnableStdout = true
	}

	refreshHours, err := c.GetenvInt("SCS_REFRESH_HOURS", "SCS Automatic Refresh of SGX Data")
	if err == nil {
		if refreshHours > 0 {
			u.Config.RefreshHours = refreshHours
		} else {
			u.Config.RefreshHours = constants.DefaultScsRefreshHours
		}
	} else {
		u.Config.RefreshHours = constants.DefaultScsRefreshHours
	}

	retryCount, err := c.GetenvInt("RETRY_COUNT", "Number of retry to PCS server")
	if err == nil {
		if retryCount >= 0 {
			u.Config.RetryCount = retryCount
		} else {
			u.Config.RetryCount = constants.DefaultRetrycount
		}
	} else {
		u.Config.RetryCount = constants.DefaultRetrycount
	}

	if u.Config.RetryCount == 0 {
		u.Config.WaitTime = 0
	} else {
		waitTime, err := c.GetenvInt("WAIT_TIME", "Duration Time between each retries to PCS")
		if err == nil {
			if waitTime >= 0 {
				u.Config.WaitTime = waitTime
			} else {
				u.Config.WaitTime = constants.DefaultWaitTime
			}
		} else {
			u.Config.WaitTime = constants.DefaultWaitTime
		}
	}

	if (u.Config.WaitTime * constants.DefaultRetrycount) >= 10 {
		u.Config.WaitTime = constants.DefaultWaitTime
		u.Config.RetryCount = constants.DefaultRetrycount
	}

	aasAPIURL, err := c.GetenvString("AAS_API_URL", "AAS Base URL")
	if err == nil && aasAPIURL != "" {
		if _, err = url.ParseRequestURI(aasAPIURL); err != nil {
			return errors.Wrap(err, "SaveConfiguration() AAS_API_URL provided is invalid")
		} else {
			u.Config.AuthServiceURL = aasAPIURL
		}
	} else if u.Config.AuthServiceURL == "" {
		log.Error("AAS_API_URL is not defined in environment")
		return errors.Wrap(errors.New("AAS_API_URL is not defined in environment"), "SaveConfiguration() ENV variable not found")
	}

	err = u.Config.Save()
	if err != nil {
		return errors.Wrap(err, "failed to save SCS config")
	}
	return nil
}

func (s Update_Service_Config) Validate(c setup.Context) error {
	return nil
}
