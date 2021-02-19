/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/scs/v3/config"
	"intel/isecl/scs/v3/constants"
	"io"
	"time"
)

type Server struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (s Server) Run(c setup.Context) error {
	fmt.Fprintln(s.ConsoleWriter, "Running server setup...")
	defaultPort, err := c.GetenvInt("SCS_PORT", "SGX Caching Service http port")
	if err != nil {
		defaultPort = constants.DefaultHTTPSPort
	}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)

	fs.IntVar(&s.Config.Port, "port", defaultPort, "SGX Caching Service http port")
	err = fs.Parse(s.Flags)
	if err != nil {
		return errors.Wrap(err, "tasks/server:Run() Could not parse input flags")
	}
	if s.Config.Port > 65535 || s.Config.Port <= 1024 {
		return errors.New("Invalid or reserved port")
	}
	fmt.Fprintf(s.ConsoleWriter, "Using HTTPS port: %d\n", s.Config.Port)

	readTimeout, err := c.GetenvInt("SCS_SERVER_READ_TIMEOUT", "SGX Caching Service Read Timeout")

	if err != nil {
		s.Config.ReadTimeout = constants.DefaultReadTimeout
	} else {
		s.Config.ReadTimeout = time.Duration(readTimeout) * time.Second
	}

	readHeaderTimeout, err := c.GetenvInt("SCS_SERVER_READ_HEADER_TIMEOUT", "SGX Caching Service Read Header Timeout")
	if err != nil {
		s.Config.ReadHeaderTimeout = constants.DefaultReadHeaderTimeout
	} else {
		s.Config.ReadHeaderTimeout = time.Duration(readHeaderTimeout) * time.Second
	}

	writeTimeout, err := c.GetenvInt("SCS_SERVER_WRITE_TIMEOUT", "SGX Caching Service Write Timeout")
	if err != nil {
		s.Config.WriteTimeout = constants.DefaultWriteTimeout
	} else {
		s.Config.WriteTimeout = time.Duration(writeTimeout) * time.Second
	}

	idleTimeout, err := c.GetenvInt("SCS_SERVER_IDLE_TIMEOUT", "SGX Caching Service Service Idle Timeout")
	if err != nil {
		s.Config.IdleTimeout = constants.DefaultIdleTimeout
	} else {
		s.Config.IdleTimeout = time.Duration(idleTimeout) * time.Second
	}

	maxHeaderBytes, err := c.GetenvInt("SCS_SERVER_MAX_HEADER_BYTES", "SGX Caching Service Max Header Bytes Timeout")
	if err != nil {
		s.Config.MaxHeaderBytes = constants.DefaultMaxHeaderBytes
	} else {
		s.Config.MaxHeaderBytes = maxHeaderBytes
	}

	intelProvURL, err := c.GetenvString("INTEL_PROVISIONING_SERVER", "Intel ECDSA Provisioning Server URL")
	if err != nil {
		intelProvURL = constants.DefaultIntelProvServerURL
	}
	s.Config.ProvServerInfo.ProvServerURL = intelProvURL

	intelProvAPIKey, err := c.GetenvString("INTEL_PROVISIONING_SERVER_API_KEY", "Intel ECDSA Provisioning Server API Subscription key")
	if err != nil {
		return errors.Wrap(err, "Intel API Subscription key not provided")
	}
	s.Config.ProvServerInfo.APISubscriptionkey = intelProvAPIKey

	logMaxLen, err := c.GetenvInt("SCS_LOG_MAX_LENGTH", "SGX Caching Service Log maximum length")
	if err != nil || logMaxLen < constants.DefaultLogEntryMaxLength {
		s.Config.LogMaxLength = constants.DefaultLogEntryMaxLength
	} else {
		s.Config.LogMaxLength = logMaxLen
	}

	s.Config.LogEnableStdout = false
	logEnableStdout, err := c.GetenvString("SCS_ENABLE_CONSOLE_LOG", "SGX Caching Service Enable standard output")
	if err != nil || logEnableStdout == "" {
		s.Config.LogEnableStdout = false
	} else {
		s.Config.LogEnableStdout = true
	}

	err = s.Config.Save()
	if err != nil {
		return errors.Wrap(err, "failed to save SCS config")
	}
	return nil
}

func (s Server) Validate(c setup.Context) error {
	return nil
}
