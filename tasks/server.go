/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"errors"
	"flag"
	"fmt"
	"intel/isecl/sgx-caching-service/config"
	"intel/isecl/sgx-caching-service/constants"
	"intel/isecl/lib/common/setup"
	"io"
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
		defaultPort = constants.DefaultHttpPort
	}
	fs := flag.NewFlagSet("server", flag.ContinueOnError)

	fs.IntVar(&s.Config.Port, "port", defaultPort, "SGX Caching Service http port")
	err = fs.Parse(s.Flags)
	if err != nil {
		return err
	}
	if s.Config.Port > 65535 || s.Config.Port <= 1024 {
		return errors.New("Invalid or reserved port")
	}
	fmt.Fprintf(s.ConsoleWriter, "Using HTTPS port: %d\n", s.Config.Port)

	s.Config.AuthDefender.MaxAttempts = constants.DefaultAuthDefendMaxAttempts
	s.Config.AuthDefender.IntervalMins = constants.DefaultAuthDefendIntervalMins
	s.Config.AuthDefender.LockoutDurationMins = constants.DefaultAuthDefendLockoutMins

	cmsBaseUrl, err := c.GetenvString("CMS_BASE_URL", "CMS Base URL")
	if err != nil {
		fmt.Fprintf(s.ConsoleWriter, "CMS Url not provided\n")
		return err
	}
	s.Config.CMSBaseUrl = cmsBaseUrl


	intelProvUrl, err := c.GetenvString("INTEL_PROVISIONING_SERVER", "Intel ECDSA Provisioning Server URL")
	if err != nil {
		intelProvUrl = constants.DefaultIntelProvServerURL
	}
	s.Config.ProvServerInfo.ProvServerUrl = intelProvUrl


	intelProvApiKey, err := c.GetenvString("INTEL_PROVISIONING_SERVER_API_KEY", "Intel ECDSA Provisioning Server API Subscription key")
	if err != nil {
		fmt.Fprintf(s.ConsoleWriter, "Intel API Subscription key not provided")
	}
	s.Config.ProvServerInfo.ApiSubscriptionkey = intelProvApiKey
	proxyUrl, err := c.GetenvString("PROXY_URL", "Enviroment Proxy URL")
	if err != nil {
		proxyUrl = ""
		fmt.Fprintf(s.ConsoleWriter, "Proxy URL not provided\n")
	}
	s.Config.ProxyUrl = proxyUrl

	return s.Config.Save()
}

func (s Server) Validate(c setup.Context) error {
	return nil
}
