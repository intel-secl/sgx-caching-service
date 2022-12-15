/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"intel/isecl/lib/common/v5/setup"
	"intel/isecl/scs/v5/config"
	"os"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestServerSetup(t *testing.T) {
	c := config.Configuration{}
	s := Update_Service_Config{
		Flags:         []string{"-port=9000"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.NotNil(t, err)
	assert.Equal(t, 9000, c.Port)
}

func TestServerSetupEnv(t *testing.T) {
	os.Setenv("AAS_API_URL", "http://localhost:8444/aas/v1")
	os.Setenv("SCS_PORT", "9000")
	os.Setenv("INTEL_PROVISIONING_SERVER_API_KEY", "abc1234")
	c := *config.Load("testconfig.yml")
	defer func() {
		os.Remove("testconfig.yml")
	}()

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Config.SaveConfiguration("update_service_config", ctx)
	err := s.Run(ctx)
	assert.Equal(t, nil, err)
	assert.Equal(t, 9000, c.Port)
}

func TestServerSetupInvalidAASUrl(t *testing.T) {
	os.Setenv("AAS_API_URL", "abcdefg")
	os.Setenv("SCS_PORT", "9000")
	os.Setenv("INTEL_PROVISIONING_SERVER_API_KEY", "abc1234")
	c := *config.Load("testconfig.yml")
	defer func() {
		os.Remove("testconfig.yml")
	}()

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Config.SaveConfiguration("update_service_config", ctx)
	err := s.Run(ctx)
	assert.True(t, strings.Contains(err.Error(), "AAS_API_URL provided is invalid"))
	assert.Equal(t, 9000, c.Port)
}

func TestServerSetupInvalidIPSServerArg(t *testing.T) {
	os.Setenv("AAS_API_URL", "http://localhost:8444/aas/v1")
	os.Setenv("SCS_PORT", "9000")
	os.Setenv("INTEL_PROVISIONING_SERVER_API_KEY", "abc1234")
	os.Setenv("INTEL_PROVISIONING_SERVER", "abcdefg")
	c := *config.Load("testconfig.yml")
	defer func() {
		os.Remove("testconfig.yml")
	}()

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Config.SaveConfiguration("update_service_config", ctx)
	err := s.Run(ctx)
	assert.True(t, strings.Contains(err.Error(), "INTEL_PROVISIONING_SERVER provided is invalid"))
	assert.Equal(t, 9000, c.Port)
}

func TestServerSetupInvalidLogLevelArg(t *testing.T) {
	os.Setenv("AAS_API_URL", "http://localhost:8444/aas/v1")
	os.Setenv("SCS_PORT", "9000")
	os.Setenv("INTEL_PROVISIONING_SERVER_API_KEY", "abc1234")
	os.Setenv("INTEL_PROVISIONING_SERVER", "http://localhost:8444/ips")
	os.Setenv("LOG_LEVEL", "invalidloglevel")
	c := *config.Load("testconfig.yml")
	defer func() {
		os.Remove("testconfig.yml")
	}()

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Config.SaveConfiguration("update_service_config", ctx)
	err := s.Run(ctx)
	assert.NoError(t, err)
	assert.Equal(t, logrus.InfoLevel, c.LogLevel)
}

func TestServerSetupWithInvalidValues(t *testing.T) {
	os.Setenv("AAS_API_URL", "http://localhost:8444/aas/v1")
	os.Setenv("SCS_PORT", "1000")
	
	c := *config.Load("testconfig.yml")
	defer func() {
		os.Remove("testconfig.yml")
	}()

	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	assert.Error(t, err)

	os.Setenv("SCS_PORT", "9000")
	// Set invalid values and verify if default values are set

	os.Setenv("SCS_SERVER_READ_TIMEOUT", "testValue")
	os.Setenv("SCS_SERVER_READ_HEADER_TIMEOUT", "testValue")
	os.Setenv("SCS_SERVER_WRITE_TIMEOUT", "testValue")
	os.Setenv("SCS_SERVER_IDLE_TIMEOUT", "testValue")
	os.Setenv("SCS_SERVER_MAX_HEADER_BYTES", "testValue")
	os.Setenv("SCS_LOGLEVEL", "testValue")
	os.Setenv("SCS_LOG_MAX_LENGTH", "testValue")
	os.Setenv("SCS_ENABLE_CONSOLE_LOG", "testValue")
	err = s.Run(ctx)
	assert.NoError(t, err)

	os.Setenv("SCS_REFRESH_HOURS", "1")
	os.Setenv("RETRY_COUNT", "1")
	os.Setenv("WAIT_TIME", "11")
	err = s.Run(ctx)
	assert.NoError(t, err)

	os.Setenv("SCS_REFRESH_HOURS", "-1")
	os.Setenv("RETRY_COUNT", "-1")
	os.Setenv("WAIT_TIME", "-11")
	err = s.Run(ctx)
	assert.NoError(t, err)

	// set valid values in env
	os.Setenv("SCS_SERVER_MAX_HEADER_BYTES", "1500")
	os.Setenv("SCS_LOGLEVEL", "info")
	os.Setenv("SCS_LOG_MAX_LENGTH", "1100")
	s.Config.RetryCount = 0
	err = s.Run(ctx)
	assert.NoError(t, err)

	os.Setenv("AAS_API_URL", "")
	s.Config.AuthServiceURL = ""
	err = s.Run(ctx)
	assert.Error(t, err)

	err = s.Validate(ctx)
	assert.NoError(t, err)
}
