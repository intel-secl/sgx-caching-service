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
