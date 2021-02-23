/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"github.com/stretchr/testify/assert"
	"intel/isecl/lib/common/v3/setup"
	"intel/isecl/scs/v3/config"
	"os"
	"testing"
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
	assert.Equal(t, nil, err)
	assert.Equal(t, 9000, c.Port)
}

func TestServerSetupEnv(t *testing.T) {
	os.Setenv("SCS_PORT", "9000")
	os.Setenv("INTEL_PROVISIONING_SERVER_API_KEY", "<provide_pcs_server_api_key>")
	c := config.Configuration{}
	s := Update_Service_Config{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	s.Config.SaveConfiguration(ctx)
	err := s.Run(ctx)
	assert.Equal(t, nil, err)
	assert.Equal(t, 9000, c.Port)
}
