/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"intel/isecl/lib/common/setup"
	"intel/isecl/scs/config"
	"os"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestServerSetup(t *testing.T) {
	c := config.Configuration{}
	s := Server{
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
	os.Setenv("INTEL_PROVISIONING_SERVER_API_KEY", "ec73a0f55ca348cb9f02371f2b9ca614")
	c := config.Configuration{}
	s := Server{
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
