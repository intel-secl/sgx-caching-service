/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"github.com/stretchr/testify/assert"
	"intel/isecl/lib/common/v4/setup"
	"intel/isecl/scs/v4/config"
	"math/rand"
	"os"
	"testing"
)

func RandomString() string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyz")

	// choose random string length to be 8
	letter := make([]rune, 8)
	for i := range letter {
		letter[i] = letters[rand.Intn(len(letters))]
	}
	return string(letter)
}

func TestDatabaseSetupEnv(t *testing.T) {
	testAssert := assert.New(t)

	hostName := RandomString()
	dbName := RandomString()
	dbUser := RandomString()
	dbPassword := RandomString()

	os.Setenv("SCS_DB_HOSTNAME", hostName)
	os.Setenv("SCS_DB_PORT", "5432")
	os.Setenv("SCS_DB_USERNAME", dbUser)
	os.Setenv("SCS_DB_PASSWORD", dbPassword)
	os.Setenv("SCS_DB_NAME", dbName)

	c := config.Configuration{}
	s := Database{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	testAssert.Error(err)
	testAssert.Equal(hostName, c.Postgres.Hostname)
	testAssert.Equal(5432, c.Postgres.Port)
	testAssert.Equal(dbUser, c.Postgres.Username)
	testAssert.Equal(dbPassword, c.Postgres.Password)
	testAssert.Equal(dbName, c.Postgres.DBName)
}
