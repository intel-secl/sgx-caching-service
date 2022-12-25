/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"intel/isecl/lib/common/v5/setup"
	"intel/isecl/scs/v5/config"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDatabaseSetup(t *testing.T) {
	db_user := RandStringBytes()
	db_pass := RandStringBytes()
	testAssert := assert.New(t)
	c := config.Configuration{}
	s := Database{
		Flags:         []string{"-db-host=hostname", "-db-port=5432", "-db-user=" + db_user, "-db-pass=" + db_pass, "-db-name=scs_db"},
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	testAssert.Error(err)
	testAssert.Equal("hostname", c.Postgres.Hostname)
	testAssert.Equal(5432, c.Postgres.Port)
	testAssert.Equal(db_user, c.Postgres.Username)
	testAssert.Equal(db_pass, c.Postgres.Password)
	testAssert.Equal("scs_db", c.Postgres.DBName)
}

func TestDatabaseSetupEnv(t *testing.T) {
	db_user := RandStringBytes()
	db_pass := RandStringBytes()
	testAssert := assert.New(t)
	os.Setenv("SCS_DB_HOSTNAME", "hostname")
	os.Setenv("SCS_DB_PORT", "5432")
	os.Setenv("SCS_DB_USERNAME", db_user)
	os.Setenv("SCS_DB_PASSWORD", db_pass)
	os.Setenv("SCS_DB_NAME", "scs_db")
	c := config.Configuration{}
	s := Database{
		Flags:         nil,
		Config:        &c,
		ConsoleWriter: os.Stdout,
	}
	ctx := setup.Context{}
	err := s.Run(ctx)
	testAssert.Error(err)
	testAssert.Equal("hostname", c.Postgres.Hostname)
	testAssert.Equal(5432, c.Postgres.Port)
	testAssert.Equal(db_user, c.Postgres.Username)
	testAssert.Equal(db_pass, c.Postgres.Password)
	testAssert.Equal("scs_db", c.Postgres.DBName)

	// Negative tests
	os.Setenv("SCS_DB_HOSTNAME", "")
	err = s.Run(ctx)
	assert.NotNil(t, err)

	os.Setenv("SCS_DB_HOSTNAME", "hostname")
	os.Setenv("SCS_DB_USERNAME", "")
	os.Setenv("SCS_DB_PASSWORD", "")
	err = s.Run(ctx)
	assert.NotNil(t, err)

	os.Setenv("SCS_DB_HOSTNAME", "hostname")
	os.Setenv("SCS_DB_USERNAME", RandStringBytes())
	os.Setenv("SCS_DB_PASSWORD", RandStringBytes())
	os.Setenv("SCS_DB_NAME", "")
	err = s.Run(ctx)
	assert.NotNil(t, err)
}

func TestDatabase_Validate(t *testing.T) {
	db := Database{
		Config: &config.Configuration{},
	}
	ctx := setup.Context{}

	db.Config.Postgres.Hostname = ""
	err := db.Validate(ctx)
	assert.NotNil(t, err)

	db.Config.Postgres.Hostname = RandStringBytes()
	db.Config.Postgres.Port = 0
	err = db.Validate(ctx)
	assert.NotNil(t, err)

	db.Config.Postgres.Port = 5432
	db.Config.Postgres.Username = ""
	err = db.Validate(ctx)
	assert.NotNil(t, err)

	db.Config.Postgres.Username = RandStringBytes()
	db.Config.Postgres.Password = ""
	err = db.Validate(ctx)
	assert.NotNil(t, err)

	db.Config.Postgres.Password = RandStringBytes()
	db.Config.Postgres.DBName = ""
	err = db.Validate(ctx)
	assert.NotNil(t, err)

	db.Config.Postgres.DBName = "testDB"
	err = db.Validate(ctx)
	assert.Nil(t, err)
}

const (
	testsslCert = "../test/sslcert.pem"
)

func TestConfigureDBSSLParams(t *testing.T) {
	_, _, err := configureDBSSLParams("allow", "", "")
	assert.Nil(t, err)

	_, _, err = configureDBSSLParams("verify-ca", "", "/test/file")
	assert.NotNil(t, err)

	testCert, _ := os.Create(testsslCert)
	testCert.Write([]byte("testContent"))
	defer os.Remove(testCert.Name())

	_, _, err = configureDBSSLParams("verify-ca", "", testsslCert)
	assert.Nil(t, err)

	_, _, err = configureDBSSLParams("verify-ca", testsslCert, testsslCert)
	assert.Nil(t, err)

	_, _, err = configureDBSSLParams("verify-ca", testsslCert, "")
	assert.NotNil(t, err)

	_, _, err = configureDBSSLParams("verify-ca", "testsslCert", "")
	assert.NotNil(t, err)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func RandStringBytes() string {
	rand.Seed(time.Now().UnixNano())
	b := make([]byte, 10)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
