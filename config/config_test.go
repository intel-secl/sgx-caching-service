/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package config

import (
	"intel/isecl/lib/common/v5/setup"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoad(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	temp.WriteString("port: 1337\naas:\n")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	assert.Equal(t, 1337, c.Port)
}

func TestSave(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	c.Port = 1337
	c.Save()
	c2 := Load(temp.Name())
	assert.Equal(t, 1337, c2.Port)

	// negative test
	c.configFile = "/test/nofound.yml"
	err := c.Save()
	assert.NotNil(t, err)
}

func TestNoConfigFileErr(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Configuration{}
	c.Port = 1337
	err := c.Save()
	assert.True(t, strings.Contains(err.Error(), ErrNoConfigFile.Error()))
}

func TestSaveConfigurationCMSTlsUnset(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	c.Port = 1337
	var setupContext setup.Context
	err := c.SaveConfiguration("all", setupContext)
	assert.True(t, strings.Contains(err.Error(), "CMS_TLS_CERT_SHA384 is not defined in environment"))
}

func TestSaveConfigurationCMSUrlInvalid(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	c.Port = 1337
	os.Setenv("CMS_TLS_CERT_SHA384", "f5662f725b1440b6103c2a8cf1e993a7e7931bae53883f57d3e0"+
		"b88ed54e1f53fe88672b77ee9a944b13c41299916d13")
	os.Setenv("CMS_BASE_URL", "invalidurl")
	defer os.Clearenv()
	var setupContext setup.Context
	err := c.SaveConfiguration("all", setupContext)
	assert.True(t, strings.Contains(err.Error(), "CMS_BASE_URL provided is invalid"))
}

func TestSaveConfiguration(t *testing.T) {
	temp, _ := ioutil.TempFile("", "config.yml")
	defer os.Remove(temp.Name())
	c := Load(temp.Name())
	c.Port = 1337
	os.Setenv("CMS_TLS_CERT_SHA384", "f5662f725b1440b6103c2a8cf1e993a7e7931bae53883f57d3e0"+
		"b88ed54e1f53fe88672b77ee9a944b13c41299916d13")
	os.Setenv("CMS_BASE_URL", "https://cms.com/v1/cms/")
	defer os.Clearenv()
	var setupContext setup.Context
	err := c.SaveConfiguration("all", setupContext)
	assert.Nil(t, err)

	os.Setenv("SCS_TLS_CERT_CN", "SCS TEST CERT NAME")
	os.Setenv("KEY_PATH", "/test/key.pem")
	os.Setenv("CERT_PATH", "/test/cert.pem")
	os.Setenv("SAN_LIST", "localhost")
	err = c.SaveConfiguration("all", setupContext)
	assert.Nil(t, err)
}

func TestSaveConfigurationCMSUrlUnset(t *testing.T) {
	c := Load("config.yml")
	defer os.Remove("config.yml")
	os.Setenv("CMS_TLS_CERT_SHA384", "f5662f725b1440b6103c2a8cf1e993a7e7931bae53883f57d3e0"+
		"b88ed54e1f53fe88672b77ee9a944b13c41299916d13")
	defer os.Clearenv()
	c.Port = 1337
	var setupContext setup.Context
	err := c.SaveConfiguration("all", setupContext)
	assert.True(t, strings.Contains(err.Error(), "CMS_BASE_URL is not defined in environment"))
}

func TestGlobal(t *testing.T) {
	global = nil
	conf := Global()
	assert.NotNil(t, conf)
}
