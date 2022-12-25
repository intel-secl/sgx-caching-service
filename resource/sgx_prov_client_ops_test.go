/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/scs/v5/config"
	"intel/isecl/scs/v5/domain/mocks"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRespFromProvServer(t *testing.T) {
	conf := config.Load(testConfigFilePath)
	client := mocks.NewClientMock(http.StatusOK)

	req, _ := http.NewRequest(http.MethodPost, "/test", nil)

	_, err := getRespFromProvServer(req, nil, nil)
	assert.NotNil(t, err)

	_, err = getRespFromProvServer(req, nil, conf)
	assert.NotNil(t, err)

	_, err = getRespFromProvServer(req, client, conf)
	assert.Nil(t, err)

	client = mocks.NewClientMock(http.StatusBadRequest)
	_, err = getRespFromProvServer(req, client, conf)
	assert.NotNil(t, err)

	client = mocks.NewClientMock(http.StatusUnauthorized)
	_, err = getRespFromProvServer(req, client, conf)
	assert.NotNil(t, err)
}

func TestGetPckCertFromProvServer(t *testing.T) {

	conf := config.Load(testConfigFilePath)
	client := mocks.NewClientMock(http.StatusOK)

	_, err := getPckCertFromProvServer("", "", nil, nil)
	assert.NotNil(t, err)

	_, err = getPckCertFromProvServer("", "", conf, nil)
	assert.NotNil(t, err)

	_, err = getPckCertFromProvServer("", "", conf, &client)
	assert.Nil(t, err)

	client = mocks.NewClientMock(401)
	_, err = getPckCertFromProvServer("", "", conf, &client)
	assert.NotNil(t, err)
}

func TestNegativeCases(t *testing.T) {
	conf := config.Load(testConfigFilePath)
	client := mocks.NewClientMock(http.StatusOK)

	// getPckCertsWithManifestFromProvServer

	_, err := getPckCertsWithManifestFromProvServer("", "", nil, nil)
	assert.NotNil(t, err)

	_, err = getPckCertsWithManifestFromProvServer("", "", conf, nil)
	assert.NotNil(t, err)

	_, err = getPckCertsWithManifestFromProvServer("", "", conf, &client)
	assert.Nil(t, err)

	client = mocks.NewClientMock(401)
	_, err = getPckCertsWithManifestFromProvServer("", "", conf, &client)
	assert.NotNil(t, err)

	// getPckCrlFromProvServer
	_, err = getPckCrlFromProvServer("", "", conf, nil)
	assert.NotNil(t, err)
	_, err = getPckCrlFromProvServer("", "", conf, &client)
	assert.NotNil(t, err)

	// getFmspcTcbInfoFromProvServer
	_, err = getFmspcTcbInfoFromProvServer("", conf, &client)
	assert.NotNil(t, err)

	// getQeInfoFromProvServer
	_, err = getQeInfoFromProvServer(conf, nil)
	assert.NotNil(t, err)

	_, err = getQeInfoFromProvServer(conf, &client)
	assert.NotNil(t, err)
}
