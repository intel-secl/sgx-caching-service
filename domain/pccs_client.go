/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package domain

import (
	clog "intel/isecl/lib/common/v5/log"
	"net/http"
	"time"
)

var log = clog.GetDefaultLogger()

type HttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func NewPCCSClient() HttpClient {
	log.Trace("domain/scs_client.go:NewPCCSClient() Entering")
	defer log.Trace("resource/scs_client.go:NewPCCSClient() Leaving")

	client := &http.Client{
		Timeout: time.Duration(3 * time.Second),
	}

	return client
}
