/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/scs/v5/repository"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
)

type TestData struct {
	Description string
	Recorder    *httptest.ResponseRecorder
	Assert      *assert.Assertions
	Router      *mux.Router
	Test        *testing.T
	Token       string
	URL         string
	StatusCode  int
	PostData    []byte
}

func setupRouter(t *testing.T) *mux.Router {
	r := mux.NewRouter()
	sr := r.PathPrefix("/scs/sgx/certification/v1/").Subrouter()
	func(setters ...func(*mux.Router, repository.SCSDatabase)) {
		for _, s := range setters {
			s(sr, nil)
		}
	}(QuoteProviderOps)

	sr = r.PathPrefix("/scs/sgx/test/platforminfo/").Subrouter()
	func(setters ...func(*mux.Router, repository.SCSDatabase)) {
		for _, s := range setters {
			s(sr, nil)
		}
	}(PlatformInfoOps)

	sr = r.PathPrefix("/scs/sgx/test-noauth/platforminfo/").Subrouter()
	func(setters ...func(*mux.Router, repository.SCSDatabase)) {
		for _, s := range setters {
			s(sr, nil)
		}
	}(PlatformInfoOps)
	return r
}
