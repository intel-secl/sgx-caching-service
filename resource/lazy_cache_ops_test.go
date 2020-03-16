/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
        "testing"
	"net/http"
	"net/http/httptest"
	"github.com/stretchr/testify/assert"
)

func TestGetLazyCachePckCert(t *testing.T) {
	input := TestData {
			Recorder : httptest.NewRecorder(),
			Assert : assert.New(t),
			Router : setupRouter(t),
			Test:t,
			Url : "/scs/sgx/certification/v1/pckcert",
			StatusCode: http.StatusBadRequest,
			PostData : nil,
			Token:"",
			Description: "Without Query Params",
	}
	ExecuteQPLTest(input)

	input.Url = "/scs/sgx/certification/v1/pckcert?encrypted_ppid=invalid&cpusvn=invalid&pcesvn=invalid&pceid=invalid"
	input.Description = "Invalid Query Params"
	ExecuteQPLTest(input)
}

func TestGetLazyCachePckCrl(t *testing.T) {
	input := TestData {
			Recorder : httptest.NewRecorder(),
			Assert : assert.New(t),
			Router : setupRouter(t),
			Test:t,
			Url : "/scs/sgx/certification/v1/pckcrl",
			StatusCode: http.StatusBadRequest,
			PostData : nil,
			Token:"",
			Description: "Without Query Params",
	}
	ExecuteQPLTest(input)
	input.Url = "/scs/sgx/certification/v1/pckcrl?ca=invalid"
	input.Description = "Invalid Query Params"
	ExecuteQPLTest(input)
}

func TestGetLazyCacheFmspc(t *testing.T) {
	input := TestData {
			Recorder : httptest.NewRecorder(),
			Assert : assert.New(t),
			Router : setupRouter(t),
			Test:t,
			Url : "/scs/sgx/certification/v1/tcb",
			StatusCode: http.StatusBadRequest,
			PostData : nil,
			Token:"",
			Description: "Without Query Params",
	}
	ExecuteQPLTest(input)
	input.Url = "/scs/sgx/certification/v1/tcb?fmspc=invalid"
	input.Description = "Invalid Query Params"
	ExecuteQPLTest(input)
}
