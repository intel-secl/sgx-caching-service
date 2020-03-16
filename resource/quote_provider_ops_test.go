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

func ExecuteQPLTest(input TestData){
	input.Test.Log("Test:", input.Description)
	var req *http.Request
	req = httptest.NewRequest("GET", input.Url, nil)
        req.Header.Add("Accept", "application/json")
        req.Header.Add("Content-Type", "application/json")

        input.Router.ServeHTTP(input.Recorder, req)
        input.Assert.Equal(input.StatusCode , input.Recorder.Code)
	input.Test.Log("Test:", input.Description,", Response:", input.Recorder.Body)
	input.Test.Log("Test:", input.Description, " ended")
}

func TestGetPckCert(t *testing.T) {
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

func TestGetPckCrl(t *testing.T) {
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

func TestGetFmspc(t *testing.T) {
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
