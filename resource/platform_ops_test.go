/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
        "testing"
	"net/http"
	"encoding/json"
	"net/http/httptest"
	"github.com/stretchr/testify/assert"
)

func ExecuteSGXAgentTest(input TestData){
	input.Test.Log("Test:", input.Description)
	var req *http.Request
	if len(input.PostData)> 0 {
		req = httptest.NewRequest("POST", input.Url, bytes.NewReader(input.PostData))
	}else {
		req = httptest.NewRequest("POST", input.Url, nil)
	}

        req.Header.Add("Accept", "application/json")
        req.Header.Add("Content-Type", "application/json")
	if len(input.Token) > 0 {
		req.Header.Add("Authorization", "Bearer "+input.Token)
	}
        input.Router.ServeHTTP(input.Recorder, req)
        input.Assert.Equal(input.StatusCode , input.Recorder.Code)
	input.Test.Log("Test:", input.Description,", Response:", input.Recorder.Body)
	input.Test.Log("Test:", input.Description, " ended")
}

func TestSgxAgentPushInvalidBearerToken(t *testing.T) {
	input := TestData {
			Recorder : httptest.NewRecorder(),
			Assert : assert.New(t),
			Router : setupRouter(t),
			Test:t,
			Url : "/scs/sgx/test-noauth/platforminfo/push",
			Token : "invalidtoken",
			StatusCode: http.StatusUnauthorized,
			PostData : nil,
			Description: "InvalidToken",
	}
	ExecuteSGXAgentTest(input)
}

func TestSgxAgentPushInvalidJson(t *testing.T) {
	input := TestData {
			Recorder : httptest.NewRecorder(),
			Assert : assert.New(t),
			Router : setupRouter(t),
			Test:t,
			Url : "/scs/sgx/test-noauth/platforminfo/push",
			Token : "",
			StatusCode: http.StatusUnauthorized,
			PostData : nil,
			Description: "InvalidToken",
	}

	sgxAgentPostBody := map[string]interface{}{
		"enc_ppid": "invalidppid",
	}
	input.PostData, _ =  json.Marshal(sgxAgentPostBody)
	input.StatusCode = http.StatusBadRequest
	ExecuteSGXAgentTest(input)

	sgxAgentPostBody = map[string]interface{}{
		"enc_ppid": "b9632b61a767df16e7417db63c56770ce782babc231e83dd54ec2e9287232c958a3a0f00054980e4d6a709c7f202248f79af1d6247e71fefbd3a2f9fd444eff80d54ae73d1277d9d86805091fe23fc81dc4aa8be604147dbaadb7aaaf6cf5b8d6c7e56207cdf0b4c6f5d7ae6c3ec97d0fcfc0cb0dc4cb4eca6598beed7191a53dee367df1df53cfa12fbb481b6fc9ec7779bf6013016878ba0ecbe1c8e39274a1e2319056da6b3028201f5d2e37179140261514e27370e6047ff758d8e8e1bc45cf9eaaeaf67b9244ff4655675764b8e6e0d236f67f3b0f1dcd35286566330b91e02030abcba7a0d32a96d5c111b645fc6b1af152f4799228d1e1081938d25e38d39cabf65a0a41337752ab65924d3d08476368c7acb0a26d841ce5c03b3eccc06d1897ca06e152b6025d35208847c033dca757065f77ddb19843f66d959f38d99f66e2929d0f01aaa26b590298d22a58f870f7316d92ac9d42a489fd10e0fc0f928450389372498a7fee9d3a1b2d10c6ea15c180c6b58f352e59c72588fef24",
		"cpu_svn": "invalidcpusvn",
		"pce_svn": "invaliddata",
		"pce_id": "invaliddata",
		"qe_id": "invaliddata",
	}
	input.PostData, _ =  json.Marshal(sgxAgentPostBody)
	ExecuteSGXAgentTest(input)

	input.PostData = nil
	input.StatusCode = http.StatusBadRequest
	ExecuteSGXAgentTest(input)
}
