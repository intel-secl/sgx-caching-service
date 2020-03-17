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
		areq.Header.Add("Authorization", "Bearer "+input.Token)
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
			Url : "/scs/sgx/test/platforminfo/push",
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
		"enc_ppid": "974F57D49D60914F44C0A7B897035FA0114A4C3659316FF56354B122896AD4CEBE559031095010553998054A578578CC979A84C62337DD17AB96BAAA00DCD252B806EDC8CA405341214522C498A996CF73106E2A91A45F4E5710360DD32240F3D869479A408166E470A033DBA4B6241E8E7497F33F44BF885BFB87975D6AB769C4EDE1FBAC5840EE612CC54674CC5CF9DCE0CD5302340555D0EC1670D73C0500B38201143AD379FB8776202856681623C2D3F062E781D04FB0A513B48AC9A416CAB5448795205302F5A020A2DACBA7351A56F6DE92745D9AD49D11C62BA4579C377BCCB6F717D9A6CC20DB2E3765C1CF5E87111EB492ED1CE70DC4E2D22BA396BB8648CF315022A2A066323269D2E79B17CCB13BCEFDEA7A3E428DCC98FD14006D9DE187FC245A6D9EECE97C2D14BE8750EA25732854A84541B5B868164A0AAEE776BC98699CDD69169994A0B303F950491EA7B0F620FC0F1492553697D30701030CA9C9F70295845F8876A0B90E72889927BA29AA5BC32B3D340D4B7F6A0156",
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
