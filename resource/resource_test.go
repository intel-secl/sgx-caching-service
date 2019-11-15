/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource
import ( 

	"time"
        "testing"
	"github.com/gorilla/mux"
	"net/http/httptest"
	"github.com/stretchr/testify/assert"
	"intel/isecl/lib/common/middleware"
	"intel/isecl/sgx-caching-service/repository"
	"intel/isecl/sgx-caching-service/constants"
)


type TestData struct {
	Description string
	Recorder *httptest.ResponseRecorder
	Assert   *assert.Assertions
	Router   *mux.Router
	Test     *testing.T
	Token 	 string
	Url	 string
        StatusCode int
	PostData []byte
}

func mockRetrieveJWTSigningCerts() error {
        log.Trace("resource/resource_test:mockRetrieveJWTSigningCerts() Entering")
        defer log.Trace("resource/resource_test:mockRetrieveJWTSigningCerts() Leaving")

	return nil
}


func setupRouter(t *testing.T) *mux.Router {
	log.Trace("resource/resource_test:setupRouter() Entering")
	defer log.Trace("resource/resource_test:setupRouter() Leaving")

        r := mux.NewRouter()
        sr := r.PathPrefix("/scs/sgx/certification/v1/").Subrouter()
        func(setters ...func(*mux.Router, repository.SCSDatabase)) {
                for _, s := range setters {
                        s(sr, nil)
                }
        }(QuoteProviderOps)

        sr = r.PathPrefix("/scs/sgx/test/platforminfo/").Subrouter()
        sr.Use(middleware.NewTokenAuth("test_resources", "test_resources", mockRetrieveJWTSigningCerts, time.Minute*constants.DefaultJwtValidateCacheKeyMins))
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
