/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"intel/isecl/sgx-caching-service/version"
	"intel/isecl/sgx-caching-service/config"
	"net/http"
	"github.com/gorilla/mux"
)

func SetVersion(r *mux.Router, config *config.Configuration) {
	log.Trace("resource/version:SetVersion() Entering")
	defer log.Trace("resource/version:SetVersion() Leaving")

	r.Handle("/version", getVersion()).Methods("GET")
}

func getVersion() http.HandlerFunc {
	log.Trace("resource/version:getVersion() Entering")
	defer log.Trace("resource/version:getVersion() Leaving")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verStr := fmt.Sprintf("%s-%s", version.Version, version.GitHash)
		log.Debugf("resource/version:getVersion() CMS version : %v", verStr)
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(verStr))
	})
}
