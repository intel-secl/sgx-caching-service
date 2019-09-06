/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	consts "intel/isecl/sgx-caching-service/constants"
	comctx "intel/isecl/lib/common/context"

	"intel/isecl/lib/common/auth"
	ct "intel/isecl/lib/common/types/aas"
	"net/http"

	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
)

type errorHandlerFunc func(w http.ResponseWriter, r *http.Request) error

func (ehf errorHandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := ehf(w, r); err != nil {
		log.WithError(err).Error("HTTP Error")
		if gorm.IsRecordNotFoundError(err) {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		switch t := err.(type) {
		case *resourceError:
			http.Error(w, t.Message, t.StatusCode)
		case resourceError:
			http.Error(w, t.Message, t.StatusCode)
		case *privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		case privilegeError:
			http.Error(w, t.Message, t.StatusCode)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

type privilegeError struct {
	StatusCode int
	Message    string
}

func (e privilegeError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

type resourceError struct {
	StatusCode int
	Message    string
}

func (e resourceError) Error() string {
	return fmt.Sprintf("%d: %s", e.StatusCode, e.Message)
}

func AuthorizeEndpoint(r *http.Request, roleNames []string, needContext bool, retNilCtxForEmptyCtx bool) (*map[string]*ct.RoleInfo, error) {
	// Check query authority
	privileges, err := comctx.GetUserRoles(r)
	if err != nil {
		log.WithError(err).Error("could not get user roles from http context")
		return nil,
			&resourceError{Message: "not able to get roles from context", StatusCode: http.StatusInternalServerError}
	}

	// this function check if the user requesting to perform operation has the right roles.
	reqRoles := make([]ct.RoleInfo, len(roleNames))
	for i, role := range roleNames {
		reqRoles[i] = ct.RoleInfo{Service: consts.ServiceName, Name: role}
	}

	ctxMap, foundRole := auth.ValidatePermissionAndGetRoleContext(privileges, reqRoles, retNilCtxForEmptyCtx)
	if !foundRole {
		return nil, &privilegeError{Message: "", StatusCode: http.StatusUnauthorized}
	}

	return ctxMap, nil
}

func AuthorizeEndPointAndGetServiceFilter(r *http.Request, roleNames []string) ([]string, error) {
	ctxMap, err := AuthorizeEndpoint(r, roleNames, true, true)
	if err != nil {
		return nil, err
	}
	svcFltr := []string{}
	if ctxMap != nil {
		for _, val := range *ctxMap {
			svcFltr = append(svcFltr, val.Context)
		}
	}
	return svcFltr, nil
}
