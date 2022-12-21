/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/scs/v5/constants"
	"net/url"
	"regexp"

	"github.com/pkg/errors"
)

var regExMap = map[string]*regexp.Regexp{
	constants.EncPPIDKey: regexp.MustCompile(`^[0-9a-fA-F]{768}$`),
	constants.CPUSvnKey:  regexp.MustCompile(`^[0-9a-fA-F]{32}$`),
	constants.PceSvnKey:  regexp.MustCompile(`^[0-9a-fA-F]{4}$`),
	constants.PceIDKey:   regexp.MustCompile(`^[0-9a-fA-F]{4}$`),
	constants.CaKey:      regexp.MustCompile(`^(processor|platform)$`),
	constants.FmspcKey:   regexp.MustCompile(`^[0-9a-fA-F]{12}$`),
	constants.QeIDKey:    regexp.MustCompile(`^[0-9a-fA-F]{32}$`),
	constants.HwUUIDKey:  regexp.MustCompile(`([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}){1}`),
	constants.PPID:       regexp.MustCompile(`^[0-9a-f]{32}$`)}

func validateInputString(key, inString string) bool {
	regEx := regExMap[key]
	if key == "" || !regEx.MatchString(inString) {
		log.WithField(key, inString).Error("Input Validation")
		return false
	}
	return true
}

func validateQueryParams(params url.Values, validQueries map[string]bool) error {
	log.Trace("resource/validation:validateQueryParams() Entering")
	defer log.Trace("resource/validation:validateQueryParams() Leaving")
	if len(params) > constants.MaxQueryParamsLength {
		return errors.New("Invalid query parameters provided. Number of query parameters exceeded maximum value")
	}
	for param := range params {
		if _, hasQuery := validQueries[param]; !hasQuery {
			return errors.New("Invalid query parameter provided. Refer to Swagger doc for details.")
		}
	}
	return nil
}
