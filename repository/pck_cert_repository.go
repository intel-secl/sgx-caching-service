/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/sgx-caching-service/types"

type PckCertRepository interface {
	Create(types.PckCert) (*types.PckCert, error)
	Retrieve(types.PckCert) (*types.PckCert, error)
	RetrieveAll(user types.PckCert) (types.PckCerts, error)
	Update(types.PckCert) error
	Delete(types.PckCert) error
}
