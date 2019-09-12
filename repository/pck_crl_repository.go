/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/sgx-caching-service/types"

type PckCrlRepository interface {
	Create(types.PckCrl) (*types.PckCrl, error)
	Retrieve(types.PckCrl) (*types.PckCrl, error)
	RetrieveAll(user types.PckCrl) (types.PckCrls, error)
	RetrieveAllPckCrls() (types.PckCrls, error)
	Update(types.PckCrl) error
	Delete(types.PckCrl) error
}
