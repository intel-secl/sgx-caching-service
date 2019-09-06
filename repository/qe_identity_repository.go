/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/sgx-caching-service/types"

type QEIdentityRepository interface {
	Create(types.QEIdentity) (*types.QEIdentity, error)
	Retrieve(types.QEIdentity) (*types.QEIdentity, error)
	RetrieveAll() (types.QEIdentities, error)
	Update(types.QEIdentity) error
	Delete(types.QEIdentity) error
}
