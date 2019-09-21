/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/sgx-caching-service/types"

type PckCertChainRepository interface {
	Create(types.PckCertChain) (*types.PckCertChain, error)
	Retrieve(types.PckCertChain) (*types.PckCertChain, error)
	RetrieveAll(user types.PckCertChain) (types.PckCertChains, error)
	Update(types.PckCertChain) error
	Delete(types.PckCertChain) error
}
