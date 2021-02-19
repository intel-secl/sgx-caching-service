/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/scs/v3/types"

type PckCertChainRepository interface {
	Create(*types.PckCertChain) (*types.PckCertChain, error)
	Retrieve() (*types.PckCertChain, error)
	Update(*types.PckCertChain) error
	Delete(*types.PckCertChain) error
}
