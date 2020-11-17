/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/scs/v3/types"

type PckCrlRepository interface {
	Create(types.PckCrl) (*types.PckCrl, error)
	Retrieve(types.PckCrl) (*types.PckCrl, error)
	RetrieveAll(user types.PckCrl) (types.PckCrls, error)
	RetrieveAllPckCrls() (types.PckCrls, error)
	Update(types.PckCrl) error
	Delete(types.PckCrl) error
}
