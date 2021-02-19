/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/scs/v3/types"

type QEIdentityRepository interface {
	Create(*types.QEIdentity) (*types.QEIdentity, error)
	Retrieve() (*types.QEIdentity, error)
	Update(*types.QEIdentity) error
	Delete(*types.QEIdentity) error
}
