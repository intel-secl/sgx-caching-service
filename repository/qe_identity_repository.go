/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/scs/types"

type QEIdentityRepository interface {
	Create(types.QEIdentity) (*types.QEIdentity, error)
	Retrieve(types.QEIdentity) (*types.QEIdentity, error)
	RetrieveAll() (types.QEIdentities, error)
	Update(types.QEIdentity) error
	Delete(types.QEIdentity) error
}
