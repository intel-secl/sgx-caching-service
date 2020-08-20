/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/scs/types"

type PlatformTcbRepository interface {
	Create(types.PlatformTcb) (*types.PlatformTcb, error)
	Retrieve(types.PlatformTcb) (*types.PlatformTcb, error)
	RetrieveAll(types.PlatformTcb) (types.PlatformTcbs, error)
	RetrieveAllPlatformTcbInfo() (types.PlatformTcbs, error)
	Update(types.PlatformTcb) error
	Delete(types.PlatformTcb) error
}
