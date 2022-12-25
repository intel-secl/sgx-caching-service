/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/scs/v5/types"

type PlatformTcbRepository interface {
	Create(*types.PlatformTcb) (*types.PlatformTcb, error)
	Retrieve(*types.PlatformTcb) (*types.PlatformTcb, error)
	RetrieveAll() (types.PlatformTcbs, error)
	Update(*types.PlatformTcb) error
	Delete(*types.PlatformTcb) error
}
