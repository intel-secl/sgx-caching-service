/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/scs/v3/types"

type PlatformRepository interface {
	Create(*types.Platform) (*types.Platform, error)
	Retrieve(*types.Platform) (*types.Platform, error)
	RetrieveAll() (types.Platforms, error)
	Update(*types.Platform) error
	Delete(*types.Platform) error
}
