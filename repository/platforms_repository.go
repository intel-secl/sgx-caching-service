/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/sgx-caching-service/types"

type PlatformRepository interface {
	Create(types.Platform) (*types.Platform, error)
	Retrieve(types.Platform) (*types.Platform, error)
	RetrieveAll(types.Platform) (types.Platforms, error)
	RetrieveAllPlatformInfo() (types.Platforms, error)
	Update(types.Platform) error
	Delete(types.Platform) error
}
