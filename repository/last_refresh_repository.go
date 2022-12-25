/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/scs/v5/types"

type LastRefreshRepository interface {
	Retrieve() (*types.LastRefresh, error)
	Update(*types.LastRefresh) error
}
