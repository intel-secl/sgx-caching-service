/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/scs/v4/types"

type FmspcTcbInfoRepository interface {
	Create(*types.FmspcTcbInfo) (*types.FmspcTcbInfo, error)
	Retrieve(*types.FmspcTcbInfo) (*types.FmspcTcbInfo, error)
	RetrieveAll() (types.FmspcTcbInfos, error)
	Update(*types.FmspcTcbInfo) error
	Delete(*types.FmspcTcbInfo) error
}
