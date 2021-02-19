/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

import "intel/isecl/scs/v3/types"

type PckCertRepository interface {
	Create(*types.PckCert) (*types.PckCert, error)
	Retrieve(*types.PckCert) (*types.PckCert, error)
	RetrieveAll() (types.PckCerts, error)
	Update(*types.PckCert) error
	Delete(*types.PckCert) error
}
