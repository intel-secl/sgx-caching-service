/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// PckCertChain struct is the database schema for pck_cert_chains table
type PckCertChain struct {
	PckCertChain string    `json:"-" gorm:"type:text;not null"`
	CreatedTime  time.Time `json:"-"`
	UpdatedTime  time.Time `json:"-"`
}
