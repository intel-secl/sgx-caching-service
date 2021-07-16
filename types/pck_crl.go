/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// PckCrl struct is the database schema for pck_crls table
type PckCrl struct {
	Ca              string    `json:"-" gorm:"primary_key"`
	PckCrlCertChain string    `json:"-" gorm:"index:idx_pckcrlcertchain;type:text;not null;unique"`
	PckCrl          string    `json:"-" gorm:"type:text;idx_pckcrl;not null;unique"`
	CreatedTime     time.Time `json:"-"`
	UpdatedTime     time.Time `json:"-"`
}

type PckCrls []PckCrl
