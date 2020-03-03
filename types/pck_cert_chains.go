/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types
import (
        "time"
)

// PckCertChain struct is the database schema of a PckCertChains table
type PckCertChain struct {
	ID		uint		`json:"-" gorm:"auto_increment"`
	PckCertChain	string		`json:"-" gorm:"type:text;not null"`
	CreatedTime	time.Time
	UpdatedTime	time.Time
}

type PckCertChains []PckCertChain
