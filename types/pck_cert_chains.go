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
	Id		uint		`json:"-" gorm:"primary_key;auto_increment"`
	CertChain	string		`json:"-"`
	CreatedTime	time.Time
	UpdatedTime	time.Time
}

type PckCertChains []PckCertChain
