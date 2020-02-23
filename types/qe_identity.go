/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types
import (
        "time"
)

//QEIdentity struct is the database schema of a QEIdentities table
type QEIdentity struct {
	ID		uint	`json:"-" gorm:"auto_increment"`
	QeInfo		string	`json:"-" gorm:"type:text;not null"`
	QeIssuerChain	string	`json:"-" gorm:"type:text;not null"`
	CreatedTime	time.Time
	UpdatedTime	time.Time
}

type QEIdentities []QEIdentity
