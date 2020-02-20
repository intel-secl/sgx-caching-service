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
	Id			uint    `json:"-" gorm:"primary_key;auto_increment"`
	QeIdentity        	string	  `json:"-" gorm:"type:text;not null"`
	QeIdentityIssuerChain   string	  `json:"-" gorm:"type:text;not null"`
	CreatedTime    		time.Time
	UpdatedTime    		time.Time
}

type QEIdentities []QEIdentity
