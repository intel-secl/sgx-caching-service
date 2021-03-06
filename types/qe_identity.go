/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// QEIdentity struct is the database schema for qe_identities table
type QEIdentity struct {
	ID            string    `json:"-" gorm:"primary_key"`
	QeInfo        string    `json:"-" gorm:"type:text;not null"`
	QeIssuerChain string    `json:"-" gorm:"type:text;not null"`
	CreatedTime   time.Time `json:"-"`
	UpdatedTime   time.Time `json:"-"`
}
