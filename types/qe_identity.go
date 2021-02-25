/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"github.com/google/uuid"
	"time"
)

// QEIdentity struct is the database schema for qe_identities table
type QEIdentity struct {
	Id            uuid.UUID `gorm:"primary_key;type:uuid"`
	QeInfo        string    `json:"-" gorm:"type:text;not null"`
	QeIssuerChain string    `json:"-" gorm:"type:text;not null"`
	CreatedTime   time.Time `json:"-"`
	UpdatedTime   time.Time `json:"-"`
}
