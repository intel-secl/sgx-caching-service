/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"

	"github.com/lib/pq"
)

// PckCert struct is the database schema for pck_certs table
type PckCert struct {
	QeID        string         `json:"-" gorm:"primary_key"`
	PceID       string         `json:"-" gorm:"primary_key"`
	CertIndex   uint8          `json:"-"`
	Tcbms       pq.StringArray `json:"-" gorm:"type:text[];not null"`
	Fmspc       string         `json:"-"`
	PckCerts    pq.StringArray `json:"-" gorm:"type:text[];not null"`
	CreatedTime time.Time      `json:"-"`
	UpdatedTime time.Time      `json:"-"`
}

type PckCerts []PckCert
