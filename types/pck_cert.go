/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"github.com/lib/pq"
	"time"
)

// PckCert struct is the database schema of a PckCerts table
type PckCert struct {
	QeId           string         `json:"-" gorm:"primary_key"`
	PceId          string         `json:"-"`
	CertIndex      uint           `json:"-"`
	Tcbms          pq.StringArray `json:"-" gorm:"type:text[];not null"`
	Fmspc          string         `json:"-"`
	PckCerts       pq.StringArray `json:"-" gorm:"type:text[];not null"`
	PckCertChainId uint           `json:"pck_cert_chain_id" gorm:"type:int;not null"`
	CreatedTime    time.Time
	UpdatedTime    time.Time
}

type PckCerts []PckCert
