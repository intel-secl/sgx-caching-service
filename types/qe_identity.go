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

type QeIdentityJSON struct {
	EnclaveIdentity EnclaveIdentityType `json:"enclaveIdentity"`
	Signature       string              `json:"signature"`
}
type EnclaveIdentityType struct {
	ID                      string          `json:"id"`
	Version                 uint16          `json:"version"`
	IssueDate               string          `json:"issueDate"`
	NextUpdate              string          `json:"nextUpdate"`
	TcbEvaluationDataNumber uint16          `json:"tcbEvaluationDataNumber"`
	MiscSelect              string          `json:"miscselect"`
	MiscSelectMask          string          `json:"miscselectMask"`
	Attributes              string          `json:"attributes"`
	AttributesMask          string          `json:"attributesMask"`
	MrSigner                string          `json:"mrsigner"`
	IsvProdID               uint16          `json:"isvprodid"`
	TcbLevels               []TcbLevelsInfo `json:"tcbLevels"`
}

type TcbLevelsInfo struct {
	Tcb       TcbInfo `json:"tcb"`
	TcbDate   string  `json:"tcbDate"`
	TcbStatus string  `json:"tcbStatus"`
}

type TcbInfo struct {
	IsvSvn uint16 `json:"isvsvn"`
}
