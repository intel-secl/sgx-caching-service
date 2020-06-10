/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// FmspcTcb struct is the database schema of a FmspcTcbs table
type FmspcTcbInfo struct {
	Fmspc              string `json:"-" gorm:"primary_key"`
	TcbInfo            string `json:"-" gorm:"type:text;not null"`
	TcbInfoIssuerChain string `json:"-" gorm:"type:text;not null"`
	CreatedTime        time.Time
	UpdatedTime        time.Time
}

type FmspcTcbInfos []FmspcTcbInfo
