/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// FmspcTcb struct is the database schema for fmspc_tcb_infos table
type FmspcTcbInfo struct {
	Fmspc              string    `json:"-" gorm:"primary_key"`
	TcbInfo            string    `json:"-" gorm:"type:text;not null"`
	TcbInfoIssuerChain string    `json:"-" gorm:"type:text;not null"`
	CreatedTime        time.Time `json:"-"`
	UpdatedTime        time.Time `json:"-"`
}

type FmspcTcbInfos []FmspcTcbInfo
