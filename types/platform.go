/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

// Platform struct is the database schema of a platforms table
type Platform struct {
	QeId        string    `json:"-" gorm:"primary_key"`
	PceId       string    `json:"-"`
	CpuSvn      string    `json:"-"`
	PceSvn      string    `json:"-"`
	Encppid     string    `json:"-"`
	Fmspc       string    `json:"-"`
	Manifest    string    `json:"-"`
	CreatedTime time.Time `json:"-"`
	UpdatedTime time.Time `json:"-"`
}

type Platforms []Platform
