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
	QeID        string    `json:"-" gorm:"primary_key"`
	PceID       string    `json:"-"`
	CPUSvn      string    `json:"-"`
	PceSvn      string    `json:"-"`
	Encppid     string    `json:"-"`
	Fmspc       string    `json:"-"`
	Manifest    string    `json:"-"`
	CreatedTime time.Time `json:"-"`
	UpdatedTime time.Time `json:"-"`
}

type Platforms []Platform
