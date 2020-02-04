/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types
import (
        "time"
)

// PlatformTcb struct is the database schema of a PlatformTcbs table
type PlatformTcb struct {
	QeId 		string     `json:"-" gorm:"primary_key"`
	PceId       	string     `json:"-"`
	CpuSvn      	string     `json:"-"`
	PceSvn      	string     `json:"-"`
	Encppid     	string	   `json:"-"`   
	CreatedTime    time.Time  `json:"-"`
	UpdatedTime    time.Time  `json:"-"`
}

type PlatformTcbs []PlatformTcb
