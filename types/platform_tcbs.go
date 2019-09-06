/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types
import (
        "time"
)

/*import (
	"bytes"
	"fmt"
        "time"

	"intel/isecl/sgx-caching-service/constants"
	"intel/isecl/lib/common/crypt"

	"golang.org/x/crypto/bcrypt"
)*/

// PlatformTcb struct is the database schema of a PlatformTcbs table
type PlatformTcb struct {
	QeId 		string     `json:"-" gorm:"primary_key"`
	PceId       	string     `json:"-" gorm:"primary_key"`
	CpuSvn      	string     `json:"-" gorm:"primary_key"`
	PceSvn      	string     `json:"-" gorm:"primary_key"`
	Encppid     	string	   `json:"-"`   
	CreatedTime    time.Time  `json:"-"`
	UpdatedTime    time.Time  `json:"-"`
}

type PlatformTcbs []PlatformTcb

