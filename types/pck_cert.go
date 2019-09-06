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

// PckCert struct is the database schema of a PckCerts table
type PckCert struct {
	QeId 		string     `json:"-" gorm:"primary_key"`
	PceId       	string     `json:"-" gorm:"primary_key"`
	Tcbm      	string     `json:"-"` //removed primary key
	Fmspc      	string     `json:"-"`
	PckCert     	[]byte	   `json:"-" gorm:"type:bytea;not null`
	CertChainId   	uint 	   `json:"cert_chain_id" gorm:"type:int;not null"`
 	CreatedTime    time.Time  
	UpdatedTime    time.Time  
}

type PckCerts []PckCert

