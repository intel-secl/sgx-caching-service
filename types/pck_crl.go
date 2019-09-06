/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types
import (
        "time"
)

// PckCrl struct is the database schema of a PckCrl table
type PckCrl struct {
	Ca 	 	string     `json:"-" gorm:"primary_key"`
	PckCrlCertChain []byte	   `json:"-" gorm:"type:bytea;not null;unique"`
	PckCrl    	[]byte	   `json:"-" gorm:"type:bytea;not null;unique"`
	CreatedTime    	time.Time  
	UpdatedTime    	time.Time  
}

type PckCrls []PckCrl

