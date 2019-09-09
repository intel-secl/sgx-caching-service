/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/sgx-caching-service/types"

	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
)

type PostgresPlatformTcbRepository struct {
	db *gorm.DB
	
}

func (r *PostgresPlatformTcbRepository) Create(p types.PlatformTcb) (*types.PlatformTcb, error) {

	err := r.db.Create(&p).Error
	return &p, err
}

func (r *PostgresPlatformTcbRepository) Retrieve(p types.PlatformTcb) (*types.PlatformTcb, error) {
	log.WithField("PlatformTcb", p).Debug("Retrieve Call")
	err := r.db.Where(&p).First(&p).Error
	if err != nil {
		return nil, err
	}
	return &p, nil
}

/*
func (r *PostgresPlatformTcbRepository)  RetriveCachedPlatormInfo(p types.PlatformTcb)(*types.PlatformTcb, *types.PckCert, *types.PckCertChain, error) {
	var count int
	pinto, err := Retrieve(p)
	if err != nil {
		return nil,nil, nil, err
	}
	return nil,nil,nil,err
}*/

func (r *PostgresPlatformTcbRepository) RetrieveAll(u types.PlatformTcb) (types.PlatformTcbs, error) {
	var platforminfo types.PlatformTcbs
	err := r.db.Where(&u).Find(&platforminfo).Error
	if err != nil {
		return nil, err
	}

	log.WithField("db platforminfo", platforminfo).Trace("RetrieveAll")
	return platforminfo, err
}

func (r *PostgresPlatformTcbRepository) Update(u types.PlatformTcb) error {
	return r.db.Save(&u).Error
}

func (r *PostgresPlatformTcbRepository) Delete(u types.PlatformTcb) error {
	return r.db.Delete(&u).Error
}

