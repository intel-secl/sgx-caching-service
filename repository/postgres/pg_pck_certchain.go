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

type PostgresPckCertChainRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCertChainRepository) Create(certchain types.PckCertChain) (*types.PckCertChain, error) {

	err := r.db.Create(&certchain).Error
	return &certchain, err
}

func (r *PostgresPckCertChainRepository) Retrieve(certchain types.PckCertChain) (*types.PckCertChain, error) {
	err := r.db.Where(&certchain).First(&certchain).Error
	if err != nil {
		return nil, err
	}
	return &certchain, nil
}

func (r *PostgresPckCertChainRepository) RetrieveAll(certchain types.PckCertChain) (types.PckCertChains, error) {
	var certchains types.PckCertChains
	err := r.db.Where(&certchain).Find(&certchains).Error
	if err != nil {
		return nil, err
	}

	log.WithField("db users", certchains).Trace("RetrieveAll")
	return certchains, err
}

func (r *PostgresPckCertChainRepository) Update(certchain types.PckCertChain) error {
	return r.db.Save(&certchain).Error
}

func (r *PostgresPckCertChainRepository) Delete(certchain types.PckCertChain) error {
	if err := r.db.Model(&certchain).Association("PckCert").Clear().Error; err != nil {
		return err
	}
	return r.db.Delete(&certchain).Error
}

