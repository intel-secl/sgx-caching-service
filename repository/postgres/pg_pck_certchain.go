/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"intel/isecl/scs/v3/types"
)

type PostgresPckCertChainRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCertChainRepository) Create(certchain types.PckCertChain) (*types.PckCertChain, error) {
	err := r.db.Create(&certchain).Error
	return &certchain, errors.Wrap(err, "create: Failed to create PckCertChain")
}

func (r *PostgresPckCertChainRepository) Retrieve(certchain types.PckCertChain) (*types.PckCertChain, error) {
	err := r.db.Where(&certchain).First(&certchain).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: Failed to Retrive PckCertChain")
	}
	return &certchain, nil
}

func (r *PostgresPckCertChainRepository) RetrieveAll(certchain types.PckCertChain) (types.PckCertChains, error) {
	var certchains types.PckCertChains
	err := r.db.Where(&certchain).Find(&certchains).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: Failed to RetriveAll PckCertChain")
	}

	log.WithField("db users", certchains).Trace("RetrieveAll")
	return certchains, errors.Wrap(err, "RetrieveAll: Failed to RetriveAll PckCertChain")
}

func (r *PostgresPckCertChainRepository) Update(certchain types.PckCertChain) error {
	if err := r.db.Save(&certchain).Error; err != nil {
		return errors.Wrap(err, "Update: Failed to Update PckCertChain")
	}
	return nil
}

func (r *PostgresPckCertChainRepository) Delete(certchain types.PckCertChain) error {
	if err := r.db.Model(&certchain).Association("PckCert").Clear().Error; err != nil {
		return errors.Wrap(err, "Delete: Failed to Delete PckCertChain")
	}
	return nil
}
