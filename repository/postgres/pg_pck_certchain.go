/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/scs/types"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresPckCertChainRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCertChainRepository) Create(certchain types.PckCertChain) (*types.PckCertChain, error) {
	log.Trace("repository/postgres/pg_pck_certchain.go: Create() Entering")
	defer log.Trace("repository/postgres/pg_pck_certchain.go: Create() Leaving")

	err := r.db.Create(&certchain).Error
	return &certchain, errors.Wrap(err, "create: Failed to create PckCertChain")
}

func (r *PostgresPckCertChainRepository) Retrieve(certchain types.PckCertChain) (*types.PckCertChain, error) {
	log.Trace("repository/postgres/pg_pck_certchain.go: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_pck_certchain.go: Retrieve() Leaving")

	err := r.db.Where(&certchain).First(&certchain).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: Failed to Retrive PckCertChain")
	}
	return &certchain, nil
}

func (r *PostgresPckCertChainRepository) RetrieveAll(certchain types.PckCertChain) (types.PckCertChains, error) {
	log.Trace("repository/postgres/pg_pck_certchain.go: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_pck_certchain.go: RetrieveAll() Leaving")

	var certchains types.PckCertChains
	err := r.db.Where(&certchain).Find(&certchains).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: Failed to RetriveAll PckCertChain")
	}

	log.WithField("db users", certchains).Trace("RetrieveAll")
	return certchains, errors.Wrap(err, "RetrieveAll: Failed to RetriveAll PckCertChain")
}

func (r *PostgresPckCertChainRepository) Update(certchain types.PckCertChain) error {
	log.Trace("repository/postgres/pg_pck_certchain.go: Update() Entering")
	defer log.Trace("repository/postgres/pg_pck_certchain.go: Update() Leaving")

	if err := r.db.Save(&certchain).Error; err != nil {
		return errors.Wrap(err, "Update: Failed to Update PckCertChain")
	}
	return nil
}

func (r *PostgresPckCertChainRepository) Delete(certchain types.PckCertChain) error {
	log.Trace("repository/postgres/pg_pck_certchain.go: Delete() Entering")
	defer log.Trace("repository/postgres/pg_pck_certchain.go: Delete() Leaving")

	if err := r.db.Model(&certchain).Association("PckCert").Clear().Error; err != nil {
		return errors.Wrap(err, "Delete: Failed to Delete PckCertChain")
	}
	return nil
}

