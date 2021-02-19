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

func (r *PostgresPckCertChainRepository) Create(pcc *types.PckCertChain) (*types.PckCertChain, error) {
	err := r.db.Create(pcc).Error
	if err != nil {
		return nil, errors.Wrap(err, "Create: failed to create a record in pck_cert_chains table")
	}
	return pcc, nil
}

func (r *PostgresPckCertChainRepository) Retrieve() (*types.PckCertChain, error) {
	var pcc types.PckCertChain
	err := r.db.Find(&pcc).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve record from pck_cert_chains table")
	}
	return &pcc, nil
}

func (r *PostgresPckCertChainRepository) Update(pcc *types.PckCertChain) error {
	if err := r.db.Save(pcc).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update record in pck_cert_chains table")
	}
	return nil
}

func (r *PostgresPckCertChainRepository) Delete(pcc *types.PckCertChain) error {
	if err := r.db.Delete(pcc).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete a record from pck_cert_chains table")
	}
	return nil
}
