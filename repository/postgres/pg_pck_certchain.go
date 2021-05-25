/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"intel/isecl/scs/v4/types"
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

func (r *PostgresPckCertChainRepository) Retrieve(pcc *types.PckCertChain) (*types.PckCertChain, error) {
	err := r.db.Where(pcc).First(pcc).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve record from pck_cert_chains table")
	}
	return pcc, nil
}

func (r *PostgresPckCertChainRepository) Update(pcc *types.PckCertChain) error {
	db := r.db.Model(pcc).Updates(pcc)
	if db.Error != nil {
		return errors.Wrap(db.Error, "Update: failed to update a record in pck_cert_chains table")
	} else if db.RowsAffected != 1 {
		return errors.New("Update: - no rows affected")
	}
	return nil
}

func (r *PostgresPckCertChainRepository) Delete(pcc *types.PckCertChain) error {
	if err := r.db.Delete(pcc).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete a record from pck_cert_chains table")
	}
	return nil
}
