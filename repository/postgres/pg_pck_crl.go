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

type PostgresPckCrlRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCrlRepository) Create(crl *types.PckCrl) (*types.PckCrl, error) {
	err := r.db.Create(crl).Error
	if err != nil {
		return nil, errors.Wrap(err, "Create: failed to create a record in pckcrl table")
	}
	return crl, nil
}

func (r *PostgresPckCrlRepository) Retrieve(crl *types.PckCrl) (*types.PckCrl, error) {
	err := r.db.Where(crl).First(&crl).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve a record from pckcrl table")
	}
	return crl, nil
}

func (r *PostgresPckCrlRepository) RetrieveAll() (types.PckCrls, error) {
	var crls types.PckCrls
	err := r.db.Find(&crls).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all records from pckcrl table")
	}
	return crls, nil
}

func (r *PostgresPckCrlRepository) Update(crl *types.PckCrl) error {
	if err := r.db.Save(crl).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update a record in pckcrl table")
	}
	return nil
}

func (r *PostgresPckCrlRepository) Delete(crl *types.PckCrl) error {
	if err := r.db.Delete(crl).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete a record in pckcrl table")
	}
	return nil
}
