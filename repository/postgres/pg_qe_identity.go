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

type PostgresQEIdentityRepository struct {
	db *gorm.DB
}

func (r *PostgresQEIdentityRepository) Create(qe *types.QEIdentity) (*types.QEIdentity, error) {
	err := r.db.Create(qe).Error
	if err != nil {
		return nil, errors.Wrap(err, "Create: failed to create a record in qe_identities table")
	}
	return qe, nil
}

func (r *PostgresQEIdentityRepository) Retrieve() (*types.QEIdentity, error) {
	var qe types.QEIdentity
	err := r.db.First(&qe).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve record from qe_identities table")
	}
	return &qe, nil
}

func (r *PostgresQEIdentityRepository) Update(qe *types.QEIdentity) error {
	db := r.db.Model(qe).Updates(qe)
	if db.Error != nil {
		return errors.Wrap(db.Error, "Update: failed to update qe identity info")
	} else if db.RowsAffected != 1 {
		return errors.New("Update: - no rows affected")
	}
	return nil
}

func (r *PostgresQEIdentityRepository) Delete(qe *types.QEIdentity) error {
	if err := r.db.Delete(qe).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete a record from qe_identities table")
	}
	return nil
}
