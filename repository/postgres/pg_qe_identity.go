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
	if err := r.db.Save(qe).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update record in qe_identities table")
	}
	return nil
}

func (r *PostgresQEIdentityRepository) Delete(qe *types.QEIdentity) error {
	if err := r.db.Delete(qe).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete a record from qe_identities table")
	}
	return nil
}
