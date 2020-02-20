/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/sgx-caching-service/types"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresQEIdentityRepository struct {
	db *gorm.DB
}

func (r *PostgresQEIdentityRepository) Create(u types.QEIdentity) (*types.QEIdentity, error) {
        log.Trace("repository/postgres/pg_qe_identity: Create() Entering")
        defer log.Trace("repository/postgres/pg_qe_identity: Create() Leaving")


	err := r.db.Create(&u).Error
	return &u, errors.Wrap(err, "Create: failed to create qeIdentity")
}

func (r *PostgresQEIdentityRepository) Retrieve(u types.QEIdentity) (*types.QEIdentity, error) {
        log.Trace("repository/postgres/pg_qe_identity: Retrieve() Entering")
        defer log.Trace("repository/postgres/pg_qe_identity: Retrieve() Leaving")

	err := r.db.Where(&u).First(&u).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve qeIdentity")
	}
	return &u, nil
}

func (r *PostgresQEIdentityRepository) RetrieveAll() (types.QEIdentities, error) {
        log.Trace("repository/postgres/pg_qe_identity: RetrieveAll() Entering")
        defer log.Trace("repository/postgres/pg_qe_identity: RetrieveAll() Leaving")

	var qes types.QEIdentities
	err := r.db.Find(&qes).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all qeIdentity")
	}

	log.WithField("db qes", qes).Trace("RetrieveAll")
	return qes, errors.Wrap(err, "RetrieveAll: failed to retrieve all qeIdentity")
}

func (r *PostgresQEIdentityRepository) Update(u types.QEIdentity) error {
        log.Trace("repository/postgres/pg_qe_identity: Update() Entering")
        defer log.Trace("repository/postgres/pg_qe_identity: Update() Leaving")

	if err := r.db.Update(&u).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update qeIdentity")
	}
	return nil
}

func (r *PostgresQEIdentityRepository) Delete(u types.QEIdentity) error {
        log.Trace("repository/postgres/pg_qe_identity: Delete() Entering")
        defer log.Trace("repository/postgres/pg_qe_identity: Delete() Leaving")

	if err := r.db.Delete(&u).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to Delete qeIdentity")
	}
	return nil
}
