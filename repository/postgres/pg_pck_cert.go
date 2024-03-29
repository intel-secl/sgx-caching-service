/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/scs/v5/types"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresPckCertRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCertRepository) Create(u *types.PckCert) (*types.PckCert, error) {
	err := r.db.Create(u).Error
	if err != nil {
		return nil, errors.Wrap(err, "Create: failed to create a record in pck_certs table")
	}
	return u, nil
}

func (r *PostgresPckCertRepository) Retrieve(pckcert *types.PckCert) (*types.PckCert, error) {
	err := r.db.Where(pckcert).First(pckcert).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve a record from pck_certs table")
	}
	return pckcert, nil
}

func (r *PostgresPckCertRepository) RetrieveAll() (types.PckCerts, error) {
	var pckcerts types.PckCerts
	err := r.db.Find(&pckcerts).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all records from pck_certs table")
	}

	return pckcerts, nil
}

func (r *PostgresPckCertRepository) Update(p *types.PckCert) error {
	db := r.db.Model(p).Updates(p)
	if db.Error != nil {
		return errors.Wrap(db.Error, "Update: failed to update a record in pck_certs table")
	} else if db.RowsAffected != 1 {
		return errors.New("Update: - no rows affected")
	}
	return nil
}

func (r *PostgresPckCertRepository) Delete(p *types.PckCert) error {
	if err := r.db.Delete(p).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete a record from pck_certs table")
	}
	return nil
}
