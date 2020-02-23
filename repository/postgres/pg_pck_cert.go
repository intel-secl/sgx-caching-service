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

type PostgresPckCertRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCertRepository) Create(u types.PckCert) (*types.PckCert, error) {
	log.Trace("repository/postgres/pg_pck_cert: Create() Entering")
	defer log.Trace("repository/postgres/pg_pck_cert: Create() Leaving")

	err := r.db.Create(&u).Error
	return &u, errors.Wrap(err, "Create: failed to create PckCert record")
}

func (r *PostgresPckCertRepository) Retrieve(pckcert types.PckCert) (*types.PckCert, error) {
	log.Trace("repository/postgres/pg_pck_cert: Retrieve() Entering")
	defer log.Trace("repository/postgres/pg_pck_cert: Retrieve() Leaving")

	var p types.PckCert
	log.WithField("PckCert", pckcert).Debug("Retrieve Call")
	err := r.db.Where("qe_id = ? AND pce_id = ?",pckcert.QeId, pckcert.PceId).First(&p).Error
	if err != nil {
		log.Trace("Error in fetch records Entering")
		return nil, errors.Wrap(err, "Retrieve: failed to Retrieve PckCert record")
	}
	return &p, nil
}

func (r *PostgresPckCertRepository) RetrieveAll(u types.PckCert) (types.PckCerts, error) {
	log.Trace("repository/postgres/pg_pck_cert: RetrieveAll() Entering")
	defer log.Trace("repository/postgres/pg_pck_cert: RetrieveAll() Leaving")

	var pckcerts types.PckCerts
	err := r.db.Where(&u).Find(&pckcerts).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to Retrieve All PckCert records")
	}

	log.WithField("db pckcerts", pckcerts).Trace("RetrieveAll")
	return pckcerts, errors.Wrap(err, "RetrieveAll: failed to Retrieve All PckCert records")
}

func (r *PostgresPckCertRepository) Update(u types.PckCert) error {
	log.Trace("repository/postgres/pg_pck_cert: Update() Entering")
	defer log.Trace("repository/postgres/pg_pck_cert: Update() Leaving")

	if err := r.db.Save(&u).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update PckCert record")
	}
	return nil
}

func (r *PostgresPckCertRepository) Delete(u types.PckCert) error {
	log.Trace("repository/postgres/pg_pck_cert: Delete() Entering")
	defer log.Trace("repository/postgres/pg_pck_cert: Delete() Leaving")

	if err := r.db.Delete(&u).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete PckCert record")
	}
	return nil
}
