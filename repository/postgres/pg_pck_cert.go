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

type PostgresPckCertRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCertRepository) Create(u types.PckCert) (*types.PckCert, error) {
	err := r.db.Create(&u).Error
	return &u, errors.Wrap(err, "Create: failed to create PckCert record")
}

func (r *PostgresPckCertRepository) Retrieve(pckcert types.PckCert) (*types.PckCert, error) {
	var p types.PckCert
	log.WithField("PckCert", pckcert).Debug("Retrieve Call")
	err := r.db.Where("qe_id = ?", pckcert.QeId).First(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to Retrieve PckCert record")
	}
	return &p, nil
}

func (r *PostgresPckCertRepository) RetrieveAll(u types.PckCert) (types.PckCerts, error) {
	var pckcerts types.PckCerts
	err := r.db.Where(&u).Find(&pckcerts).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to Retrieve All PckCert records")
	}

	log.WithField("db pckcerts", pckcerts).Trace("RetrieveAll")
	return pckcerts, errors.Wrap(err, "RetrieveAll: failed to Retrieve All PckCert records")
}

func (r *PostgresPckCertRepository) Update(u types.PckCert) error {
	if err := r.db.Save(&u).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update PckCert record")
	}
	return nil
}

func (r *PostgresPckCertRepository) Delete(u types.PckCert) error {
	if err := r.db.Delete(&u).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete PckCert record")
	}
	return nil
}
