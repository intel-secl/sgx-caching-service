/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/sgx-caching-service/types"
	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
)

type PostgresPckCertRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCertRepository) Create(u types.PckCert) (*types.PckCert, error) {
	err := r.db.Create(&u).Error
	return &u, err
}

func (r *PostgresPckCertRepository) Retrieve(pckcert types.PckCert) (*types.PckCert, error) {
	log.WithField("PckCert", pckcert).Debug("Retrieve Call")
	err := r.db.Where("qe_id = ? AND pce_id >= ?",pckcert.QeId, pckcert.PceId).First(&pckcert).Error
	if err != nil {
		return nil, err
	}
	return &pckcert, nil
}

func (r *PostgresPckCertRepository) RetrieveAll(u types.PckCert) (types.PckCerts, error) {
	var pckcerts types.PckCerts
	err := r.db.Where(&u).Find(&pckcerts).Error
	if err != nil {
		return nil, err
	}

	log.WithField("db pckcerts", pckcerts).Trace("RetrieveAll")
	return pckcerts, err
}

func (r *PostgresPckCertRepository) Update(u types.PckCert) error {
	return r.db.Save(&u).Error
}

func (r *PostgresPckCertRepository) Delete(u types.PckCert) error {
	return r.db.Delete(&u).Error
}

