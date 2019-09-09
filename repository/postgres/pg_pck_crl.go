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

type PostgresPckCrlRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCrlRepository) Create(crl types.PckCrl) (*types.PckCrl, error) {

	err := r.db.Create(&crl).Error
	return &crl, err
}

func (r *PostgresPckCrlRepository) Retrieve(crl types.PckCrl) (*types.PckCrl, error) {
	err := r.db.Where(&crl).First(&crl).Error
	if err != nil {
		return nil, err
	}
	return &crl, nil
}

func (r *PostgresPckCrlRepository) RetrieveAll(crl types.PckCrl) (types.PckCrls, error) {
	var crls types.PckCrls
	err := r.db.Where(&crl).Find(&crls).Error
	if err != nil {
		return nil, err
	}

	log.WithField("db crl", crl).Trace("RetrieveAll")
	return crls, err
}

func (r *PostgresPckCrlRepository) Update(crl types.PckCrl) error {
	return r.db.Save(&crl).Error
}

func (r *PostgresPckCrlRepository) Delete(crl types.PckCrl) error {
	return r.db.Delete(&crl).Error
}

