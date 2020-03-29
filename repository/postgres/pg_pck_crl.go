/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/scs/types"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresPckCrlRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCrlRepository) Create(crl types.PckCrl) (*types.PckCrl, error) {
	err := r.db.Create(&crl).Error
	return &crl, errors.Wrap(err, "create: Failed to create PckCrl")
}

func (r *PostgresPckCrlRepository) Retrieve(crl types.PckCrl) (*types.PckCrl, error) {
	err := r.db.Where(&crl).First(&crl).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: Failed to Retrieve PckCrl")
	}
	return &crl, nil
}

func (r *PostgresPckCrlRepository) RetrieveAll(crl types.PckCrl) (types.PckCrls, error) {
	var crls types.PckCrls
	err := r.db.Where(&crl).Find(&crls).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: Failed to RetrieveAll PckCrl")
	}

	log.WithField("db crl", crl).Trace("RetrieveAll")
	return crls, errors.Wrap(err, "RetrieveAll: Failed to RetrieveAll PckCrl")
}

func (r *PostgresPckCrlRepository) RetrieveAllPckCrls() (types.PckCrls, error) {
	var crls types.PckCrls
        err := r.db.Find(&crls).Error
        if err != nil {
                return nil, errors.Wrap(err, "RetrieveAllPckCrls: Failed to RetrieveAllPckCrls")
        }

        log.WithField("DB Crls", crls).Trace("RetrieveAllPckCrls")
        return crls, errors.Wrap(err, "RetrieveAllPckCrls: Failed to RetrieveAllPckCrls")
}

func (r *PostgresPckCrlRepository) Update(crl types.PckCrl) error {
	if err := r.db.Save(&crl).Error; err != nil {
		return errors.Wrap(err, "Update: Failed to Update PckCrl")
	}
	return nil
}

func (r *PostgresPckCrlRepository) Delete(crl types.PckCrl) error {
	if err := r.db.Delete(&crl).Error; err != nil {
		return errors.Wrap(err, "Delete: Failed to Delete PckCrl")
	}
	return nil
}
