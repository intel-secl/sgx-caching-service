/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	//"fmt"
	//"intel/isecl/sgx-caching-service/repository"

	"intel/isecl/sgx-caching-service/types"

	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
)

type PostgresQEIdentityRepository struct {
	db *gorm.DB
}

func (r *PostgresQEIdentityRepository) Create(u types.QEIdentity) (*types.QEIdentity, error) {

	err := r.db.Create(&u).Error
	return &u, err
}

func (r *PostgresQEIdentityRepository) Retrieve(u types.QEIdentity) (*types.QEIdentity, error) {
	err := r.db.Where(&u).First(&u).Error
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *PostgresQEIdentityRepository) RetrieveAll() (types.QEIdentities, error) {
	var qes types.QEIdentities
	err := r.db.Find(&qes).Error
	if err != nil {
		return nil, err
	}

	log.WithField("db qes", qes).Trace("RetrieveAll")
	return qes, err
}

func (r *PostgresQEIdentityRepository) Update(u types.QEIdentity) error {
	return r.db.Save(&u).Error
}

func (r *PostgresQEIdentityRepository) Delete(u types.QEIdentity) error {
	if err := r.db.Model(&u).Association("Roles").Clear().Error; err != nil {
		return err
	}
	return r.db.Delete(&u).Error
}

