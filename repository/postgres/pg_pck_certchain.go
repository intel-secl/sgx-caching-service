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

type PostgresPckCertChainRepository struct {
	db *gorm.DB
}

func (r *PostgresPckCertChainRepository) Create(u types.PckCertChain) (*types.PckCertChain, error) {

	err := r.db.Create(&u).Error
	return &u, err
}

func (r *PostgresPckCertChainRepository) Retrieve(u types.PckCertChain) (*types.PckCertChain, error) {
	err := r.db.Where(&u).First(&u).Error
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *PostgresPckCertChainRepository) RetrieveAll(u types.PckCertChain) (types.PckCertChains, error) {
	var users types.PckCertChains
	err := r.db.Where(&u).Find(&users).Error
	if err != nil {
		return nil, err
	}

	log.WithField("db users", users).Trace("RetrieveAll")
	return users, err
}

func (r *PostgresPckCertChainRepository) Update(u types.PckCertChain) error {
	return r.db.Save(&u).Error
}

func (r *PostgresPckCertChainRepository) Delete(u types.PckCertChain) error {
	if err := r.db.Model(&u).Association("Roles").Clear().Error; err != nil {
		return err
	}
	return r.db.Delete(&u).Error
}

