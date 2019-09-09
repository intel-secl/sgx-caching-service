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

type PostgresFmspcTcbInfoRepository struct {
	db *gorm.DB
}

func (r *PostgresFmspcTcbInfoRepository) Create(u types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {

	err := r.db.Create(&u).Error
	return &u, err
}

func (r *PostgresFmspcTcbInfoRepository) Retrieve(u types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
	err := r.db.Where(&u).First(&u).Error
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *PostgresFmspcTcbInfoRepository) RetrieveAll(u types.FmspcTcbInfo) (types.FmspcTcbInfos, error) {
	var users types.FmspcTcbInfos
	err := r.db.Where(&u).Find(&users).Error
	if err != nil {
		return nil, err
	}

	log.WithField("db users", users).Trace("RetrieveAll")
	return users, err
}

func (r *PostgresFmspcTcbInfoRepository) Update(u types.FmspcTcbInfo) error {
	return r.db.Save(&u).Error
}

func (r *PostgresFmspcTcbInfoRepository) Delete(u types.FmspcTcbInfo) error {
	return r.db.Delete(&u).Error
}

