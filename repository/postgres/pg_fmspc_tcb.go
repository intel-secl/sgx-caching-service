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

func (r *PostgresFmspcTcbInfoRepository) Create(tcb types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {

	err := r.db.Create(&tcb ).Error
	return &tcb , err
}

func (r *PostgresFmspcTcbInfoRepository) Retrieve(tcb types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
	err := r.db.Where(&tcb ).First(&tcb ).Error
	if err != nil {
		return nil, err
	}
	return &tcb , nil
}

func (r *PostgresFmspcTcbInfoRepository) RetrieveAll(tcb types.FmspcTcbInfo) (types.FmspcTcbInfos, error) {
	var tcbs types.FmspcTcbInfos
	err := r.db.Where(&tcb).Find(&tcbs).Error
	if err != nil {
		return nil, err
	}

	log.WithField("db Fmspc", tcbs).Trace("RetrieveAll")
	return tcbs, err
}

func (r *PostgresFmspcTcbInfoRepository) RetrieveAllFmspcTcbInfos() (types.FmspcTcbInfos, error) {
	var tcbs types.FmspcTcbInfos
	err := r.db.Find(&tcbs).Error
	if err != nil {
		return nil, err
	}

	log.WithField("db Tcbs", tcbs).Trace("RetrieveAll")
	return tcbs, err
}

func (r *PostgresFmspcTcbInfoRepository) Update(tcb types.FmspcTcbInfo) error {
	return r.db.Save(&tcb ).Error
}

func (r *PostgresFmspcTcbInfoRepository) Delete(tcb types.FmspcTcbInfo) error {
	return r.db.Delete(&tcb ).Error
}

