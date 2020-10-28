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

type PostgresFmspcTcbInfoRepository struct {
	db *gorm.DB
}

func (r *PostgresFmspcTcbInfoRepository) Create(tcb types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
	err := r.db.Create(&tcb).Error
	return &tcb, errors.Wrap(err, "create: failed to create fmspcTcbInfo")
}

func (r *PostgresFmspcTcbInfoRepository) Retrieve(tcb types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
	err := r.db.Where(&tcb).First(&tcb).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrive fmspcTcbInfo")
	}
	return &tcb, nil
}

func (r *PostgresFmspcTcbInfoRepository) RetrieveAll(tcb types.FmspcTcbInfo) (types.FmspcTcbInfos, error) {
	var tcbs types.FmspcTcbInfos
	err := r.db.Where(&tcb).Find(&tcbs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all fmspcTcbInfo")
	}

	log.WithField("db Fmspc", tcbs).Trace("RetrieveAll")
	return tcbs, errors.Wrap(err, "RetrieveAll: failed to retrieve all fmspcTcbInfo")
}

func (r *PostgresFmspcTcbInfoRepository) RetrieveAllFmspcTcbInfos() (types.FmspcTcbInfos, error) {
	var tcbs types.FmspcTcbInfos
	err := r.db.Find(&tcbs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAllFmspcTcbInfos: failed to retrieveAllFmspcTcbInfos")
	}

	log.WithField("db Tcbs", tcbs).Trace("RetrieveAll")
	return tcbs, errors.Wrap(err, "RetrieveAllFmspcTcbInfos: failed to retrieveAllFmspcTcbInfos")
}

func (r *PostgresFmspcTcbInfoRepository) Update(tcb types.FmspcTcbInfo) error {
	if err := r.db.Save(&tcb).Error; err != nil {
		return errors.Wrap(err, "update: failed to update fmspcTcbInfo")
	}
	return nil
}

func (r *PostgresFmspcTcbInfoRepository) Delete(tcb types.FmspcTcbInfo) error {
	if err := r.db.Delete(&tcb).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to Delete fmspcTcbInfo")
	}
	return nil
}
