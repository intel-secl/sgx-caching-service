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

type PostgresFmspcTcbInfoRepository struct {
	db *gorm.DB
}

func (r *PostgresFmspcTcbInfoRepository) Create(tcb types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
        log.Trace("repository/postgres/pg_fmspc_tcb: Create() Entering")
        defer log.Trace("repository/postgres/pg_fmspc_tcb: Create() Leaving")

	err := r.db.Create(&tcb ).Error
	return &tcb, errors.Wrap(err, "create: failed to create fmspcTcbInfo")
}

func (r *PostgresFmspcTcbInfoRepository) Retrieve(tcb types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
        log.Trace("repository/postgres/pg_fmspc_tcb: Retrieve() Entering")
        defer log.Trace("repository/postgres/pg_fmspc_tcb: Retrieve() Leaving")

	err := r.db.Where(&tcb ).First(&tcb ).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrive fmspcTcbInfo")
	}
	return &tcb, nil
}

func (r *PostgresFmspcTcbInfoRepository) RetrieveAll(tcb types.FmspcTcbInfo) (types.FmspcTcbInfos, error) {
        log.Trace("repository/postgres/pg_fmspc_tcb: RetrieveAll() Entering")
        defer log.Trace("repository/postgres/pg_fmspc_tcb: RetrieveAll() Leaving")

	var tcbs types.FmspcTcbInfos
	err := r.db.Where(&tcb).Find(&tcbs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all fmspcTcbInfo")
	}

	log.WithField("db Fmspc", tcbs).Trace("RetrieveAll")
	return tcbs, errors.Wrap(err, "RetrieveAll: failed to retrieve all fmspcTcbInfo")
}

func (r *PostgresFmspcTcbInfoRepository) RetrieveAllFmspcTcbInfos() (types.FmspcTcbInfos, error) {
        log.Trace("repository/postgres/pg_fmspc_tcb: RetrieveAllFmspcTcbInfos() Entering")
        defer log.Trace("repository/postgres/pg_fmspc_tcb: RetrieveAllFmspcTcbInfos() Leaving")

	var tcbs types.FmspcTcbInfos
	err := r.db.Find(&tcbs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAllFmspcTcbInfos: failed to retrieveAllFmspcTcbInfos")
	}

	log.WithField("db Tcbs", tcbs).Trace("RetrieveAll")
	return tcbs, errors.Wrap(err, "RetrieveAllFmspcTcbInfos: failed to retrieveAllFmspcTcbInfos")
}

func (r *PostgresFmspcTcbInfoRepository) Update(tcb types.FmspcTcbInfo) error {
        log.Trace("repository/postgres/pg_fmspc_tcb: Update() Entering")
        defer log.Trace("repository/postgres/pg_fmspc_tcb: Update() Leaving")

	if err := r.db.Save(&tcb).Error; err != nil {
		return errors.Wrap(err, "update: failed to update fmspcTcbInfo")
	}
	return nil
}

func (r *PostgresFmspcTcbInfoRepository) Delete(tcb types.FmspcTcbInfo) error {
        log.Trace("repository/postgres/pg_fmspc_tcb: Delete() Entering")
        defer log.Trace("repository/postgres/pg_fmspc_tcb: Delete() Leaving")

	if err := r.db.Delete(&tcb ).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to Delete fmspcTcbInfo")
	}
	return nil
}
