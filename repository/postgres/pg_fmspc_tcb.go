/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"intel/isecl/scs/v5/types"
)

type PostgresFmspcTcbInfoRepository struct {
	db *gorm.DB
}

func (r *PostgresFmspcTcbInfoRepository) Create(tcb *types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
	err := r.db.Create(tcb).Error
	if err != nil {
		return nil, errors.Wrap(err, "create: failed to create a record in fmspctcb table")
	}
	return tcb, nil
}

func (r *PostgresFmspcTcbInfoRepository) Retrieve(tcb *types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
	err := r.db.Where(tcb).First(&tcb).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrive a record from fmspctcb table")
	}
	return tcb, nil
}

func (r *PostgresFmspcTcbInfoRepository) RetrieveAll() (types.FmspcTcbInfos, error) {
	var tcbs types.FmspcTcbInfos
	err := r.db.Find(&tcbs).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all fmspctcb records")
	}
	return tcbs, nil
}

func (r *PostgresFmspcTcbInfoRepository) Update(tcb *types.FmspcTcbInfo) error {
	db := r.db.Model(tcb).Updates(tcb)
	if db.Error != nil {
		return errors.Wrap(db.Error, "Update: failed to update a record in fmspctcb table")
	} else if db.RowsAffected != 1 {
		return errors.New("Update: - no rows affected")
	}
	return nil
}

func (r *PostgresFmspcTcbInfoRepository) Delete(tcb *types.FmspcTcbInfo) error {
	if err := r.db.Delete(tcb).Error; err != nil {
		return errors.Wrap(err, "delete: failed to delete a record fmspctcb table")
	}
	return nil
}
