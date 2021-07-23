/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/scs/v5/types"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresPlatformTcbRepository struct {
	db *gorm.DB
}

func (r *PostgresPlatformTcbRepository) Create(p *types.PlatformTcb) (*types.PlatformTcb, error) {
	err := r.db.Create(p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Create: failed to create a record in platform_tcbs table")
	}
	return p, nil
}

func (r *PostgresPlatformTcbRepository) Retrieve(p *types.PlatformTcb) (*types.PlatformTcb, error) {
	err := r.db.Where(p).First(p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve a record from platform_tcbs table")
	}
	return p, nil
}

func (r *PostgresPlatformTcbRepository) RetrieveAll() (types.PlatformTcbs, error) {
	var p types.PlatformTcbs
	err := r.db.Find(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all records from platform_tcbs table")
	}

	return p, nil
}

func (r *PostgresPlatformTcbRepository) Update(p *types.PlatformTcb) error {
	db := r.db.Model(p).Updates(p)
	if db.Error != nil {
		return errors.Wrap(db.Error, "Update: failed to update a record in platform_tcbs table")
	} else if db.RowsAffected != 1 {
		return errors.New("Update: - no rows affected")
	}
	return nil
}

func (r *PostgresPlatformTcbRepository) Delete(p *types.PlatformTcb) error {
	if err := r.db.Delete(p).Error; err != nil {
		return errors.Wrap(err, "Delete: failed to delete a record in platform_tcbs table")
	}
	return nil
}
