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

type PostgresPlatformRepository struct {
	db *gorm.DB
}

func (r *PostgresPlatformRepository) Create(p *types.Platform) (*types.Platform, error) {
	err := r.db.Create(p).Error
	if err != nil {
		return nil, errors.Wrap(err, "create: failed to create a record in platform table")
	}
	return p, nil
}

func (r *PostgresPlatformRepository) Retrieve(p *types.Platform) (*types.Platform, error) {
	err := r.db.Where(p).First(p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve a record from platform table")
	}
	return p, nil
}

func (r *PostgresPlatformRepository) RetrieveAll() (types.Platforms, error) {
	var p types.Platforms
	err := r.db.Find(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all records from platform table")
	}
	return p, nil
}

func (r *PostgresPlatformRepository) Update(p *types.Platform) error {
	db := r.db.Model(p).Updates(p)
	if db.Error != nil {
		return errors.Wrap(db.Error, "Update: failed to update a record in platforms table")
	} else if db.RowsAffected != 1 {
		return errors.New("Update: - no rows affected")
	}
	return nil
}

func (r *PostgresPlatformRepository) Delete(p *types.Platform) error {
	if err := r.db.Delete(p).Error; err != nil {
		return errors.Wrap(err, "Update: failed to delete a record from platform table")
	}
	return nil
}
