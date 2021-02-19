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
	err := r.db.Where("qe_id = ?", p.QeID).First(p).Error
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
	if err := r.db.Save(p).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update a record in platform table")
	}
	return nil
}

func (r *PostgresPlatformRepository) Delete(p *types.Platform) error {
	if err := r.db.Delete(p).Error; err != nil {
		return errors.Wrap(err, "Update: failed to delete a record from platform table")
	}
	return nil
}
