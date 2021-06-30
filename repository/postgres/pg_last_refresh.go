/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"intel/isecl/scs/v4/types"
)

type PostgresLastRefreshRepository struct {
	db *gorm.DB
}

func (r *PostgresLastRefreshRepository) Retrieve() (*types.LastRefresh, error) {
	var lastRefresh types.LastRefresh
	err := r.db.Take(&lastRefresh).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}

	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve a record from last_refresh table.")
	}

	return &lastRefresh, nil
}

func (r *PostgresLastRefreshRepository) Update(lastRefresh *types.LastRefresh) error {
	// Delete all rows as we keep only the last refresh info.
	err := r.db.Where("1 = 1").Delete(&types.LastRefresh{}).Error

	if err != nil {
		return errors.Wrap(err, "Update: failed to delete rows from last_refresh table.")
	}

	// Create a new row with the latest info
	err = r.db.Create(lastRefresh).Error
	if err != nil {
		return errors.Wrap(err, "Update: failed to delete rows from last_refresh table.")
	}

	return nil
}
