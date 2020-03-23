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

type PostgresPlatformRepository struct {
	db *gorm.DB
}

func (r *PostgresPlatformRepository) Create(p types.Platform) (*types.Platform, error) {
        log.Trace("repository/postgres/pg_platform: Create() Entering")
        defer log.Trace("repository/postgres/pg_platform: Create() Leaving")

	err := r.db.Create(&p).Error
	return &p, errors.Wrap(err, "create: failed to create Platform")
}

func (r *PostgresPlatformRepository) Retrieve(p types.Platform) (*types.Platform, error) {
        log.Trace("repository/postgres/pg_platform: Retrieve() Entering")
        defer log.Trace("repository/postgres/pg_platform: Retrieve() Leaving")

	log.WithField("Platform", p).Debug("Retrieve Call")
	err := r.db.Where(&p).First(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve Platform")
	}
	return &p, nil
}

func (r *PostgresPlatformRepository) RetrieveAll(u types.Platform) (types.Platforms, error) {
        log.Trace("repository/postgres/pg_platform: RetrieveAll() Entering")
        defer log.Trace("repository/postgres/pg_platform: RetrieveAll() Leaving")

	var platforminfo types.Platforms
	err := r.db.Where(&u).Find(&platforminfo).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all Platform")
	}

	log.WithField("db platforminfo", platforminfo).Trace("RetrieveAll")
	return platforminfo, nil
}

func (r *PostgresPlatformRepository) RetrieveAllPlatformInfo() (types.Platforms, error) {
        log.Trace("repository/postgres/pg_platform: RetrieveAllPlatformInfo() Entering")
        defer log.Trace("repository/postgres/pg_platform: RetrieveAllPlatformInfo() Leaving")

        var p types.Platforms
        err := r.db.Find(&p).Error
        if err != nil {
                return nil, errors.Wrap(err, "RetrieveAllPlatformInfo: failed to retrieve all PlatformInfo")
        }

        log.WithField("db PlatformInfo", p).Trace("RetrieveAll")
        return p, nil
}

func (r *PostgresPlatformRepository) Update(u types.Platform) error {
        log.Trace("repository/postgres/pg_platform: Update() Entering")
        defer log.Trace("repository/postgres/pg_platform: Update() Leaving")

	if err := r.db.Save(&u).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update Platform")
	}
	return nil
}

func (r *PostgresPlatformRepository) Delete(u types.Platform) error {
        log.Trace("repository/postgres/pg_platform: Delete() Entering")
        defer log.Trace("repository/postgres/pg_platform: Delete() Leaving")

	if err := r.db.Delete(&u).Error; err != nil {
		return errors.Wrap(err, "Update: failed to Delete Platform")
	}
	return nil
}
