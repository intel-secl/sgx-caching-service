/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"intel/isecl/sgx-caching-service/types"

	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
)

type PostgresPlatformTcbRepository struct {
	db *gorm.DB
}

func (r *PostgresPlatformTcbRepository) Create(p types.PlatformTcb) (*types.PlatformTcb, error) {
        log.Trace("repository/postgres/pg_platform_tcb: Create() Entering")
        defer log.Trace("repository/postgres/pg_platform_tcb: Create() Leaving")

	err := r.db.Create(&p).Error
	return &p, errors.Wrap(err, "create: failed to create PlatformTcb")
}

func (r *PostgresPlatformTcbRepository) Retrieve(p types.PlatformTcb) (*types.PlatformTcb, error) {
        log.Trace("repository/postgres/pg_platform_tcb: Retrieve() Entering")
        defer log.Trace("repository/postgres/pg_platform_tcb: Retrieve() Leaving")

	slog.WithField("PlatformTcb", p).Debug("Retrieve Call")
	err := r.db.Where(&p).First(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve PlatformTcb")
	}
	return &p, nil
}


func (r *PostgresPlatformTcbRepository) RetrieveAll(u types.PlatformTcb) (types.PlatformTcbs, error) {
        log.Trace("repository/postgres/pg_platform_tcb: RetrieveAll() Entering")
        defer log.Trace("repository/postgres/pg_platform_tcb: RetrieveAll() Leaving")

	var platforminfo types.PlatformTcbs
	err := r.db.Where(&u).Find(&platforminfo).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all PlatformTcb")
	}

	slog.WithField("db platforminfo", platforminfo).Trace("RetrieveAll")
	return platforminfo, nil
}

func (r *PostgresPlatformTcbRepository) RetrieveAllPlatformInfo() (types.PlatformTcbs, error) {
        log.Trace("repository/postgres/pg_platform_tcb: RetrieveAllPlatformInfo() Entering")
        defer log.Trace("repository/postgres/pg_platform_tcb: RetrieveAllPlatformInfo() Leaving")

        var p types.PlatformTcbs
        err := r.db.Find(&p).Error
        if err != nil {
                return nil, errors.Wrap(err, "RetrieveAllPlatformInfo: failed to retrieve all PlatformInfo")
        }

        slog.WithField("db PlatformInfo", p).Trace("RetrieveAll")
        return p, nil
}


func (r *PostgresPlatformTcbRepository) Update(u types.PlatformTcb) error {
        log.Trace("repository/postgres/pg_platform_tcb: Update() Entering")
        defer log.Trace("repository/postgres/pg_platform_tcb: Update() Leaving")

	if err := r.db.Save(&u).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update Platformtcb")
	}
	return nil
}

func (r *PostgresPlatformTcbRepository) Delete(u types.PlatformTcb) error {
        log.Trace("repository/postgres/pg_platform_tcb: Delete() Entering")
        defer log.Trace("repository/postgres/pg_platform_tcb: Delete() Leaving")

	if err := r.db.Delete(&u).Error; err != nil {
		return errors.Wrap(err, "Update: failed to Delete Platformtcb")
	}
	return nil
}

