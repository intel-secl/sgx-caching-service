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

type PostgresPlatformTcbRepository struct {
	db *gorm.DB
}

func (r *PostgresPlatformTcbRepository) Create(p types.PlatformTcb) (*types.PlatformTcb, error) {
	err := r.db.Create(&p).Error
	return &p, errors.Wrap(err, "create: failed to create PlatformTcb")
}

func (r *PostgresPlatformTcbRepository) Retrieve(p types.PlatformTcb) (*types.PlatformTcb, error) {
	log.WithField("PlatformTcb", p).Debug("Retrieve Call")
	err := r.db.Where(&p).First(&p).Error
	if err != nil {
		return nil, errors.Wrap(err, "Retrieve: failed to retrieve PlatformTcb")
	}
	return &p, nil
}

func (r *PostgresPlatformTcbRepository) RetrieveAll(u types.PlatformTcb) (types.PlatformTcbs, error) {
	var platformTcbinfo types.PlatformTcbs
	err := r.db.Where(&u).Find(&platformTcbinfo).Error
	if err != nil {
		return nil, errors.Wrap(err, "RetrieveAll: failed to retrieve all PlatformTcb")
	}

	log.WithField("db platformTcbinfo", platformTcbinfo).Trace("RetrieveAll")
	return platformTcbinfo, nil
}

func (r *PostgresPlatformTcbRepository) RetrieveAllPlatformTcbInfo() (types.PlatformTcbs, error) {
        var p types.PlatformTcbs
        err := r.db.Find(&p).Error
        if err != nil {
                return nil, errors.Wrap(err, "RetrieveAllPlatformTcbInfo: failed to retrieve all PlatformTcbInfo")
        }

        log.WithField("db PlatformTcbInfo", p).Trace("RetrieveAll")
        return p, nil
}

func (r *PostgresPlatformTcbRepository) Update(u types.PlatformTcb) error {
	if err := r.db.Save(&u).Error; err != nil {
		return errors.Wrap(err, "Update: failed to update PlatformTcb")
	}
	return nil
}

func (r *PostgresPlatformTcbRepository) Delete(u types.PlatformTcb) error {
	if err := r.db.Delete(&u).Error; err != nil {
		return errors.Wrap(err, "Update: failed to Delete PlatformTcb")
	}
	return nil
}
