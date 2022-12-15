/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"errors"
	"intel/isecl/scs/v5/repository"
	"intel/isecl/scs/v5/types"
	"time"
)

type MockPlatformRepository struct {
	Platforms []*types.Platform
}

func NewMockPlatformRepository() repository.PlatformRepository {
	return &MockPlatformRepository{}
}

func (r *MockPlatformRepository) Create(p *types.Platform) (*types.Platform, error) {
	if r.Platforms != nil {
		for _, platform := range r.Platforms {
			if p.QeID == platform.QeID && p.PceID == platform.PceID {
				return nil, errors.New("cert chain already exists")
			}
		}
	}
	thisPlatform := &types.Platform{
		QeID:        p.QeID,
		PceID:       p.PceID,
		CPUSvn:      p.CPUSvn,
		PceSvn:      p.PceSvn,
		Encppid:     p.Encppid,
		Fmspc:       p.Fmspc,
		Ca:          p.Ca,
		Manifest:    p.Manifest,
		HwUUID:      p.HwUUID,
		CreatedTime: time.Now(),
		UpdatedTime: time.Now().Add(2 * time.Hour),
	}
	r.Platforms = append(r.Platforms, thisPlatform)
	return thisPlatform, nil
}

func (r *MockPlatformRepository) Retrieve(p *types.Platform) (*types.Platform, error) {
	for _, platform := range r.Platforms {
		if platform.PceID == "1111" && platform.QeID == "1111111116973c5e69577195511e9080" {
			return nil, nil
		}

		if p.QeID == platform.QeID && p.PceID == platform.PceID {
			return platform, nil
		}
	}
	return nil, errors.New("no records found")
}

func (r *MockPlatformRepository) RetrieveAll() (types.Platforms, error) {
	var thisPlatforms types.Platforms
	for _, platform := range r.Platforms {
		thisPlatforms = append(thisPlatforms, *platform)
	}
	return thisPlatforms, nil
}

func (r *MockPlatformRepository) Update(p *types.Platform) error {
	if p.QeID == "" && p.PceID == "" {
		return errors.New("update failed due to missing field")
	}
	return nil
}

func (r *MockPlatformRepository) Delete(p *types.Platform) error {
	return nil
}
