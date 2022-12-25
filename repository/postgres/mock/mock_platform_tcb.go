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

type MockPlatformTcbRepository struct {
	PlatformTcbs types.PlatformTcbs
}

func NewMockPlatformTcbRepository() repository.PlatformTcbRepository {
	return &MockPlatformTcbRepository{}
}

func (r *MockPlatformTcbRepository) Create(p *types.PlatformTcb) (*types.PlatformTcb, error) {
	if r.PlatformTcbs != nil {
		for _, platformtcb := range r.PlatformTcbs {
			if p.QeID == platformtcb.QeID && p.PceID == platformtcb.PceID {
				return nil, errors.New("cert chain already exists")
			}
		}
	}
	thisPlatformTcb := &types.PlatformTcb{
		QeID:        p.QeID,
		PceID:       p.PceID,
		CPUSvn:      p.CPUSvn,
		PceSvn:      p.PceSvn,
		Tcbm:        p.Tcbm,
		CreatedTime: time.Now(),
		UpdatedTime: time.Now().Add(2 * time.Hour),
	}
	r.PlatformTcbs = append(r.PlatformTcbs, *thisPlatformTcb)
	return nil, nil
}

func (r *MockPlatformTcbRepository) Retrieve(p *types.PlatformTcb) (*types.PlatformTcb, error) {
	return nil, nil
}

func (r *MockPlatformTcbRepository) RetrieveAll() (types.PlatformTcbs, error) {
	return nil, nil
}

func (r *MockPlatformTcbRepository) Update(p *types.PlatformTcb) error {
	if p.QeID == "" && p.PceID == "" {
		return errors.New("update failed")
	}
	return nil
}

func (r *MockPlatformTcbRepository) Delete(p *types.PlatformTcb) error {
	return nil
}
