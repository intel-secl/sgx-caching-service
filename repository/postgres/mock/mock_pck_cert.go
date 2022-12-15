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

type MockPckCertRepository struct {
	PckCerts []*types.PckCert
}

func NewMockPckCertRepository() repository.PckCertRepository {
	return &MockPckCertRepository{}
}

func (r *MockPckCertRepository) Create(u *types.PckCert) (*types.PckCert, error) {
	if r.PckCerts != nil {
		for _, pckCert := range r.PckCerts {
			if u.QeID == pckCert.QeID {
				return nil, errors.New("pckCert already exists")
			}
		}
	}
	newPckCert := &types.PckCert{
		QeID:        u.QeID,
		PceID:       u.PceID,
		CertIndex:   u.CertIndex,
		Tcbms:       u.Tcbms,
		Fmspc:       u.Fmspc,
		PckCerts:    u.PckCerts,
		CreatedTime: time.Now(),
		UpdatedTime: time.Now().Add(2 * time.Hour),
	}
	r.PckCerts = append(r.PckCerts, newPckCert)
	return newPckCert, nil
}

func (r *MockPckCertRepository) Retrieve(pckcert *types.PckCert) (*types.PckCert, error) {
	for _, pck := range r.PckCerts {
		if pck.QeID == pckcert.QeID || pck.PceID == pckcert.PceID {
			return pck, nil
		}
	}
	return nil, errors.New("no records found")
}

func (r *MockPckCertRepository) RetrieveAll() (types.PckCerts, error) {
	return nil, nil
}

func (r *MockPckCertRepository) Update(p *types.PckCert) error {
	if p.QeID == "" && p.PceID == "" {
		return errors.New("updated failed due to missing field")
	}
	return nil
}

func (r *MockPckCertRepository) Delete(p *types.PckCert) error {
	return nil
}
