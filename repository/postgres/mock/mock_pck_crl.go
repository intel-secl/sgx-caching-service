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

type MockPckCrlRepository struct {
	PckCrls []*types.PckCrl
}

func NewMockPckCrlRepository() repository.PckCrlRepository {
	return &MockPckCrlRepository{}
}

func (r *MockPckCrlRepository) Create(crl *types.PckCrl) (*types.PckCrl, error) {
	if r.PckCrls != nil {
		for _, thisCrl := range r.PckCrls {
			if thisCrl.Ca == crl.Ca {
				return nil, errors.New("already exists")
			}
		}
	}
	pckCrl := &types.PckCrl{
		Ca:              crl.Ca,
		PckCrlCertChain: crl.PckCrlCertChain,
		CreatedTime:     time.Now(),
		UpdatedTime:     time.Now().Add(2 * time.Hour),
	}
	r.PckCrls = append(r.PckCrls, pckCrl)
	return pckCrl, nil
}

func (r *MockPckCrlRepository) Retrieve(crl *types.PckCrl) (*types.PckCrl, error) {
	for _, thisCrl := range r.PckCrls {
		if thisCrl.Ca == crl.Ca {
			return thisCrl, nil
		}
	}
	return nil, errors.New("no records found")
}

func (r *MockPckCrlRepository) RetrieveAll() (types.PckCrls, error) {
	var pckCrls types.PckCrls
	for _, thisCrl := range r.PckCrls {
		pckCrls = append(pckCrls, *thisCrl)
	}
	return pckCrls, nil
}

func (r *MockPckCrlRepository) Update(crl *types.PckCrl) error {
	if crl.Ca == "" && crl.PckCrlCertChain == "" {
		return errors.New("update failed")
	}
	return nil
}

func (r *MockPckCrlRepository) Delete(crl *types.PckCrl) error {
	return nil
}
