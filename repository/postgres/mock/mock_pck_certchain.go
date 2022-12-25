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

type MockPckCertChainRepository struct {
	CertChains []*types.PckCertChain
}

func NewMockPckCertChainRepository() repository.PckCertChainRepository {
	return &MockPckCertChainRepository{}
}

func (r *MockPckCertChainRepository) Create(pcc *types.PckCertChain) (*types.PckCertChain, error) {
	if r.CertChains != nil {
		for _, certChain := range r.CertChains {
			if pcc.Ca == certChain.Ca {
				return nil, errors.New("cert chain already exists")
			}
		}
	}
	certChain := &types.PckCertChain{
		Ca:           pcc.Ca,
		PckCertChain: pcc.PckCertChain,
		CreatedTime:  time.Now(),
		UpdatedTime:  time.Now().Add(2 * time.Hour),
	}
	r.CertChains = append(r.CertChains, certChain)
	return certChain, nil
}

func (r *MockPckCertChainRepository) Retrieve(pcc *types.PckCertChain) (*types.PckCertChain, error) {
	for _, certChain := range r.CertChains {
		if certChain.Ca == pcc.Ca {
			return certChain, nil
		}
	}
	return nil, errors.New("no records found")
}

func (r *MockPckCertChainRepository) Update(pcc *types.PckCertChain) error {
	if pcc.Ca == "" && pcc.PckCertChain == "" {
		return errors.New("updated failed due to missing field")
	}
	return nil
}

func (r *MockPckCertChainRepository) Delete(pcc *types.PckCertChain) error {
	return nil
}
