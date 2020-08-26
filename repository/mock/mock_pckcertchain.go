/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/scs/types"
)

type MockPckCertChainRepository struct {
	CreateFunc      func(types.PckCertChain) (*types.PckCertChain, error)
	RetrieveFunc    func(types.PckCertChain) (*types.PckCertChain, error)
	RetrieveAllFunc func(types.PckCertChain) (types.PckCertChains, error)
	UpdateFunc      func(types.PckCertChain) error
	DeleteFunc      func(types.PckCertChain) error
}

func (m *MockPckCertChainRepository) Create(certchain types.PckCertChain) (*types.PckCertChain, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(certchain)
	}
	return nil, nil
}

func (m *MockPckCertChainRepository) Retrieve(rs types.PckCertChain) (*types.PckCertChain, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(rs)
	}
	return nil, nil
}

func (m *MockPckCertChainRepository) RetrieveAll(rs types.PckCertChain) (types.PckCertChains, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(rs)
	}
	return nil, nil
}

func (m *MockPckCertChainRepository) Update(certchain types.PckCertChain) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(certchain)
	}
	return nil
}

func (m *MockPckCertChainRepository) Delete(certchain types.PckCertChain) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(certchain)
	}
	return nil
}
