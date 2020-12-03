/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/scs/v3/types"
)

type MockPckCertChainRepository struct {
	CreateFunc   func(types.PckCertChain) (*types.PckCertChain, error)
	RetrieveFunc func() (*types.PckCertChain, error)
	UpdateFunc   func(types.PckCertChain) error
	DeleteFunc   func(types.PckCertChain) error
}

func (m *MockPckCertChainRepository) Create(certchain types.PckCertChain) (*types.PckCertChain, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(certchain)
	}
	return nil, nil
}

func (m *MockPckCertChainRepository) Retrieve() (*types.PckCertChain, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc()
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
