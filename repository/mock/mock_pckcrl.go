/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/scs/v3/types"
)

type MockPckCrlRepository struct {
	CreateFunc      func(types.PckCrl) (*types.PckCrl, error)
	RetrieveFunc    func(types.PckCrl) (*types.PckCrl, error)
	RetrieveAllFunc func() (types.PckCrls, error)
	UpdateFunc      func(types.PckCrl) error
	DeleteFunc      func(types.PckCrl) error
}

func (m *MockPckCrlRepository) Create(crl types.PckCrl) (*types.PckCrl, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(crl)
	}
	return nil, nil
}

func (m *MockPckCrlRepository) Retrieve(crl types.PckCrl) (*types.PckCrl, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(crl)
	}
	return nil, nil
}

func (m *MockPckCrlRepository) RetrieveAll() (types.PckCrls, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc()
	}
	return nil, nil
}

func (m *MockPckCrlRepository) Update(crl types.PckCrl) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(crl)
	}
	return nil
}

func (m *MockPckCrlRepository) Delete(crl types.PckCrl) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(crl)
	}
	return nil
}
