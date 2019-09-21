/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/sgx-caching-service/types"
)

type MockQEIdentityRepository struct {
	CreateFunc      func(types.QEIdentity) (*types.QEIdentity, error)
	RetrieveFunc    func(types.QEIdentity) (*types.QEIdentity, error)
	RetrieveAllFunc func() (types.QEIdentities, error)
	UpdateFunc      func(types.QEIdentity) error
	DeleteFunc      func(types.QEIdentity) error
}

func (m *MockQEIdentityRepository) Create(qe types.QEIdentity) (*types.QEIdentity, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(qe)
	}
	return nil, nil
}

func (m *MockQEIdentityRepository) Retrieve(qe types.QEIdentity) (*types.QEIdentity, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(qe)
	}
	return nil, nil
}

func (m *MockQEIdentityRepository) RetrieveAll() (types.QEIdentities, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc()
	}
	return nil, nil
}

func (m *MockQEIdentityRepository) Update(qe types.QEIdentity) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(qe)
	}
	return nil
}

func (m *MockQEIdentityRepository) Delete(qe types.QEIdentity) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(qe)
	}
	return nil
}
