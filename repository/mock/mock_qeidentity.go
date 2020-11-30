/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/scs/v3/types"
)

type MockQEIdentityRepository struct {
	CreateFunc   func(types.QEIdentity) (*types.QEIdentity, error)
	RetrieveFunc func() (*types.QEIdentity, error)
	UpdateFunc   func(types.QEIdentity) error
	DeleteFunc   func(types.QEIdentity) error
}

func (m *MockQEIdentityRepository) Create(qe types.QEIdentity) (*types.QEIdentity, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(qe)
	}
	return nil, nil
}

func (m *MockQEIdentityRepository) Retrieve() (*types.QEIdentity, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc()
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
