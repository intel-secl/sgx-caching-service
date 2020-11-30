/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/scs/v3/types"
)

type MockPlatformRepository struct {
	CreateFunc      func(types.Platform) (*types.Platform, error)
	RetrieveFunc    func(types.Platform) (*types.Platform, error)
	RetrieveAllFunc func() (types.Platforms, error)
	UpdateFunc      func(types.Platform) error
	DeleteFunc      func(types.Platform) error
}

func (m *MockPlatformRepository) Create(p types.Platform) (*types.Platform, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(p)
	}
	return nil, nil
}

func (m *MockPlatformRepository) Retrieve(p types.Platform) (*types.Platform, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(p)
	}
	return nil, nil
}

func (m *MockPlatformRepository) RetrieveAll() (types.Platforms, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc()
	}
	return nil, nil
}

func (m *MockPlatformRepository) Update(p types.Platform) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(p)
	}
	return nil
}

func (m *MockPlatformRepository) Delete(p types.Platform) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(p)
	}
	return nil
}
