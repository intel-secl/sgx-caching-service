/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/scs/types"
)

type MockPlatformTcbRepository struct {
	CreateFunc                     func(types.PlatformTcb) (*types.PlatformTcb, error)
	RetrieveFunc                   func(types.PlatformTcb) (*types.PlatformTcb, error)
	RetrieveAllFunc                func(types.PlatformTcb) (types.PlatformTcbs, error)
	RetrieveAllPlatformTcbInfoFunc func() (types.PlatformTcbs, error)
	UpdateFunc                     func(types.PlatformTcb) error
	DeleteFunc                     func(types.PlatformTcb) error
}

func (m *MockPlatformTcbRepository) Create(p types.PlatformTcb) (*types.PlatformTcb, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(p)
	}
	return nil, nil
}

func (m *MockPlatformTcbRepository) Retrieve(p types.PlatformTcb) (*types.PlatformTcb, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(p)
	}
	return nil, nil
}

func (m *MockPlatformTcbRepository) RetrieveAll(u types.PlatformTcb) (types.PlatformTcbs, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(u)
	}
	return nil, nil
}

func (m *MockPlatformTcbRepository) RetrieveAllPlatformTcbInfo() (types.PlatformTcbs, error) {
	if m.RetrieveAllPlatformTcbInfoFunc != nil {
		return m.RetrieveAllPlatformTcbInfoFunc()
	}
	return nil, nil
}

func (m *MockPlatformTcbRepository) Update(p types.PlatformTcb) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(p)
	}
	return nil
}

func (m *MockPlatformTcbRepository) Delete(p types.PlatformTcb) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(p)
	}
	return nil
}
