/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/sgx-caching-service/types"
)

type MockFmspcTcbInfoRepository struct {
	CreateFunc      func(types.FmspcTcbInfo) (*types.FmspcTcbInfo, error)
	RetrieveFunc    func(types.FmspcTcbInfo) (*types.FmspcTcbInfo, error)
	RetrieveAllFunc func(types.FmspcTcbInfo) (types.FmspcTcbInfos, error)
	UpdateFunc      func(types.FmspcTcbInfo) error
	DeleteFunc      func(types.FmspcTcbInfo) error
}

func (m *MockFmspcTcbInfoRepository) Create(fmspc types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(fmspc)
	}
	return nil, nil
}

func (m *MockFmspcTcbInfoRepository) Retrieve(fmspc types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(fmspc)
	}
	return nil, nil
}

func (m *MockFmspcTcbInfoRepository) RetrieveAll(fmspc types.FmspcTcbInfo) (types.FmspcTcbInfos, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(fmspc)
	}
	return nil, nil
}

func (m *MockFmspcTcbInfoRepository) Update(fmspc types.FmspcTcbInfo) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(fmspc)
	}
	return nil
}

func (m *MockFmspcTcbInfoRepository) Delete(fmspc types.FmspcTcbInfo) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(fmspc)
	}
	return nil
}
