/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"intel/isecl/sgx-caching-service/types"
)

type MockPckCertRepository struct {
	CreateFunc      func(types.PckCert) (*types.PckCert, error)
	RetrieveFunc    func(types.PckCert) (*types.PckCert, error)
	RetrieveAllFunc func(types.PckCert) (types.PckCerts, error)
	UpdateFunc      func(types.PckCert) error
	DeleteFunc      func(types.PckCert) error
}

func (m *MockPckCertRepository) Create(cert types.PckCert) (*types.PckCert, error) {
	if m.CreateFunc != nil {
		return m.CreateFunc(cert)
	}
	return nil, nil
}

func (m *MockPckCertRepository) Retrieve(cert types.PckCert) (*types.PckCert, error) {
	if m.RetrieveFunc != nil {
		return m.RetrieveFunc(cert)
	}
	return nil, nil
}

func (m *MockPckCertRepository) RetrieveAll(cert types.PckCert) (types.PckCerts, error) {
	if m.RetrieveAllFunc != nil {
		return m.RetrieveAllFunc(cert)
	}
	return nil, nil
}

func (m *MockPckCertRepository) Update(cert types.PckCert) error {
	if m.UpdateFunc != nil {
		return m.UpdateFunc(cert)
	}
	return nil
}

func (m *MockPckCertRepository) Delete(cert types.PckCert) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(cert)
	}
	return nil
}
