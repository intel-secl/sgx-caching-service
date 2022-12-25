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

type MockQEIdentityRepository struct {
	QEList *types.QEIdentity
}

func NewMockQEIdentityRepository() repository.QEIdentityRepository {
	return &MockQEIdentityRepository{}
}

func (r *MockQEIdentityRepository) Create(qe *types.QEIdentity) (*types.QEIdentity, error) {
	if r.QEList != nil && r.QEList.ID == qe.ID {
		return nil, errors.New("already exists")
	}
	newQe := &types.QEIdentity{
		ID:            qe.ID,
		QeInfo:        qe.QeInfo,
		QeIssuerChain: qe.QeIssuerChain,
		CreatedTime:   time.Now(),
		UpdatedTime:   time.Now().Add(2 * time.Hour),
	}
	r.QEList = newQe
	return newQe, nil
}

func (r *MockQEIdentityRepository) Retrieve() (*types.QEIdentity, error) {
	if r.QEList != nil {
		return r.QEList, nil
	}
	return nil, errors.New("no records found")
}

func (r *MockQEIdentityRepository) Update(qe *types.QEIdentity) error {
	if qe.QeInfo == "" {
		return errors.New("update failed due to missing field")
	}
	return nil
}

func (r *MockQEIdentityRepository) Delete(qe *types.QEIdentity) error {
	return nil
}
