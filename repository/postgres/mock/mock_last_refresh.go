/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import (
	"errors"
	"intel/isecl/scs/v5/repository"
	"intel/isecl/scs/v5/types"
)

type MockLastRefreshRepository struct {
}

func NewMockLastRefreshRepository() repository.LastRefreshRepository {
	return &MockLastRefreshRepository{}
}

func (r *MockLastRefreshRepository) Retrieve() (*types.LastRefresh, error) {
	return nil, errors.New("no records found")
}

func (r *MockLastRefreshRepository) Update(lastRefresh *types.LastRefresh) error {
	return nil
}
