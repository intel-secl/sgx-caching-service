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

type MockFmspcTcbInfoRepository struct {
	FmspcTcbInfo []*types.FmspcTcbInfo
}

func NewMockFmspcTcbInfoRepository() repository.FmspcTcbInfoRepository {
	return &MockFmspcTcbInfoRepository{}
}

func (r *MockFmspcTcbInfoRepository) Create(tcb *types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
	if r.FmspcTcbInfo != nil {
		for _, thisFmspc := range r.FmspcTcbInfo {
			if thisFmspc.Fmspc == tcb.Fmspc {
				return nil, errors.New("already exists")
			}
		}
	}
	tcbInfo := &types.FmspcTcbInfo{
		Fmspc:       tcb.Fmspc,
		TcbInfo:     tcb.TcbInfo,
		CreatedTime: time.Now(),
		UpdatedTime: time.Now().Add(2 * time.Hour),
	}
	r.FmspcTcbInfo = append(r.FmspcTcbInfo, tcbInfo)
	return tcbInfo, nil
}

func (r *MockFmspcTcbInfoRepository) Retrieve(tcb *types.FmspcTcbInfo) (*types.FmspcTcbInfo, error) {
	for _, tcbInfo := range r.FmspcTcbInfo {
		// &types.Platform{QeID: qeID, PceID: pceID}
		if tcb.Fmspc == tcbInfo.Fmspc {
			return tcbInfo, nil
		}
	}
	return nil, errors.New("no records found")
}

func (r *MockFmspcTcbInfoRepository) RetrieveAll() (types.FmspcTcbInfos, error) {
	var fmspcTcbInfos types.FmspcTcbInfos
	for _, tcbInfo := range r.FmspcTcbInfo {
		fmspcTcbInfos = append(fmspcTcbInfos, *tcbInfo)
	}
	return fmspcTcbInfos, nil
}

func (r *MockFmspcTcbInfoRepository) Update(tcb *types.FmspcTcbInfo) error {
	if tcb.Fmspc == "" {
		return errors.New("updated failed due to missing field")
	}
	return nil
}

func (r *MockFmspcTcbInfoRepository) Delete(tcb *types.FmspcTcbInfo) error {
	return nil
}
