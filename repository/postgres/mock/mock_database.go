/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mock

import "intel/isecl/scs/v5/repository"

type MockDatabase struct {
	MockPlatformRepository     repository.PlatformRepository
	MockPlatformTcbRepository  repository.PlatformTcbRepository
	MockFmspcTcbInfoRepository repository.FmspcTcbInfoRepository
	MockPckCertChainRepository repository.PckCertChainRepository
	MockPckCertRepository      repository.PckCertRepository
	MockPckCrlRepository       repository.PckCrlRepository
	MockLastRefreshRepository  repository.LastRefreshRepository
	MockQEIdentityRepository   repository.QEIdentityRepository
}

func (pd *MockDatabase) Migrate() error {
	return nil
}

func (pd *MockDatabase) PlatformRepository() repository.PlatformRepository {
	return pd.MockPlatformRepository
}

func (pd *MockDatabase) PlatformTcbRepository() repository.PlatformTcbRepository {
	return pd.MockPlatformTcbRepository
}

func (pd *MockDatabase) FmspcTcbInfoRepository() repository.FmspcTcbInfoRepository {
	return pd.MockFmspcTcbInfoRepository
}

func (pd *MockDatabase) PckCertChainRepository() repository.PckCertChainRepository {
	return pd.MockPckCertChainRepository
}

func (pd *MockDatabase) PckCertRepository() repository.PckCertRepository {
	return pd.MockPckCertRepository
}

func (pd *MockDatabase) PckCrlRepository() repository.PckCrlRepository {
	return pd.MockPckCrlRepository
}

func (pd *MockDatabase) LastRefreshRepository() repository.LastRefreshRepository {
	return pd.MockLastRefreshRepository
}

func (pd *MockDatabase) QEIdentityRepository() repository.QEIdentityRepository {
	return pd.MockQEIdentityRepository
}

func (pd *MockDatabase) Close() {
}
