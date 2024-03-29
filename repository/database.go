/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package repository

type SCSDatabase interface {
	Migrate() error
	PlatformRepository() PlatformRepository
	PlatformTcbRepository() PlatformTcbRepository
	PckCertChainRepository() PckCertChainRepository
	PckCertRepository() PckCertRepository
	PckCrlRepository() PckCrlRepository
	FmspcTcbInfoRepository() FmspcTcbInfoRepository
	QEIdentityRepository() QEIdentityRepository
	LastRefreshRepository() LastRefreshRepository
	Close()
}
