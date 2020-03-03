/*
 * Copyright (C) 2019 Intel Corporation
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
	Close()
}
