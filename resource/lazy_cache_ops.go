/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (

        "intel/isecl/scs/repository"
        "intel/isecl/scs/types"
	"github.com/pkg/errors"
)

func GetLazyCachePckCert(db repository.SCSDatabase, encryptedPPID string, cpuSvn string,
			PceSvn string, pceId string, qeId string) (*types.Platform, error) {
	var data SgxData
	data.PlatformInfo.EncPpid = encryptedPPID
	data.PlatformInfo.CpuSvn = cpuSvn
	data.PlatformInfo.PceSvn = PceSvn
	data.PlatformInfo.PceId = pceId
	data.PlatformInfo.QeId = qeId

        err := FetchPCKCertInfo(&data)
	if err != nil {
		return nil, errors.New("FetchPCKCertInfo:" + err.Error())
	}

	err = CachePlatformInfo(db, &data)
	if err != nil {
		return nil, errors.New("CachePlatformInfo:" + err.Error())
	}

	err = CachePlatformTcbInfo(db, &data)
	if err != nil {
		return nil, errors.New("CachePlatformTcbInfo:" + err.Error())
	}

	err = CacheFmspcTcbInfo(db, &data)
	if err != nil {
		return nil, errors.New("CacheFmpscTcbInfo:" + err.Error())
	}

	err = CachePckCertChainInfo(db, &data)
	if err != nil {
		return nil, errors.New("CachePckCertChainInfo:" + err.Error())
	}

	err = CachePckCertInfo(db, &data)
	if err != nil {
		return nil, errors.New("CachePckCertInfo:" + err.Error())
	}

	log.Debug("GetLazyCachePckCert: Pck Cert best suited for current tcb level is fetched")
	return data.Platform, nil
}

func GetLazyCacheFmspcTcbInfo(db repository.SCSDatabase, fmspcType string) (*types.FmspcTcbInfo, error) {
	var data SgxData
	data.FmspcTcbInfo.Fmspc = fmspcType

	err := FetchFmspcTcbInfo(&data)
	if err != nil {
		return nil, errors.New("FetchFmspcTcbInfo:" + err.Error())
	}

	err = CacheFmspcTcbInfo(db, &data)
	if err != nil {
		return nil, errors.New("CacheFmspcTcbInfo:" + err.Error())
	}

	log.Debug("GetLazyCacheFmspcTcbInfo fetch and cache operation completed")
	return data.FmspcTcb, nil
}

func GetLazyCachePckCrl(db repository.SCSDatabase, CaType string) (*types.PckCrl, error) {
	var data SgxData
	data.PckCRLInfo.Ca = CaType

	err := FetchPCKCRLInfo(&data)
	if err != nil {
		return nil, errors.New("FetchPCKCRLInfo:" + err.Error())
	}

	err = CachePckCRLInfo(db, &data)
	if err != nil {
		return nil, errors.New("CachePckCRLInfo:" + err.Error())
	}

	log.Debug("GetLazyCachePckCrl fetch and cache operation completed")
	return data.PckCrl, nil
}

func GetLazyCacheQEIdentityInfo(db repository.SCSDatabase) (types.QEIdentities, error) {
	var data SgxData

	err := FetchQEIdentityInfo(&data)
	if err != nil {
		return nil, errors.New("FetchQEIdentityInfo:" + err.Error())
	}

	err = CacheQEIdentityInfo(db, &data)
	if err != nil {
		return nil, errors.New("CacheQEIdentityInfo:" + err.Error())
	}

	existingQeInfo, err := db.QEIdentityRepository().RetrieveAll()
	if existingQeInfo == nil && err == nil {
		return nil, errors.New("GetLazyCacheQEIdentityInfo: Retrive data error" +  err.Error() )
	}

	log.Debug("GetLazyCacheQEIdentityInfo fetch and cache operation completed")
	return existingQeInfo, nil
}
