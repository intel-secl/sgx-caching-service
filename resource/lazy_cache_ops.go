/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"github.com/pkg/errors"
	"intel/isecl/scs/repository"
	"intel/isecl/scs/types"
)

// perform an api call to pcs server to get PCK Certificate for a sgx platform and store in db
func getLazyCachePckCert(db repository.SCSDatabase, encryptedPPID string, cpuSvn string,
	PceSvn string, pceId string, qeId string, manifest string) (*types.PckCert, error) {
	log.Trace("resource/lazy_cache_ops: getLazyCachePckCert() Entering")
	defer log.Trace("resource/lazy_cache_ops: getLazyCachePckCert() Leaving")

	var data SgxData
	data.PlatformInfo.EncPpid = encryptedPPID
	data.PlatformInfo.CpuSvn = cpuSvn
	data.PlatformInfo.PceSvn = PceSvn
	data.PlatformInfo.PceId = pceId
	data.PlatformInfo.QeId = qeId
	data.PlatformInfo.PlatformManifest = manifest

	err := fetchPckCertInfo(&data)
	if err != nil {
		return nil, errors.New("fetchPckCertInfo:" + err.Error())
	}

	err = cachePlatformInfo(db, &data)
	if err != nil {
		return nil, errors.New("cachePlatformInfo:" + err.Error())
	}

	err = cachePlatformTcbInfo(db, &data)
	if err != nil {
		return nil, errors.New("cachePlatformTcbInfo:" + err.Error())
	}

	err = cacheFmspcTcbInfo(db, &data)
	if err != nil {
		return nil, errors.New("cacheFmpscTcbInfo:" + err.Error())
	}

	err = cachePckCertChainInfo(db, &data)
	if err != nil {
		return nil, errors.New("cachePckCertChainInfo:" + err.Error())
	}

	err = cachePckCertInfo(db, &data)
	if err != nil {
		return nil, errors.New("cachePckCertInfo:" + err.Error())
	}

	log.Debug("getLazyCachePckCert: Pck Cert best suited for current tcb level is fetched")
	return data.PckCert, nil
}

// perform an api call to pcs server to get trusted computing base info for a sgx platform and store in db
func getLazyCacheFmspcTcbInfo(db repository.SCSDatabase, fmspcType string) (*types.FmspcTcbInfo, error) {
	log.Trace("resource/lazy_cache_ops: getLazyCacheFmspcTcbInfo() Entering")
	defer log.Trace("resource/lazy_cache_ops: getLazyCacheFmspcTcbInfo() Leaving")
	var data SgxData
	data.FmspcTcbInfo.Fmspc = fmspcType

	err := fetchFmspcTcbInfo(&data)
	if err != nil {
		return nil, errors.New("getLazyCacheFmspcTcbInfo: failed to fetch tcbinfo")
	}

	err = cacheFmspcTcbInfo(db, &data)
	if err != nil {
		return nil, errors.New("cacheFmspcTcbInfo:" + err.Error())
	}

	log.Debug("getLazyCacheFmspcTcbInfo fetch and cache operation completed")
	return data.FmspcTcb, nil
}

func getLazyCachePckCrl(db repository.SCSDatabase, CaType string) (*types.PckCrl, error) {
	log.Trace("resource/lazy_cache_ops: getLazyCachePckCrl() Entering")
	defer log.Trace("resource/lazy_cache_ops: getLazyCachePckCrl() Leaving")

	var data SgxData
	data.PckCRLInfo.Ca = CaType

	err := fetchPckCrlInfo(&data)
	if err != nil {
		return nil, errors.New("getLazyCachePckCrl: Failed to fetch PCKCRLInfo")
	}

	err = cachePckCrlInfo(db, &data)
	if err != nil {
		return nil, errors.New("cachePckCRLInfo:" + err.Error())
	}

	log.Debug("getLazyCachePckCrl fetch and cache operation completed")
	return data.PckCrl, nil
}

func getLazyCacheQEIdentityInfo(db repository.SCSDatabase) (types.QEIdentities, error) {
	log.Trace("resource/lazy_cache_ops: getLazyCacheQEIdentityInfo() Entering")
	defer log.Trace("resource/lazy_cache_ops: getLazyCacheQEIdentityInfo() Leaving")

	var data SgxData

	err := fetchQeIdentityInfo(&data)
	if err != nil {
		return nil, errors.New("fetchQeIdentityInfo:" + err.Error())
	}

	err = cacheQeIdentityInfo(db, &data)
	if err != nil {
		return nil, errors.New("cacheQeIdentityInfo:" + err.Error())
	}

	existingQeInfo, err := db.QEIdentityRepository().RetrieveAll()
	if existingQeInfo == nil && err == nil {
		return nil, errors.New("getLazyCacheQEIdentityInfo: Retrive data error" + err.Error())
	}

	log.Debug("getLazyCacheQEIdentityInfo fetch and cache operation completed")
	return existingQeInfo, nil
}
