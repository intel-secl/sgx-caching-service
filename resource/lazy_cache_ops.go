/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"github.com/pkg/errors"
	"intel/isecl/scs/v5/constants"
	"intel/isecl/scs/v5/repository"
	"intel/isecl/scs/v5/types"
)

// perform an api call to pcs server to get PCK Certificate for a sgx platform and store in db
func getLazyCachePckCert(db repository.SCSDatabase, platformInfo *types.Platform, cacheType constants.CacheType) (*types.PckCert, *types.PckCertChain, string, error) {
	log.Trace("resource/lazy_cache_ops: getLazyCachePckCert() Entering")
	defer log.Trace("resource/lazy_cache_ops: getLazyCachePckCert() Leaving")

	pckCertInfo, fmspcTcbInfo, pckCertChain, ca, err := fetchPckCertInfo(platformInfo)
	if err != nil {
		return nil, nil, "", errors.New("fetchPckCertInfo:" + err.Error())
	}

	platformInfo.Fmspc = fmspcTcbInfo.Fmspc
	platformInfo.Ca = ca
	err = cachePlatformInfo(db, platformInfo, cacheType)
	if err != nil {
		return nil, nil, "", errors.New("cachePlatformInfo:" + err.Error())
	}

	err = cachePlatformTcbInfo(db, platformInfo, pckCertInfo.Tcbms[pckCertInfo.CertIndex], cacheType)
	if err != nil {
		return nil, nil, "", errors.New("cachePlatformTcbInfo:" + err.Error())
	}

	_, err = cacheFmspcTcbInfo(db, fmspcTcbInfo, cacheType)
	if err != nil {
		return nil, nil, "", errors.New("cacheFmpscTcbInfo:" + err.Error())
	}

	certChain, err := cachePckCertChainInfo(db, pckCertChain, ca, cacheType)
	if err != nil {
		return nil, nil, "", errors.New("cachePckCertChainInfo:" + err.Error())
	}

	pckCert, err := cachePckCertInfo(db, pckCertInfo, cacheType)
	if err != nil {
		return nil, nil, "", errors.New("cachePckCertInfo:" + err.Error())
	}

	log.Debug("getLazyCachePckCert: Pck Cert best suited for current tcb level is fetched")
	return pckCert, certChain, ca, nil
}

// perform an api call to pcs server to get trusted computing base info for a sgx platform and store in db
func getLazyCacheFmspcTcbInfo(db repository.SCSDatabase, fmspcType string, cacheType constants.CacheType) (*types.FmspcTcbInfo, error) {
	log.Trace("resource/lazy_cache_ops: getLazyCacheFmspcTcbInfo() Entering")
	defer log.Trace("resource/lazy_cache_ops: getLazyCacheFmspcTcbInfo() Leaving")

	fmspcTcbInfo, err := fetchFmspcTcbInfo(fmspcType)
	if err != nil {
		return nil, errors.New("getLazyCacheFmspcTcbInfo: failed to fetch tcbinfo")
	}

	fmspcTcb, err := cacheFmspcTcbInfo(db, fmspcTcbInfo, cacheType)
	if err != nil {
		return nil, errors.New("cacheFmspcTcbInfo:" + err.Error())
	}

	log.Debug("getLazyCacheFmspcTcbInfo fetch and cache operation completed")
	return fmspcTcb, nil
}

func getLazyCachePckCrl(db repository.SCSDatabase, caType string, cacheType constants.CacheType) (*types.PckCrl, error) {
	log.Trace("resource/lazy_cache_ops: getLazyCachePckCrl() Entering")
	defer log.Trace("resource/lazy_cache_ops: getLazyCachePckCrl() Leaving")

	pckCRLInfo, err := fetchPckCrlInfo(caType)
	if err != nil {
		return nil, errors.New("getLazyCachePckCrl: Failed to fetch PCKCRLInfo")
	}

	pckCrl, err := cachePckCrlInfo(db, pckCRLInfo, cacheType)
	if err != nil {
		return nil, errors.New("cachePckCRLInfo:" + err.Error())
	}

	log.Debug("getLazyCachePckCrl fetch and cache operation completed")
	return pckCrl, nil
}

func getLazyCacheQEIdentityInfo(db repository.SCSDatabase, cacheType constants.CacheType) (*types.QEIdentity, error) {
	log.Trace("resource/lazy_cache_ops: getLazyCacheQEIdentityInfo() Entering")
	defer log.Trace("resource/lazy_cache_ops: getLazyCacheQEIdentityInfo() Leaving")

	qeInfo, err := fetchQeIdentityInfo()
	if err != nil {
		return nil, errors.New("fetchQeIdentityInfo:" + err.Error())
	}

	qeIdentity, err := cacheQeIdentityInfo(db, qeInfo, cacheType)
	if err != nil {
		return nil, errors.New("cacheQeIdentityInfo:" + err.Error())
	}

	log.Debug("getLazyCacheQEIdentityInfo fetch and cache operation completed")
	return qeIdentity, nil
}
