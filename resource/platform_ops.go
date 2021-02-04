/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

/*
 #cgo LDFLAGS: -lPCKCertSelection
 #include <stdlib.h>
 #include "pck_cert_selection.h"
*/
import "C"

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/scs/v3/constants"
	"intel/isecl/scs/v3/repository"
	"intel/isecl/scs/v3/types"
)

const (
	Error = iota
	EqualOrGreater
	Lower
	Undefined
)

type Response struct {
	Status  string
	Message string
}

type PlatformInfo struct {
	EncPpid     string `json:"enc_ppid"`
	CpuSvn      string `json:"cpu_svn"`
	PceSvn      string `json:"pce_svn"`
	PceId       string `json:"pce_id"`
	QeId        string `json:"qe_id"`
	Manifest    string `json:"manifest"`
}

type TcbLevels struct {
	SgxTcbComp01Svn uint8  `json:"sgxtcbcomp01svn"`
	SgxTcbComp02Svn uint8  `json:"sgxtcbcomp02svn"`
	SgxTcbComp03Svn uint8  `json:"sgxtcbcomp03svn"`
	SgxTcbComp04Svn uint8  `json:"sgxtcbcomp04svn"`
	SgxTcbComp05Svn uint8  `json:"sgxtcbcomp05svn"`
	SgxTcbComp06Svn uint8  `json:"sgxtcbcomp06svn"`
	SgxTcbComp07Svn uint8  `json:"sgxtcbcomp07svn"`
	SgxTcbComp08Svn uint8  `json:"sgxtcbcomp08svn"`
	SgxTcbComp09Svn uint8  `json:"sgxtcbcomp09svn"`
	SgxTcbComp10Svn uint8  `json:"sgxtcbcomp10svn"`
	SgxTcbComp11Svn uint8  `json:"sgxtcbcomp11svn"`
	SgxTcbComp12Svn uint8  `json:"sgxtcbcomp12svn"`
	SgxTcbComp13Svn uint8  `json:"sgxtcbcomp13svn"`
	SgxTcbComp14Svn uint8  `json:"sgxtcbcomp14svn"`
	SgxTcbComp15Svn uint8  `json:"sgxtcbcomp15svn"`
	SgxTcbComp16Svn uint8  `json:"sgxtcbcomp16svn"`
	PceSvn          uint16 `json: "pcesvn"`
}

type TcbLevelsType struct {
	Tcb       TcbLevels `json: "tcb"`
	TcbDate   string    `json: "tcbDate"`
	TcbStatus string    `json: "tcbStatus"`
}

type TcbInfoType struct {
	Version                 int             `json:"version"`
	IssueDate               string          `json:"issueDate"`
	NextUpdate              string          `json:"nextUpdate"`
	Fmspc                   string          `json:"fmspc"`
	PceId                   string          `json:"pceId"`
	TcbType                 int             `json:"tcbType"`
	TcbEvaluationDataNumber int             `josn:"tcbEvaluationDataNumber"`
	TcbLevels               []TcbLevelsType `json:"tcbLevels"`
}

type TcbInfoJson struct {
	TcbInfo   TcbInfoType `josn:"tcbInfo"`
	Signature string      `json:"signature"`
}

type PckCertsInfo struct {
	Tcb  TcbLevels `json:"tcb"`
	Tcbm string    `json:"tcbm"`
	Cert string    `json:"cert"`
}

type cpu_svn struct {
	bytes []byte
}

func PlatformInfoOps(r *mux.Router, db repository.SCSDatabase) {
	r.Handle("/platforms", handlers.ContentTypeHandler(pushPlatformInfo(db), "application/json")).Methods("POST")
	r.Handle("/refreshes", handlers.ContentTypeHandler(refreshPlatformInfo(db), "application/json")).Methods("GET")
	r.Handle("/tcbstatus", handlers.ContentTypeHandler(getTcbStatus(db), "application/json")).Methods("GET")
}

// This function invokes SGX DCAP PCK Certificate Selection Library (C++)
// we pass following parameters to the C++ library
// 1. current taw tcb level of the platform (cpusvn and pcesvn value)
// 2. pce id of the platform
// 3. TCBInfo for the platform
// 4. All PCK Certficates for all the TCB levels of the platform
// 5. Number of PCK certificates
// C++ library chooses best suited PCK certificate for the current TCB level
// and returns index to the certificate
func getBestPckCert(platformInfo *types.Platform, pckCerts []string, tcb string) (uint8, error) {
	var err error
	var cpuSvn cpu_svn

	cpuSvn.bytes, err = hex.DecodeString(platformInfo.CpuSvn)
	if err != nil {
		log.WithError(err).Error("could not decode cpusvn string")
		return 0, err
	}
	pceSvn, err := strconv.ParseUint(platformInfo.PceSvn, 16, 32)
	if err != nil {
		log.WithError(err).Error("could not parse pcesvn string")
		return 0, err
	}
	pceId, err := strconv.ParseUint(platformInfo.PceId, 16, 32)
	if err != nil {
		log.WithError(err).Error("could not parse pceid string")
		return 0, err
	}

	tcbInfo := C.CString(tcb)
	if tcbInfo != nil {
		defer C.free(unsafe.Pointer(tcbInfo))
	} else {
		return 0, errors.New("failed to allocate memory for tcbinfo")
	}

	var certIdx C.uint
	totalPckCerts := len(pckCerts)

	certs := make([]*C.char, totalPckCerts)
	for i := 0; i < totalPckCerts; i++ {
		certs[i] = C.CString(pckCerts[i])
		if certs[i] != nil {
			defer C.free(unsafe.Pointer(certs[i]))
		} else {
			return 0, errors.New("failed to allocate memory for pckcert")
		}
	}
	ret := C.pck_cert_select((*C.cpu_svn_t)(unsafe.Pointer(&cpuSvn.bytes[0])), C.ushort(pceSvn),
		C.ushort(pceId), (*C.char)(unsafe.Pointer(tcbInfo)),
		(**C.char)(unsafe.Pointer(&certs[0])), C.uint(totalPckCerts), &certIdx)

	certError := [...]string{
		"PCK Cert Select Lib selected best suited PCK cert",
		"Invalid Arguments provided to PCK Cert Select Lib",
		"Invalid PCK Certificate",
		"PCK certificate CPUSVN doesn't match TCB Components",
		"Invalid PCK Certificate Version",
		"PCK Cert Lib returned Unexpected Error",
		"PCKs PCEID doesn't match other PCKs",
		"PCKs PPID doesn't match other PCKs",
		"PCKs FMSPC doesn't match other PCKs",
		"Invalid TCB Info provided as input to PCK Cert Select Lib",
		"TCB Info PceID does not match input PceID Value",
		"TCBInfo TCB Type is not supported",
		"Raw TCB is lower than all input PCKs",
	}

	if ret != 0 {
		err = errors.New(certError[ret])
	}
	return uint8(certIdx), err
}

func fetchPckCertInfo(platformInfo *types.Platform) (*types.PckCert, *types.FmspcTcbInfo, string, string, error) {
	log.Trace("resource/platform_ops: fetchPckCertInfo() Entering")
	defer log.Trace("resource/platform_ops: fetchPckCertInfo() Leaving")

	// using platform sgx values, fetch the pck certs from intel pcs server
	var resp *http.Response
	var err error
	if platformInfo.Encppid == "" && platformInfo.Manifest == "" {
		log.Error("invalid request")
		return nil, nil, "", "", errors.New("invalid request, enc_ppid and platform_manifest are null")
	}

	if platformInfo.Manifest != "" {
		resp, err = getPckCertsWithManifestFromProvServer(platformInfo.Manifest,
			platformInfo.PceId)
	} else {
		resp, err = getPckCertFromProvServer(platformInfo.Encppid,
			platformInfo.PceId)
	}
	if resp != nil {
		defer func() {
			derr := resp.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing pckcert response body")
			}
		}()
	}

	if err != nil {
		log.WithError(err).Error("Intel PCS Server getPckCerts api failed")
		return nil, nil, "", "", err
	}

	if resp.StatusCode != http.StatusOK {
		dump, _ := httputil.DumpResponse(resp, true)
		log.WithField("Status Code", resp.StatusCode).Error(string(dump))
		return nil, nil, "", "", errors.New("get pckcerts api call failed with pcs")
	}
	if resp.ContentLength == 0 {
		return nil, nil, "", "", errors.New("no content found in getPCkCerts Http Response")
	}

	// read the PCKCertChain from HTTP response header
	pckCertChain := resp.Header.Get("Sgx-Pck-Certificate-Issuer-Chain")

	// read the fmspc value of the platform for which pck certs are being returned
	fmspc := resp.Header.Get("Sgx-Fmspc")

	// read the type of SGX intermediate CA that issued requested pck certs(either processor or platform)
	ca := resp.Header.Get("Sgx-Pck-Certificate-Ca-Type")

	// read the set  of PCKCerts blob sent as part of HTTP response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("could not read getPckCerts http Response body")
		return nil, nil, "", "", err
	}

	// we unmarshal the json response to read set of pck certs and tcbm values
	var pckCerts []PckCertsInfo
	err = json.Unmarshal(body, &pckCerts)
	if err != nil {
		log.WithError(err).Error("Could not decode the pckCerts json response")
		return nil, nil, "", "", err
	}

	pckCertList := make([]string, len(pckCerts))
	tcbmList := make([]string, len(pckCerts))

	certCount := 0
	// PCS Service can return "Not available" string instead of a PCK certificate,
	// if PCK certificate is not available for a TCB level.
	// Iterate through the array and filter out TCB levels for which PCK Certs is
	// marked as "Not available". The filtered bunch is then sent to PCK Cert
	// Selection Lib to choose best suited PCK cert for the current TCB level
	for i := 0; i < len(pckCerts); i++ {
		if pckCerts[i].Cert != "Not available" {
			pckCertList[certCount], _ = url.QueryUnescape(pckCerts[i].Cert)
			tcbmList[certCount] = pckCerts[i].Tcbm
			certCount++
		}
	}

	// Now we have the bunch of PCK certificates which can be safely passed
	// to PCK Cert Selection Lib
	var pckCertInfo types.PckCert
	pckCertInfo.PckCerts = make([]string, certCount)
	pckCertInfo.Tcbms = make([]string, certCount)

	for i := 0; i < certCount; i++ {
		pckCertInfo.PckCerts[i] = pckCertList[i]
		pckCertInfo.Tcbms[i] = tcbmList[i]
	}

	pckCertInfo.Fmspc = fmspc
	pckCertInfo.QeId = platformInfo.QeId
	pckCertInfo.PceId = platformInfo.PceId

	fmspcTcbInfo, err := fetchFmspcTcbInfo(fmspc)
	if err != nil {
		return nil, nil, "", "", err
	}

	// From bunch of PCK certificates, choose best suited PCK certificate for the
	// current raw TCB level
	pckCertInfo.CertIndex, err = getBestPckCert(platformInfo, pckCertInfo.PckCerts, fmspcTcbInfo.TcbInfo)
	if err != nil {
		log.WithError(err).Error("failed to get best suited pckcert for the current tcb level")
		return nil, nil, "", "", err
	}
	return &pckCertInfo, fmspcTcbInfo, pckCertChain, ca, nil
}

// Fetches the latest PCK Certificate Revocation List for the sgx intel processor
// SVS will make use of this to verify if PCK certificate in a quote is valid
// by comparing against this CRL
func fetchPckCrlInfo(ca string) (*types.PckCrl, error) {
	resp, err := getPckCrlFromProvServer(ca, constants.Encoding_Value)
	if resp != nil {
		defer func() {
			derr := resp.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing pckcrl response body")
			}
		}()
	}

	if err != nil {
		log.WithError(err).Error("Intel PCS Server getPckCrl api failed")
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return nil, errors.New("get revocation list api call failed with pcs")
	}

	var pckCRLInfo types.PckCrl
	pckCRLInfo.Ca = ca
	pckCRLInfo.PckCrlCertChain = resp.Header.Get("Sgx-Pck-Crl-Issuer-Chain")

	if resp.ContentLength == 0 {
		return nil, errors.New("no content found in getPCkCrl Http Response")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("could not read getPckCrl http response")
		return nil, err
	}
	pckCRLInfo.PckCrl = base64.StdEncoding.EncodeToString(body)
	return &pckCRLInfo, nil
}

// for a platform FMSPC value, fetches corresponding TCBInfo structure from Intel PCS server
func fetchFmspcTcbInfo(fmspc string) (*types.FmspcTcbInfo, error) {
	resp, err := getFmspcTcbInfoFromProvServer(fmspc)
	if resp != nil {
		defer func() {
			derr := resp.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing tcbinfo response body")
			}
		}()
	}

	if err != nil {
		log.WithError(err).Error("Intel PCS Server getTCBInfo api failed")
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return nil, errors.New("get tcb info api call failed with pcs")
	}

	var fmspcTcbInfo types.FmspcTcbInfo
	fmspcTcbInfo.Fmspc = fmspc
	fmspcTcbInfo.TcbInfoIssuerChain = resp.Header.Get("Sgx-Tcb-Info-Issuer-Chain")

	if resp.ContentLength == 0 {
		return nil, errors.New("no content found in getTCBInfo Http Response")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("could not read getTCBInfo http response")
		return nil, err
	}
	fmspcTcbInfo.TcbInfo = string(body)
	return &fmspcTcbInfo, nil
}

// Fetches Quoting Enclave ID details for a platform from intel PCS server
func fetchQeIdentityInfo() (*types.QEIdentity, error) {
	resp, err := getQeInfoFromProvServer()
	if resp != nil {
		defer func() {
			derr := resp.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing qeidentity response body")
			}
		}()
	}

	if err != nil {
		log.WithError(err).Error("Intel PCS Server getQEIdentity api failed")
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return nil, errors.New("get qe identity api call failed with pcs")
	}

	var qeInfo types.QEIdentity
	qeInfo.QeIssuerChain = resp.Header.Get("Sgx-Enclave-Identity-Issuer-Chain")

	if resp.ContentLength == 0 {
		return nil, errors.New("no content found in getQeIdentity Http Response")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("could not read getQeIdentity http response")
		return nil, err
	}
	qeInfo.QeInfo = string(body)
	return &qeInfo, nil
}

func cachePckCertInfo(db repository.SCSDatabase, pckCert *types.PckCert, cacheType constants.CacheType) (*types.PckCert, error) {
	var err error
	pckCert.UpdatedTime = time.Now().UTC()
	if cacheType == constants.CacheRefresh {
		err = db.PckCertRepository().Update(*pckCert)
		if err != nil {
			log.WithError(err).Error("PckCerts record could not be updated in db")
			return nil, err
		}
	} else {
		pckCert.CreatedTime = time.Now().UTC()
		pckCert, err = db.PckCertRepository().Create(*pckCert)
		if err != nil {
			log.WithError(err).Error("PckCerts record could not be created in db")
			return nil, err
		}
	}
	return pckCert, nil
}

func cacheQeIdentityInfo(db repository.SCSDatabase, qeIdentity *types.QEIdentity, cacheType constants.CacheType) (*types.QEIdentity, error) {
	var err error
	qeIdentity.UpdatedTime = time.Now().UTC()
	if cacheType == constants.CacheRefresh {
		err = db.QEIdentityRepository().Update(*qeIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity record could not be updated in db")
			return nil, err
		}
	} else {
		qeIdentity.CreatedTime = time.Now().UTC()
		qeIdentity, err = db.QEIdentityRepository().Create(*qeIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity record could not created in db")
			return nil, err
		}
	}
	return qeIdentity, nil
}

func cachePckCertChainInfo(db repository.SCSDatabase, pckCertChain string, cacheType constants.CacheType) (*types.PckCertChain, error) {
	certChain := &types.PckCertChain{
		PckCertChain: pckCertChain}

	var err error
	certChain.UpdatedTime = time.Now().UTC()
	if cacheType == constants.CacheRefresh {
		err = db.PckCertChainRepository().Update(*certChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain record could not be updated in db")
			return nil, err
		}
	} else {
		certChain.CreatedTime = time.Now().UTC()
		certChain, err = db.PckCertChainRepository().Create(*certChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain record could not be created in db")
			return nil, err
		}
	}
	return certChain, nil
}

func cacheFmspcTcbInfo(db repository.SCSDatabase, fmspcTcb *types.FmspcTcbInfo, cacheType constants.CacheType) (*types.FmspcTcbInfo, error) {
	var err error
	fmspcTcb.UpdatedTime = time.Now().UTC()
	if cacheType == constants.CacheRefresh {
		err = db.FmspcTcbInfoRepository().Update(*fmspcTcb)
		if err != nil {
			log.WithError(err).Error("FmspcTcb record could not be Updated in db")
			return nil, err
		}
	} else {
		fmspcTcb.CreatedTime = time.Now().UTC()
		fmspcTcb, err = db.FmspcTcbInfoRepository().Create(*fmspcTcb)
		if err != nil {
			log.WithError(err).Error("FmspcTcb record could not be created in db")
			return nil, err
		}
	}
	return fmspcTcb, nil
}

func cachePlatformInfo(db repository.SCSDatabase, platform *types.Platform, cacheType constants.CacheType) error {
	var err error
	platform.UpdatedTime = time.Now().UTC()
	if cacheType == constants.CacheRefresh {
		err = db.PlatformRepository().Update(*platform)
		if err != nil {
			log.WithError(err).Error("Platform values record could not be updated in db")
			return err
		}
	} else {
		platform.CreatedTime = time.Now().UTC()
		platform, err = db.PlatformRepository().Create(*platform)
		if err != nil {
			log.WithError(err).Error("Platform values record could not be created in db")
			return err
		}
	}
	return nil
}

func cachePlatformTcbInfo(db repository.SCSDatabase, platformInfo *types.Platform, tcbm string, cacheType constants.CacheType) error {
	platformTcb := &types.PlatformTcb{
		Tcbm:   tcbm,
		CpuSvn: platformInfo.CpuSvn,
		PceSvn: platformInfo.PceSvn,
		PceId:  platformInfo.PceId,
		QeId:   platformInfo.QeId}

	var err error
	platformTcb.UpdatedTime = time.Now().UTC()
	if cacheType == constants.CacheRefresh {
		err = db.PlatformTcbRepository().Update(*platformTcb)
		if err != nil {
			log.WithError(err).Error("PlatformTcb values record could not be updated in db")
			return err
		}
	} else {
		platformTcb.CreatedTime = time.Now().UTC()
		platformTcb, err = db.PlatformTcbRepository().Create(*platformTcb)
		if err != nil {
			log.WithError(err).Error("PlatformTcb values record could not be created in db")
			return err
		}
	}
	return nil
}

func cachePckCrlInfo(db repository.SCSDatabase, pckCrl *types.PckCrl, cacheType constants.CacheType) (*types.PckCrl, error) {
	var err error
	pckCrl.UpdatedTime = time.Now().UTC()
	if cacheType == constants.CacheRefresh {
		err = db.PckCrlRepository().Update(*pckCrl)
		if err != nil {
			log.WithError(err).Error("PckCrl record could not be updated in db")
			return nil, err
		}
	} else {
		pckCrl.CreatedTime = time.Now().UTC()
		pckCrl, err = db.PckCrlRepository().Create(*pckCrl)
		if err != nil {
			log.WithError(err).Error("PckCrl record could not be created in db")
			return nil, err
		}
	}
	return pckCrl, nil
}

func pushPlatformInfo(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		err := authorizeEndpoint(r, constants.HostDataUpdaterGroupName, true)
		if err != nil {
			return err
		}
		var platformInfo PlatformInfo

		if r.ContentLength == 0 {
			slog.Error("resource/platform_ops: pushPlatformInfo() The request body was not provided")
			return &resourceError{Message: "platform data not provided",
				StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&platformInfo)
		if err != nil {
			slog.WithError(err).Errorf("resource/platform_ops: pushPlatformInfo() %s :  Failed to decode request body", commLogMsg.InvalidInputBadEncoding)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}
		if !validateInputString(constants.EncPPID_Key, platformInfo.EncPpid) ||
			!validateInputString(constants.CpuSvn_Key, platformInfo.CpuSvn) ||
			!validateInputString(constants.PceSvn_Key, platformInfo.PceSvn) ||
			!validateInputString(constants.PceId_Key, platformInfo.PceId) ||
			!validateInputString(constants.QeId_Key, platformInfo.QeId) {
			slog.Error("resource/platform_ops: pushPlatformInfo() Input validation failed")
			return &resourceError{Message: "invalid query param data",
				StatusCode: http.StatusBadRequest}
		}

		platform := &types.Platform{QeId: platformInfo.QeId}
		existingPlaformData, err := db.PlatformRepository().Retrieve(*platform)
		if existingPlaformData != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			res := Response{Status: "Success", Message: "platform info already cached"}
			js, err := json.Marshal(res)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			_, err = w.Write(js)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			return nil
		}

		platform = &types.Platform{
			Encppid:  platformInfo.EncPpid,
			CpuSvn:   platformInfo.CpuSvn,
			PceSvn:   platformInfo.PceSvn,
			PceId:    platformInfo.PceId,
			QeId:     platformInfo.QeId,
			Manifest: platformInfo.Manifest,
		}

		_, _, ca, err := getLazyCachePckCert(db, platform, constants.CacheInsert)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		pckCrl := &types.PckCrl{Ca: ca}
		existingPckCrl, err := db.PckCrlRepository().Retrieve(*pckCrl)
		if existingPckCrl == nil {
			_, err = getLazyCachePckCrl(db, ca, constants.CacheInsert)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		tcbInfo := types.FmspcTcbInfo{Fmspc: platform.Fmspc}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(tcbInfo)
		if existingFmspc == nil {
			_, err = getLazyCacheFmspcTcbInfo(db, platform.Fmspc, constants.CacheInsert)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		qeIdentity, err := db.QEIdentityRepository().Retrieve()
		if qeIdentity == nil {
			_, err = getLazyCacheQEIdentityInfo(db, constants.CacheInsert)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)

		res := Response{Status: "Created", Message: "platform data pushed to scs"}
		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: platform data pushed by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func refreshPckCerts(db repository.SCSDatabase) error {
	existingPlaformData, _ := db.PlatformRepository().RetrieveAll()
	if len(existingPlaformData) == 0 {
		return errors.New("no platform value records are found in db, cannot perform refresh")
	}

	for n := 0; n < len(existingPlaformData); n++ {
		pckCertInfo, _, _, _, err := fetchPckCertInfo(&existingPlaformData[n])
		if err != nil {
			return errors.New(fmt.Sprintf("pck cert refresh failed: %s", err.Error()))
		}

		_, err = cachePckCertInfo(db, pckCertInfo, constants.CacheRefresh)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Cache Pck Cert Info: %s", err.Error()))
		}
	}
	log.Debug("All PckCerts for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshAllPckCrl(db repository.SCSDatabase) error {
	existingPckCrlData, err := db.PckCrlRepository().RetrieveAll()
	if len(existingPckCrlData) == 0 {
		return errors.New("no pck crl record found in db, cannot perform refresh operation")
	}

	for n := 0; n < len(existingPckCrlData); n++ {
		_, err = getLazyCachePckCrl(db, existingPckCrlData[n].Ca, constants.CacheRefresh)
		if err != nil {
			return errors.New(fmt.Sprintf("refresh of pckcrl failed: %s", err.Error()))
		}
	}
	log.Debug("All PckCrls for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshAllTcbInfo(db repository.SCSDatabase) error {
	existingTcbInfoData, err := db.FmspcTcbInfoRepository().RetrieveAll()
	if len(existingTcbInfoData) == 0 {
		return errors.New("no tcbinfo record found in db, cannot perform refresh operation")
	}

	log.Debug("Existing Fmspc count:", len(existingTcbInfoData))
	for n := 0; n < len(existingTcbInfoData); n++ {
		_, err = getLazyCacheFmspcTcbInfo(db, existingTcbInfoData[n].Fmspc, constants.CacheRefresh)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Refresh Tcb info: %s", err.Error()))
		}
	}
	log.Debug("TCBInfo for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshAllQE(db repository.SCSDatabase) error {
	existingQEData, err := db.QEIdentityRepository().Retrieve()
	if existingQEData == nil {
		return errors.New("no qe identity record found in db, cannot perform refresh operation")
	}

	_, err = getLazyCacheQEIdentityInfo(db, constants.CacheRefresh)
	if err != nil {
		return errors.New(fmt.Sprintf("Error in Refresh QEIdentity info: %s", err.Error()))
	}
	log.Debug("QEIdentity for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshNonPCKCollaterals(db repository.SCSDatabase) error {
	err := refreshAllPckCrl(db)
	if err != nil {
		log.WithError(err).Error("could not complete refresh of PCK Crl")
		return err
	}

	err = refreshAllTcbInfo(db)
	if err != nil {
		log.WithError(err).Error("could not complete refresh of TcbInfo")
		return err
	}

	err = refreshAllQE(db)
	if err != nil {
		log.WithError(err).Error("could not complete refresh of QE Identity")
		return err
	}
	return nil
}

func RefreshPlatformInfoTimer(db repository.SCSDatabase, rtype string) error {
	var err error
	if strings.Compare(rtype, constants.Type_Refresh_Cert) == 0 {
		err = refreshPckCerts(db)
		if err != nil {
			log.WithError(err).Error("could not complete refresh of Pck Certificates")
			return err
		}
	} else if strings.Compare(rtype, constants.Type_Refresh_Tcb) == 0 {
		err = refreshNonPCKCollaterals(db)
		if err != nil {
			log.WithError(err).Error("could not complete refresh of TcbInfo")
			return err
		}
	}
	log.Debug("Refresh Timer Callback: refreshPlatformInfoTimer, completed")
	return nil
}

func refreshPlatformInfo(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		err := authorizeEndpoint(r, constants.CacheManagerGroupName, true)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")

		err = refreshPckCerts(db)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)

			res := Response{Status: "Failure", Message: "could not find platform info in database"}
			js, err := json.Marshal(res)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
			}
			_, err = w.Write(js)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			return err
		}

		err = refreshNonPCKCollaterals(db)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)

			res := Response{Status: "Failure", Message: "could not find platform info in database"}
			js, err := json.Marshal(res)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
			}
			_, err = w.Write(js)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			return err
		}

		w.WriteHeader(http.StatusOK)

		res := Response{Status: "Success", Message: "sgx collaterals refreshed successfully"}
		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: Platform data refreshed by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func compareTcbComponents(pckComponents []byte, pckpcesvn uint16, tcbComponents []byte, tcbpcesvn uint16) int {
	left_lower := false
	right_lower := false

	if len(pckComponents) != constants.MaxTcbLevels || len(tcbComponents) != constants.MaxTcbLevels {
		return Error
	}
	if pckpcesvn < tcbpcesvn {
		left_lower = true
	}
	if pckpcesvn > tcbpcesvn {
		right_lower = true
	}

	for i := 0; i < constants.MaxTcbLevels; i++ {
		if pckComponents[i] < tcbComponents[i] {
			left_lower = true
		}
		if pckComponents[i] > tcbComponents[i] {
			right_lower = true
		}
	}
	// this should not happen as either one can be greater
	if left_lower && right_lower {
		return Undefined
	}
	if left_lower {
		return Lower
	}
	return EqualOrGreater
}

func getTcbCompList(TcbLevelList *TcbLevels) []byte {
	TcbCompLevel := make([]byte, constants.MaxTcbLevels)

	TcbCompLevel[0] = TcbLevelList.SgxTcbComp01Svn
	TcbCompLevel[1] = TcbLevelList.SgxTcbComp02Svn
	TcbCompLevel[2] = TcbLevelList.SgxTcbComp03Svn
	TcbCompLevel[3] = TcbLevelList.SgxTcbComp04Svn
	TcbCompLevel[4] = TcbLevelList.SgxTcbComp05Svn
	TcbCompLevel[5] = TcbLevelList.SgxTcbComp06Svn
	TcbCompLevel[6] = TcbLevelList.SgxTcbComp07Svn
	TcbCompLevel[7] = TcbLevelList.SgxTcbComp08Svn
	TcbCompLevel[8] = TcbLevelList.SgxTcbComp09Svn
	TcbCompLevel[9] = TcbLevelList.SgxTcbComp10Svn
	TcbCompLevel[10] = TcbLevelList.SgxTcbComp11Svn
	TcbCompLevel[11] = TcbLevelList.SgxTcbComp12Svn
	TcbCompLevel[12] = TcbLevelList.SgxTcbComp13Svn
	TcbCompLevel[13] = TcbLevelList.SgxTcbComp14Svn
	TcbCompLevel[14] = TcbLevelList.SgxTcbComp15Svn
	TcbCompLevel[15] = TcbLevelList.SgxTcbComp16Svn

	return TcbCompLevel
}

/*
 * To Determine, if a Platform's TCB status is uptodate or not, following mechanism is employed
 * 1. Retrieve FMSPC value from SGX PCK Certificate assigned to a given platform.
 * 2. Retrieve TCB Info matching the FMSPC value
 * 3. Iterate over the sorted collection of TCB Levels retrieved from TCB Info starting from the first item on the list
 * 4. Compare all the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate with the corresponding values in the TCB Level
 *    If all SGX TCB Comp SVNs in the certificate are greater or equal to the corresponding values in TCB Level, go to next step
 *    otherwise move to the next item on TCB Levels list.
 * 5. Compare PCESVN value retrieved from the SGX PCK certificate with the corresponding value in the TCB Level.
 *    If it is greater or equal to the value in TCB Level, read status assigned to this TCB level
 *    Otherwise, move to the next item on TCB Levels list
 * 6. If no TCB level matches SGX PCK Certificate, then TCB Level is not supported
 */
func getTcbStatus(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		err := authorizeEndpoint(r, constants.HostDataReaderGroupName, true)
		if err != nil {
			return err
		}

		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "query data not provided",
				StatusCode: http.StatusBadRequest}
		}
		QeId := r.URL.Query().Get("qeid")
		if !validateInputString(constants.QeId_Key, QeId) {
			slog.Errorf("resource/platform_ops: getTcbStatus() Input validation failed for query parameter")
			return &resourceError{Message: "invalid qeid",
				StatusCode: http.StatusBadRequest}
		}

		pckinfo := &types.PckCert{QeId: QeId}
		existingPckCertData, err := db.PckCertRepository().Retrieve(*pckinfo)
		if existingPckCertData == nil {
			return &resourceError{Message: "no pck cert record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		certIndex := existingPckCertData.CertIndex
		existingPlatformData := &types.Platform{QeId: QeId}
		existingPlatformData, err = db.PlatformRepository().Retrieve(*existingPlatformData)
		if existingPlatformData == nil {
			return &resourceError{Message: "no platform record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		TcbInfo := types.FmspcTcbInfo{Fmspc: existingPlatformData.Fmspc}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(TcbInfo)
		if existingFmspc == nil {
			return &resourceError{Message: "no tcb info record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		// for the selected pck cert, select corresponding raw tcb level (tcbm)
		tcbm, err1 := hex.DecodeString(existingPckCertData.Tcbms[certIndex])
		if err1 != nil {
			return &resourceError{Message: "cannot decode tcbm: " + err1.Error(),
				StatusCode: http.StatusInternalServerError}
		}

		// tcbm (current raw tcb level) is 18 byte array with first 16 bytes for cpusvn
		//  and next 2 bytes for pcesvn
		PckComponents := tcbm[:16]
		PckPceSvn := binary.LittleEndian.Uint16(tcbm[16:])

		var tcbInfo TcbInfoJson

		// unmarshal the json encoded TcbInfo response for a platform
		err = json.Unmarshal([]byte(existingFmspc.TcbInfo), &tcbInfo)
		if err != nil {
			return &resourceError{Message: "cannot unmarshal tcbinfo: " + err.Error(),
				StatusCode: http.StatusInternalServerError}
		}

		var Status string
		var response Response
		response.Status = "false"
		response.Message = "TCB Status is not UpToDate"

		var TcbComponents []byte
		// iterate through all TCB Levels present in TCBInfo
		for i := 0; i < len(tcbInfo.TcbInfo.TcbLevels); i++ {
			TcbPceSvn := tcbInfo.TcbInfo.TcbLevels[i].Tcb.PceSvn
			TcbComponents = getTcbCompList(&tcbInfo.TcbInfo.TcbLevels[i].Tcb)
			TcbError := compareTcbComponents(PckComponents, PckPceSvn, TcbComponents, TcbPceSvn)
			if TcbError == EqualOrGreater {
				Status = tcbInfo.TcbInfo.TcbLevels[i].TcbStatus
				break
			}
		}

		if Status == "UpToDate" || Status == "ConfigurationNeeded" {
			response.Status = "true"
			response.Message = "TCB Status is UpToDate"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		res := Response{Status: response.Status, Message: response.Message}
		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: TCB status retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}
