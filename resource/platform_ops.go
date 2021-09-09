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
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	"github.com/pkg/errors"
	"intel/isecl/lib/common/v5/context"
	commLogMsg "intel/isecl/lib/common/v5/log/message"
	"intel/isecl/scs/v5/constants"
	"intel/isecl/scs/v5/repository"
	"intel/isecl/scs/v5/types"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

const (
	Error = iota
	EqualOrGreater
	Lower
	Undefined
)

type RefreshResponse struct {
	Status      string             `json:"status"`
	RetryAfter  *int               `json:"retry-after,omitempty"`
	LastRefresh *types.LastRefresh `json:"last-refresh,omitempty"`
}

type Response struct {
	Status  string
	Message string
}

type PlatformInfo struct {
	EncPpid  string `json:"enc_ppid"`
	CPUSvn   string `json:"cpu_svn"`
	PceSvn   string `json:"pce_svn"`
	PceID    string `json:"pce_id"`
	QeID     string `json:"qe_id"`
	Manifest string `json:"manifest"`
	HwUUID   string `json:"hardware_uuid"`
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
	PceSvn          uint16 `json:"pcesvn"`
}

type TcbLevelsType struct {
	Tcb       TcbLevels `json:"tcb"`
	TcbDate   string    `json:"tcbDate"`
	TcbStatus string    `json:"tcbStatus"`
}

type TcbInfoType struct {
	Version                 int             `json:"version"`
	IssueDate               string          `json:"issueDate"`
	NextUpdate              string          `json:"nextUpdate"`
	Fmspc                   string          `json:"fmspc"`
	PceID                   string          `json:"pceId"`
	TcbType                 int             `json:"tcbType"`
	TcbEvaluationDataNumber int             `json:"tcbEvaluationDataNumber"`
	TcbLevels               []TcbLevelsType `json:"tcbLevels"`
}

type TcbInfoJSON struct {
	TcbInfo   TcbInfoType `josn:"tcbInfo"`
	Signature string      `json:"signature"`
}

type PckCertsInfo struct {
	Tcb  TcbLevels `json:"tcb"`
	Tcbm string    `json:"tcbm"`
	Cert string    `json:"cert"`
}

type cpuSvn struct {
	bytes []byte
}

var tcbStatusRetrieveParams = map[string]bool{"qeid": true, "pceid": true}

func PlatformInfoOps(r *mux.Router, db repository.SCSDatabase) {
	r.Handle("/platforms", handlers.ContentTypeHandler(pushPlatformInfo(db), "application/json")).Methods("POST")
	r.Handle("/tcbstatus", handlers.ContentTypeHandler(getTcbStatus(db), "application/json")).Methods("GET")
}

func RefreshPlatformInfoOps(r *mux.Router, db repository.SCSDatabase, trigger chan<- constants.RefreshTrigger) {
	r.Handle("/refreshes", handlers.ContentTypeHandler(refreshPlatformInfoStatus(db, trigger), "application/json")).Methods("GET")
	r.Handle("/refreshes", handlers.ContentTypeHandler(refreshPlatformInfoStart(db, trigger), "application/json")).Methods("POST")
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
	var cpusvn cpuSvn

	cpusvn.bytes, err = hex.DecodeString(platformInfo.CPUSvn)
	if err != nil {
		log.WithError(err).Error("could not decode cpusvn string")
		return 0, err
	}
	pceSvn, err := strconv.ParseUint(platformInfo.PceSvn, 16, 32)
	if err != nil {
		log.WithError(err).Error("could not parse pcesvn string")
		return 0, err
	}
	pceID, err := strconv.ParseUint(platformInfo.PceID, 16, 32)
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
	ret := C.pck_cert_select((*C.cpu_svn_t)(unsafe.Pointer(&cpusvn.bytes[0])), C.ushort(pceSvn),
		C.ushort(pceID), (*C.char)(unsafe.Pointer(tcbInfo)),
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
			platformInfo.PceID)
	} else {
		resp, err = getPckCertFromProvServer(platformInfo.Encppid,
			platformInfo.PceID)
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
	pckCertInfo.QeID = platformInfo.QeID
	pckCertInfo.PceID = platformInfo.PceID

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
	resp, err := getPckCrlFromProvServer(ca, constants.EncodingValue)
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

	//To validate if the response read from PCS is actually a DER encoded CRL
	if _, err = x509.ParseDERCRL(body); err != nil {
		log.WithError(err).Error("error decoding DER CRL")
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

	//To validate that tcbinfo response read from PCS is as per the expected json response
	var tcbInfo TcbInfoJSON
	if err = json.Unmarshal(body, &tcbInfo); err != nil {
		log.WithError(err).Error("error unmarshalling TCB info")
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

	//To validate that QE identity info response read from PCS is as per the expected json response
	var qeIdentityInfo types.QeIdentityJSON
	if err = json.Unmarshal(body, &qeIdentityInfo); err != nil {
		log.WithError(err).Error("error unmarshalling enclave identity info")
		return nil, err
	}

	qeInfo.QeInfo = string(body)
	return &qeInfo, nil
}

func cachePckCertInfo(db repository.SCSDatabase, pckCert *types.PckCert, cacheType constants.CacheType) (*types.PckCert, error) {
	var err error
	pckCert.UpdatedTime = time.Now().UTC()
	if cacheType == constants.CacheRefresh {
		err = db.PckCertRepository().Update(pckCert)
		if err != nil {
			log.WithError(err).Error("PckCerts record could not be updated in db")
			return nil, err
		}
	} else {
		pckCert.CreatedTime = time.Now().UTC()
		pckCert, err = db.PckCertRepository().Create(pckCert)
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
		err = db.QEIdentityRepository().Update(qeIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity record could not be updated in db")
			return nil, err
		}
	} else {
		qeIdentity.ID = "QE"
		qeIdentity.CreatedTime = time.Now().UTC()
		qeIdentity, err = db.QEIdentityRepository().Create(qeIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity record could not created in db")
			return nil, err
		}
	}
	return qeIdentity, nil
}

func cachePckCertChainInfo(db repository.SCSDatabase, pckCertChain, ca string, cacheType constants.CacheType) (*types.PckCertChain, error) {
	certChain := &types.PckCertChain{
		Ca:           ca,
		PckCertChain: pckCertChain,
	}

	var err error
	certChain.UpdatedTime = time.Now().UTC()
	if cacheType == constants.CacheRefresh {
		err = db.PckCertChainRepository().Update(certChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain record could not be updated in db")
			return nil, err
		}
	} else {
		certChain.CreatedTime = time.Now().UTC()
		certChain, err = db.PckCertChainRepository().Create(certChain)
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
		err = db.FmspcTcbInfoRepository().Update(fmspcTcb)
		if err != nil {
			log.WithError(err).Error("FmspcTcb record could not be Updated in db")
			return nil, err
		}
	} else {
		fmspcTcb.CreatedTime = time.Now().UTC()
		fmspcTcb, err = db.FmspcTcbInfoRepository().Create(fmspcTcb)
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
		err = db.PlatformRepository().Update(platform)
		if err != nil {
			log.WithError(err).Error("Platform values record could not be updated in db")
			return err
		}
	} else {
		platform.CreatedTime = time.Now().UTC()
		platform, err = db.PlatformRepository().Create(platform)
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
		CPUSvn: platformInfo.CPUSvn,
		PceSvn: platformInfo.PceSvn,
		PceID:  platformInfo.PceID,
		QeID:   platformInfo.QeID}

	var err error
	platformTcb.UpdatedTime = time.Now().UTC()
	if cacheType == constants.CacheRefresh {
		err = db.PlatformTcbRepository().Update(platformTcb)
		if err != nil {
			log.WithError(err).Error("PlatformTcb values record could not be updated in db")
			return err
		}
	} else {
		platformTcb.CreatedTime = time.Now().UTC()
		platformTcb, err = db.PlatformTcbRepository().Create(platformTcb)
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
		err = db.PckCrlRepository().Update(pckCrl)
		if err != nil {
			log.WithError(err).Error("PckCrl record could not be updated in db")
			return nil, err
		}
	} else {
		pckCrl.CreatedTime = time.Now().UTC()
		pckCrl, err = db.PckCrlRepository().Create(pckCrl)
		if err != nil {
			log.WithError(err).Error("PckCrl record could not be created in db")
			return nil, err
		}
	}
	return pckCrl, nil
}
func checkPlatformDataCacheStatus(db repository.SCSDatabase, platformInfo *PlatformInfo, tokenSubject string) (bool, error) {
	log.Trace("resource/platform_ops:checkPlatformDataCacheStatus() Entering")
	defer log.Trace("resource/platform_ops:checkPlatformDataCacheStatus() Leaving")

	platform := &types.Platform{
		QeID:  platformInfo.QeID,
		PceID: platformInfo.PceID,
	}
	existingPlatformData, err := db.PlatformRepository().Retrieve(platform)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.WithError(err).Error("resource/platform_ops:checkPlatformDataCacheStatus() Error while retrieving platform data from DB")
		return false, &resourceError{Message: err.Error(),
			StatusCode: http.StatusInternalServerError}
	}
	if existingPlatformData != nil {
		if !strings.EqualFold(existingPlatformData.HwUUID.String(), tokenSubject) {
			slog.Errorf("resource/platform_ops:checkPlatformDataCacheStatus() %s : Failed to match host identity from database", commLogMsg.AuthenticationFailed)
			return false, &resourceError{Message: "Invalid Token",
				StatusCode: http.StatusUnauthorized}
		}

		if platformInfo.Manifest == "" {
			platformInfo.Manifest = existingPlatformData.Manifest
			cert := &types.PckCert{
				QeID:  platformInfo.QeID,
				PceID: platformInfo.PceID,
			}
			existingPckCert, err := db.PckCertRepository().Retrieve(cert)
			if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				log.WithError(err).Error("resource/platform_ops:checkPlatformDataCacheStatus() Error while retrieving pck cert from DB")
				return false, &resourceError{Message: err.Error(),
					StatusCode: http.StatusInternalServerError}
			}
			if existingPckCert != nil {
				return true, nil
			}
		} else if existingPlatformData.Manifest == platformInfo.Manifest {
			return true, nil
		}
	}
	return false, nil
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
		if !validateInputString(constants.EncPPIDKey, platformInfo.EncPpid) ||
			!validateInputString(constants.CPUSvnKey, platformInfo.CPUSvn) ||
			!validateInputString(constants.PceSvnKey, platformInfo.PceSvn) ||
			!validateInputString(constants.PceIDKey, platformInfo.PceID) ||
			!validateInputString(constants.QeIDKey, platformInfo.QeID) ||
			!validateInputString(constants.HwUUIDKey, platformInfo.HwUUID) {
			slog.Error("resource/platform_ops: pushPlatformInfo() Input validation failed")
			return &resourceError{Message: "invalid query param data",
				StatusCode: http.StatusBadRequest}
		}

		tokenSubject, err := context.GetTokenSubject(r)
		if err != nil || tokenSubject != platformInfo.HwUUID {
			slog.Errorf("resource/platform_ops: pushPlatformInfo() %s : Failed to match host identity from token", commLogMsg.AuthenticationFailed)
			return &resourceError{Message: "Invalid Token",
				StatusCode: http.StatusUnauthorized}
		}

		isCached, err := checkPlatformDataCacheStatus(db, &platformInfo, tokenSubject)
		if err != nil {
			return err
		}

		if isCached {
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

		platform := &types.Platform{
			Encppid:  platformInfo.EncPpid,
			CPUSvn:   platformInfo.CPUSvn,
			PceSvn:   platformInfo.PceSvn,
			PceID:    platformInfo.PceID,
			QeID:     platformInfo.QeID,
			Manifest: platformInfo.Manifest,
			HwUUID:   uuid.MustParse(platformInfo.HwUUID),
		}

		pckCertInfo, fmspcTcbInfo, pckCertChain, ca, err := fetchPckCertInfo(platform)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		platform.Fmspc = fmspcTcbInfo.Fmspc
		platform.Ca = ca
		err = cachePlatformInfo(db, platform, constants.CacheInsert)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = cachePlatformTcbInfo(db, platform, pckCertInfo.Tcbms[pckCertInfo.CertIndex], constants.CacheInsert)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		tcbInfo := &types.FmspcTcbInfo{Fmspc: platform.Fmspc}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(tcbInfo)
		if existingFmspc == nil {
			_, err = getLazyCacheFmspcTcbInfo(db, platform.Fmspc, constants.CacheInsert)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		certChain := &types.PckCertChain{Ca: ca}
		existingPckCertChain, err := db.PckCertChainRepository().Retrieve(certChain)
		if existingPckCertChain == nil {
			_, err = cachePckCertChainInfo(db, pckCertChain, ca, constants.CacheInsert)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		_, err = cachePckCertInfo(db, pckCertInfo, constants.CacheInsert)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		pckCrl := &types.PckCrl{Ca: ca}
		existingPckCrl, err := db.PckCrlRepository().Retrieve(pckCrl)
		if existingPckCrl == nil {
			_, err = getLazyCachePckCrl(db, ca, constants.CacheInsert)
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

	existingPlatformData, _ := db.PlatformRepository().RetrieveAll()
	if len(existingPlatformData) == 0 {
		return errors.New("No platform value records are found in db, cannot perform refresh.")
	}

	// Envelope to pass data to go routines.
	type refreshedDataResponse struct {
		pckCertInfo  *types.PckCert
		pckCertChain string
		ca           string
		platformInfo *types.Platform
		err          error
	}

	dbRows := make(chan *types.Platform)
	refreshedData := make(chan refreshedDataResponse)
	errC := make(chan error)
	errorStatus := make(chan error)

	var fetchPckCertWG sync.WaitGroup
	var dbUpdateWG sync.WaitGroup

	// Create a pool of DB update routines.
	for n := 0; n < constants.MaxConcurrentRefreshDBUpdates; n++ {
		// Update DB with new pckCertInfo returned by fetchPckCertInfo
		go func(inst int, refreshedData <-chan refreshedDataResponse,
			errC chan<- error) {

			dbUpdateWG.Add(1)
			defer dbUpdateWG.Done()

			for responseEnvelope := range refreshedData {
				pckCertInfo := responseEnvelope.pckCertInfo
				pckCertChain := responseEnvelope.pckCertChain
				ca := responseEnvelope.ca
				existingPlatformData := responseEnvelope.platformInfo
				responseErr := responseEnvelope.err

				if responseErr != nil {
					errC <- errors.Wrap(responseErr, "Error while requesting PCS.")
					break
				}

				err := cachePlatformTcbInfo(db, existingPlatformData, pckCertInfo.Tcbms[pckCertInfo.CertIndex], constants.CacheRefresh)
				if err != nil {
					errC <- errors.Wrap(err, "Error while caching Platform Tcb Info")
					break
				}

				_, err = cachePckCertChainInfo(db, pckCertChain, ca, constants.CacheRefresh)
				if err != nil {
					errC <- errors.Wrap(err, "Error while caching Pck CertChain Info")
					break
				}

				_, err = cachePckCertInfo(db, pckCertInfo, constants.CacheRefresh)
				if err != nil {
					errC <- errors.Wrap(err, "Error while caching Pck Cert Info")
					break
				}
			}
		}(n, refreshedData, errC)
	}

	// Goroutine pool for outbound PCCS requests.
	for n := 0; n < constants.MaxConcurrentRefreshRequests; n++ {
		go func(dbRows <-chan *types.Platform, errC chan<- error) {
			fetchPckCertWG.Add(1)
			defer fetchPckCertWG.Done()

			for platformInfo := range dbRows {
				pckCertInfo, _, pckCertChain, ca, err := fetchPckCertInfo(platformInfo)

				if err != nil {
					errC <- errors.Wrap(err, "Error while fetching pck cert info.")
				} else {
					// Send the response from fetchPckCertInfo inside an envelope
					refreshed := refreshedDataResponse{
						pckCertInfo:  pckCertInfo,
						pckCertChain: pckCertChain,
						ca:           ca,
						err:          err,
						platformInfo: platformInfo,
					}
					refreshedData <- refreshed
				}
			}
		}(dbRows, errC)
	}

	// Error Collection.
	go func(errC <-chan error, errorStatus chan<- error) {
		refreshHadErrors := false
		for err := range errC {
			log.Error(err)
			refreshHadErrors = true
		}

		if refreshHadErrors {
			errorStatus <- errors.New("refreshPckCerts encounted errors!")
		} else {
			errorStatus <- nil
		}
	}(errC, errorStatus)

	// Stage 1 - Send rows from DB to PCCS Request Pool.
	for n := 0; n < len(existingPlatformData); n++ {
		dbRows <- &existingPlatformData[n]
	}
	close(dbRows)

	// Stage 2 - Wait for outbound PCCS requests
	fetchPckCertWG.Wait()
	close(refreshedData)

	// Stage 3 - Wait for DB updates
	dbUpdateWG.Wait()
	close(errC)

	// Stage 4 - Check on errors
	err := <-errorStatus
	log.Debug("refreshPckCerts Complete.")

	return err
}

func refreshAllPckCrl(db repository.SCSDatabase) error {
	existingPckCrlData, err := db.PckCrlRepository().RetrieveAll()
	if len(existingPckCrlData) == 0 {
		return errors.New("no pck crl record found in db, cannot perform refresh operation")
	}

	for n := 0; n < len(existingPckCrlData); n++ {
		_, err = getLazyCachePckCrl(db, existingPckCrlData[n].Ca, constants.CacheRefresh)
		if err != nil {
			return fmt.Errorf("refresh of pckcrl failed: %s", err.Error())
		}
	}
	log.Debug("All PckCrls for the platform re-fetched from PCS as part of refresh")
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
	log.Debug("TCBInfo for the platform re-fetched from PCS as part of refresh")
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
	log.Debug("QEIdentity for the platform re-fetched from PCS as part of refresh")
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

func RefreshPlatformInfo(db repository.SCSDatabase, trigger <-chan constants.RefreshTrigger) {
	for {
		triggerType := <-trigger
		status := constants.RefreshStatusSucceeded

		if triggerType == constants.TriggerStatus {
			log.Debug("Ignoring status trigger.")
			continue
		}

		// Start refresh
		err := refreshPckCerts(db)
		if err != nil {
			status = constants.RefreshStatusFailed
			log.WithError(err).Error("Error while refreshing PCK Certs")
		}

		err = refreshNonPCKCollaterals(db)
		if err != nil {
			status = constants.RefreshStatusFailed
			log.WithError(err).Error("Error while refreshing Non PCK Collaterals")
		}

		// Update status in DB
		refreshInfo := types.LastRefresh{CompletedAt: time.Now(), Status: status}
		err = db.LastRefreshRepository().Update(&refreshInfo)
		if err != nil {
			log.WithError(err).Error("Error while updating lastRefresh Info in DB.")
		}

	}
}

func fetchLastRefreshInfo(db repository.SCSDatabase) (*types.LastRefresh, error) {
	refreshInfo, err := db.LastRefreshRepository().Retrieve()
	if err != nil {
		log.WithError(err).Error("Error while fetching lastRefresh Info in DB.")
	}

	return refreshInfo, nil
}

func isCoolOffTimeout(lastRefresh *types.LastRefresh) *int {
	if lastRefresh == nil {
		// We might not have previous refresh info.
		return nil
	}

	sinceLastRefresh := time.Since(lastRefresh.CompletedAt)
	var lastRefreshinSeconds int
	lastRefreshinSeconds = int(sinceLastRefresh.Seconds())

	if lastRefreshinSeconds > 0 && lastRefreshinSeconds <= constants.RefreshCoolOffTimeout {
		log.Debug("Too many refresh requests.")
		lastRefreshinSeconds = constants.RefreshCoolOffTimeout - lastRefreshinSeconds
		return &lastRefreshinSeconds
	}

	return nil
}

func InitAutoRefreshTimer(db repository.SCSDatabase, refreshTrigger chan<- constants.RefreshTrigger, refreshHours int) error {

	stop := make(chan os.Signal)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	// Start the timer.
	go func() {
		ticker := time.NewTicker(time.Hour * time.Duration(refreshHours))
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				fmt.Fprintln(os.Stderr, "Got Signal for exit and exiting.... Refresh Timer")
				return
			case t := <-ticker.C:
				log.Debug("Timer started", t)
				// TODO : Timer expired. Check if we are in coolOff period.
				lastRefresh, err := fetchLastRefreshInfo(db)
				if err != nil {
					log.Error("Unable to get last refresh info")
					break
				}

				coolOffTimeout := isCoolOffTimeout(lastRefresh)
				if coolOffTimeout != nil {
					log.Debug("Timer triggered during cooloff timeout.")
				} else {
					select {
					case refreshTrigger <- constants.TriggerStart:
						log.Debug("Timer triggered a platforminfo refresh.")
					default:
						log.Debug("Timer triggered - Refresh is already in progress.")
					}
				}
			}
		}
	}()
	return nil
}

func refreshPlatformInfoStatus(db repository.SCSDatabase, refreshTrigger chan<- constants.RefreshTrigger) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		err := authorizeEndpoint(r, constants.CacheManagerGroupName, true)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")

		res := RefreshResponse{}
		res.LastRefresh, err = fetchLastRefreshInfo(db)
		if err != nil {
			return err
		}

		select {
		// Check if refresh is already running or not
		// without triggering a new async refresh.
		case refreshTrigger <- constants.TriggerStatus:
			res.Status = constants.RefreshStatusIdle
		default:
			res.Status = constants.RefreshStatusInProgress
		}

		w.WriteHeader(http.StatusOK)

		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: Platform data refresh status requested by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func refreshPlatformInfoStart(db repository.SCSDatabase, refreshTrigger chan<- constants.RefreshTrigger) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		err := authorizeEndpoint(r, constants.CacheManagerGroupName, true)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")

		res := RefreshResponse{}
		res.LastRefresh, err = fetchLastRefreshInfo(db)
		if err != nil {
			return err
		}

		coolOffTimeout := isCoolOffTimeout(res.LastRefresh)
		if coolOffTimeout != nil {
			res.RetryAfter = coolOffTimeout
			res.Status = constants.RefreshStatusTooMany
		} else {
			select {
			case refreshTrigger <- constants.TriggerStart:
				res.Status = constants.RefreshStatusStarted
			default:
				res.Status = constants.RefreshStatusInProgress
			}
		}

		w.WriteHeader(http.StatusOK)

		js, err := json.Marshal(res)
		log.Info(string(js))
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
	leftLower := false
	rightLower := false

	if len(pckComponents) != constants.MaxTcbLevels || len(tcbComponents) != constants.MaxTcbLevels {
		return Error
	}
	if pckpcesvn < tcbpcesvn {
		leftLower = true
	}
	if pckpcesvn > tcbpcesvn {
		rightLower = true
	}

	for i := 0; i < constants.MaxTcbLevels; i++ {
		if pckComponents[i] < tcbComponents[i] {
			leftLower = true
		}
		if pckComponents[i] > tcbComponents[i] {
			rightLower = true
		}
	}
	// this should not happen as either one can be greater
	if leftLower && rightLower {
		return Undefined
	}
	if leftLower {
		return Lower
	}
	return EqualOrGreater
}

func getTcbCompList(tcbLevelList *TcbLevels) []byte {
	tcbCompLevel := make([]byte, constants.MaxTcbLevels)

	tcbCompLevel[0] = tcbLevelList.SgxTcbComp01Svn
	tcbCompLevel[1] = tcbLevelList.SgxTcbComp02Svn
	tcbCompLevel[2] = tcbLevelList.SgxTcbComp03Svn
	tcbCompLevel[3] = tcbLevelList.SgxTcbComp04Svn
	tcbCompLevel[4] = tcbLevelList.SgxTcbComp05Svn
	tcbCompLevel[5] = tcbLevelList.SgxTcbComp06Svn
	tcbCompLevel[6] = tcbLevelList.SgxTcbComp07Svn
	tcbCompLevel[7] = tcbLevelList.SgxTcbComp08Svn
	tcbCompLevel[8] = tcbLevelList.SgxTcbComp09Svn
	tcbCompLevel[9] = tcbLevelList.SgxTcbComp10Svn
	tcbCompLevel[10] = tcbLevelList.SgxTcbComp11Svn
	tcbCompLevel[11] = tcbLevelList.SgxTcbComp12Svn
	tcbCompLevel[12] = tcbLevelList.SgxTcbComp13Svn
	tcbCompLevel[13] = tcbLevelList.SgxTcbComp14Svn
	tcbCompLevel[14] = tcbLevelList.SgxTcbComp15Svn
	tcbCompLevel[15] = tcbLevelList.SgxTcbComp16Svn

	return tcbCompLevel
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

		if len(r.URL.Query()) < 2 {
			return &resourceError{Message: "query data not provided",
				StatusCode: http.StatusBadRequest}
		}

		if err := validateQueryParams(r.URL.Query(), tcbStatusRetrieveParams); err != nil {
			slog.Errorf("resource/platform_ops: getTcbStatus() %s", err.Error())
			return &resourceError{Message: "invalid query param", StatusCode: http.StatusBadRequest}
		}

		qeID := r.URL.Query().Get("qeid")
		pceID := r.URL.Query().Get("pceid")
		if !validateInputString(constants.QeIDKey, qeID) || !validateInputString(constants.PceIDKey, pceID) {
			slog.Errorf("resource/platform_ops: getTcbStatus() Input validation failed for query parameter")
			return &resourceError{Message: "invalid query param",
				StatusCode: http.StatusBadRequest}
		}

		pckInfo := &types.PckCert{QeID: qeID, PceID: pceID}
		existingPckCertData, err := db.PckCertRepository().Retrieve(pckInfo)
		if existingPckCertData == nil {
			return &resourceError{Message: "no pck cert record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		certIndex := existingPckCertData.CertIndex
		existingPlatformData := &types.Platform{QeID: qeID, PceID: pceID}
		existingPlatformData, err = db.PlatformRepository().Retrieve(existingPlatformData)
		if existingPlatformData == nil {
			return &resourceError{Message: "no platform record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		tcbInf := &types.FmspcTcbInfo{Fmspc: existingPlatformData.Fmspc}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(tcbInf)
		if existingFmspc == nil {
			return &resourceError{Message: "no tcb info record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		// for the selected pck cert, select corresponding raw tcb level (tcbm)
		tcbm, err := hex.DecodeString(existingPckCertData.Tcbms[certIndex])
		if err != nil {
			return &resourceError{Message: "cannot decode tcbm: " + err.Error(),
				StatusCode: http.StatusInternalServerError}
		}

		// tcbm (current raw tcb level) is 18 byte array with first 16 bytes for cpusvn
		//  and next 2 bytes for pcesvn
		pckComponents := tcbm[:16]
		pckPceSvn := binary.LittleEndian.Uint16(tcbm[16:])

		var tcbInfo TcbInfoJSON

		// unmarshal the json encoded TcbInfo response for a platform
		err = json.Unmarshal([]byte(existingFmspc.TcbInfo), &tcbInfo)
		if err != nil {
			return &resourceError{Message: "cannot unmarshal tcbinfo: " + err.Error(),
				StatusCode: http.StatusInternalServerError}
		}

		var status string
		var response Response
		response.Status = "false"
		response.Message = "TCB Status is not UpToDate"

		var tcbComponents []byte
		// iterate through all TCB Levels present in TCBInfo
		for i := 0; i < len(tcbInfo.TcbInfo.TcbLevels); i++ {
			tcbPceSvn := tcbInfo.TcbInfo.TcbLevels[i].Tcb.PceSvn
			tcbComponents = getTcbCompList(&tcbInfo.TcbInfo.TcbLevels[i].Tcb)
			tcbError := compareTcbComponents(pckComponents, pckPceSvn, tcbComponents, tcbPceSvn)
			if tcbError == EqualOrGreater {
				status = tcbInfo.TcbInfo.TcbLevels[i].TcbStatus
				break
			}
		}

		if status == "UpToDate" || status == "ConfigurationNeeded" {
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
